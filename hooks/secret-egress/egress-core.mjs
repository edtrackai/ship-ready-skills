// Stack & Ship Guardrails: secret-egress decision logic. No dependencies. Node 18+.
// Pattern-based: it catches the listed patterns only. Rephrased, encoded or split commands can get past it.
// Every check is linear-time (token scans and simple regexes, no nested quantifiers), and inputs over
// MAX_INPUT (64 K characters) are denied unchecked, so a huge or crafted input can't stall the hook.
// Malformed input (no tool_input, non-string command) returns null: no decision, normal permission flow.

export const MAX_INPUT = 64 * 1024;

const LIVE_KEY = /\b(?:sk_live_[0-9a-zA-Z]{10,}|rk_live_[0-9a-zA-Z]{10,}|whsec_[0-9a-zA-Z]{20,}|sb_secret_[0-9a-zA-Z_-]{10,}|gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,}|(?:AKIA|ASIA)[0-9A-Z]{16})\b/;
const SECRET_NAME = /(SUPABASE_SERVICE_ROLE_KEY|SUPABASE_SECRET_KEY|STRIPE_SECRET_KEY|STRIPE_WEBHOOK_SECRET|AWS_SECRET_ACCESS_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|GITHUB_TOKEN)/;
const NET_TOOLS = new Set(["curl", "wget", "http", "https", "xh", "nc", "ncat", "netcat", "socat", "scp", "sftp", "rsync", "ftp", "telnet", "ssh", "invoke-webrequest", "iwr", "invoke-restmethod", "irm"]);
// In-code network calls (node -e, python -c and similar), matched as plain substrings.
const NET_CALLS = ["fetch(", "requests.", "urllib", "http.request", "https.request", "axios", "httpx.", "XMLHttpRequest", "net.connect", "socket."];
// Tools for which the official-host exemption may apply.
const URL_TOOLS = new Set(["curl", "wget", "http", "https", "xh"]);
const SEP = /[\s|;&<>()`'"=,{}\[\]]+/;

function isEnvFileToken(tok) {
  let t = tok.replace(/^@+/, "");
  const slash = t.lastIndexOf("/");
  if (slash >= 0) t = t.slice(slash + 1);
  if (t === ".env") return true;
  if (!t.startsWith(".env.")) return false;
  const parts = t.slice(5).split(".");
  if (parts.some((p) => !/^[\w-]+$/.test(p))) return false;
  return !["example", "sample", "template"].includes(parts[parts.length - 1]);
}

export function hasServiceRoleJwt(text) {
  for (const tok of String(text).split(/[^A-Za-z0-9_.-]+/)) {
    if (!tok.startsWith("eyJ")) continue;
    const parts = tok.split(".");
    if (parts.length !== 3 || !parts[1].startsWith("eyJ") || parts[1].length < 10 || parts[2].length < 8) continue;
    try {
      const payload = Buffer.from(parts[1].replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8");
      if (/"role"\s*:\s*"service_role"/.test(payload)) return true;
    } catch {}
  }
  return false;
}

export function findLiteralSecret(text) {
  const s = String(text ?? "");
  if (LIVE_KEY.test(s)) return "a live secret key or token (Stripe sk_live_/rk_live_/whsec_, Supabase sb_secret_, GitHub, AWS)";
  if (hasServiceRoleJwt(s)) return "a Supabase service-role key";
  return null;
}

function isOfficialHost(host) {
  const h = host.toLowerCase().replace(/:\d+$/, "");
  return h === "api.stripe.com" || /^[a-z0-9-]+\.supabase\.co$/.test(h);
}

/** Exempt only when the tool is curl/wget/httpie, there is no comment, every URL is official,
 *  and no other token looks like a host. */
// curl/wget options that can send the request somewhere other than the visible URL, or load hidden options.
const REDIRECT_OPTS = new Set(["--config", "--resolve", "--connect-to", "--doh-url", "--unix-socket", "--abstract-unix-socket", "--proxy", "-x", "--preproxy", "-e", "--execute", "--input-file", "-i"]);
function hasRedirectOption(tokens) {
  // Any --proxy* / --socks* option (with or without =value), --proxytunnel, and short clusters with K, x or p (-p = --proxytunnel).
  return tokens.some((t) => REDIRECT_OPTS.has(t) || t.startsWith("--proxy") || t.startsWith("--socks") || t.startsWith("--preproxy")
    || (t.startsWith("-") && !t.startsWith("--") && (t.includes("K") || t.includes("x") || t.includes("p"))));
}

// Environment assignments that can reroute or reconfigure curl/wget: *PROXY*=, *_proxy=, CURL_HOME=, CURLRC=,
// WGETRC=, CURLOPT*=, and CA-trust variables (SSL_CERT_FILE, SSL_CERT_DIR, CURL_CA_BUNDLE, REQUESTS_CA_BUNDLE,
// NODE_EXTRA_CA_CERTS, any *CA_BUNDLE* / *CA_CERT*) (case-insensitive). Linear: split at the first "=", check the name.
const ENV_REROUTE = /PROXY|CURL_HOME|CURLRC|WGETRC|CURLOPT|SSL_CERT|CA_BUNDLE|CA_CERT/i;
export function hasRerouteAssignment(cmd) {
  for (const t of cmd.split(/[\s;&|()`'"]+/)) {
    const eq = t.indexOf("=");
    if (eq <= 0) continue;
    const name = t.slice(0, eq);
    if (/^[A-Za-z_]+$/.test(name) && ENV_REROUTE.test(name)) return true;
  }
  return false;
}

function allTargetsOfficial(cmd, tokens) {
  if (cmd.includes("#")) return false;
  if (hasRedirectOption(tokens)) return false;
  if (hasRerouteAssignment(cmd)) return false;
  const urls = cmd.match(/https?:\/\/[^\s'"`<>|;&)]+/g) ?? [];
  if (!urls.length) return false;
  for (const u of urls) { let host; try { host = new URL(u).host; } catch { return false; } if (!isOfficialHost(host)) return false; }
  if (tokens.some((t) => NET_TOOLS.has(t.toLowerCase()) && !URL_TOOLS.has(t.toLowerCase()))) return false;
  const rest = cmd.replace(/https?:\/\/[^\s'"`<>|;&)]+/g, " ");
  for (const t of rest.split(SEP)) if (/^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(:\d+)?(\/\S*)?$/.test(t) && !/\.(json|txt|csv|ts|js|mjs|md|sh|sql|ya?ml|toml|xml|html?)$/i.test(t)) return false;
  return true;
}

// `env`, `env -0`, `printenv`, `set`, `export -p`, `declare -x` / `-p` before a pipe dump the environment.
function dumpsEnvIntoPipe(cmd) {
  const segs = cmd.split("|");
  for (let i = 0; i < segs.length - 1; i++) {
    if (segs[i + 1] === "") continue; // part of "||"
    const w = segs[i].trim().split(/\s+/);
    const first = w[0] ?? "";
    const flagsOnly = w.slice(1).every((x) => x.startsWith("-"));
    if ((first === "env" || first === "printenv" || first === "set") && flagsOnly) return true;
    if ((first === "export" || first === "declare" || first === "typeset") && w.length > 1 && flagsOnly) return true;
  }
  return false;
}

/** Shell command check. Returns a reason string or null. */
export function evaluateCommand(cmd) {
  if (typeof cmd !== "string") return null;
  if (cmd.length > MAX_INPUT) return `the command is over ${MAX_INPUT / 1024} K characters, too large to check.`;
  const lit = findLiteralSecret(cmd);
  if (lit) return `the command contains ${lit}. Read secrets from env on the server; never paste them into commands.`;

  const pieces = cmd.split(/([\s|;&<>()`'"=,{}\[\]]+)/); // tokens at even indexes, separators at odd
  const tokens = pieces.filter((_, i) => i % 2 === 0 && pieces[i] !== "");
  const lower = tokens.map((t) => t.toLowerCase());
  const net = lower.some((t) => NET_TOOLS.has(t) || NET_TOOLS.has(t.split("/").pop())) || NET_CALLS.some((c) => cmd.includes(c));

  // A .env file piped into another command.
  for (let i = 0; i < pieces.length - 1; i += 2) if (isEnvFileToken(pieces[i]) && pieces[i + 1].includes("|")) return "the command pipes a .env file into another command.";
  if (!net) return null;

  if (tokens.some(isEnvFileToken)) return "the command reads or sends a .env file in a command that uses the network.";
  if (dumpsEnvIntoPipe(cmd)) return "the command pipes all environment variables into a command that uses the network.";
  if (tokens.some((t) => t.includes("/proc/") && t.endsWith("/environ"))) return "the command reads a process environment (/proc/*/environ) in a command that uses the network.";
  if (lower.includes("printenv") || cmd.includes("process.env)") || /\bos\.environ\b(?!\s*\[|\.get)/.test(cmd)) return "the command reads environment variables in a command that uses the network.";
  if (SECRET_NAME.test(cmd) && !allTargetsOfficial(cmd, tokens)) return "the command uses a secret env variable in a network call to a host other than api.stripe.com or your *.supabase.co project.";
  return null;
}

/** Claude Code PreToolUse input. Returns {decision:"deny",reason} or null. */
export function evaluateEgress(input) {
  const tool = String(input?.tool_name ?? "");
  const ti = input?.tool_input ?? {};
  let why = null;
  if (tool === "Bash") why = evaluateCommand(ti.command);
  else if (tool === "WebFetch" || tool === "WebSearch" || tool.startsWith("mcp__")) {
    const text = tool.startsWith("mcp__") ? JSON.stringify(ti) : `${ti.url ?? ""} ${ti.prompt ?? ""} ${ti.query ?? ""}`;
    if (text.length > MAX_INPUT) why = `the tool input is over ${MAX_INPUT / 1024} K characters, too large to check.`;
    else { const lit = findLiteralSecret(text); if (lit) why = `the ${tool.startsWith("mcp__") ? "MCP tool input" : "request"} contains ${lit}.`; }
  }
  return why ? { decision: "deny", reason: `Secret egress blocked: ${why}` } : null;
}
