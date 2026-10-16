#!/usr/bin/env node
// unthrottled-route-check: flags Next.js API routes that call an AI API or
// create a Stripe Checkout Session with no rate limiter in sight.
// Zero dependencies. Static text scan: it can miss limiters applied in ways
// it doesn't recognise, and it can miss sinks hidden more than one import deep.
// Usage: node scan-unthrottled.mjs [projectDir=.] [--json] [--exit-zero]
import { readdirSync, readFileSync, statSync, existsSync } from "node:fs";
import { join, relative, dirname, resolve, extname } from "node:path";

const MAX_BYTES = 512 * 1024;
const CODE_EXT = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"]);
const SKIP_DIRS = new Set(["node_modules", ".next", ".git", "dist", "build", "out", ".vercel", "coverage"]);

// Matched by method shape, whatever the client variable is called.
export const SINKS = [
  { id: "ai", label: "AI API call", severity: "high", re: /\.\s*chat\s*\.\s*completions\s*\.\s*(?:create|stream|parse)\s*\(/ },
  { id: "ai", label: "AI API call", severity: "high", re: /\.\s*responses\s*\.\s*(?:create|stream|parse)\s*\(/ },
  { id: "ai", label: "AI API call", severity: "high", re: /\.\s*messages\s*\.\s*(?:create|stream)\s*\(/ },
  { id: "ai", label: "AI API call", severity: "high", re: /\.\s*(?:images\s*\.\s*generate|embeddings\s*\.\s*create|completions\s*\.\s*create)\s*\(/ },
  { id: "ai", label: "AI SDK call", severity: "high", re: /\b(?:streamText|generateText|generateObject|streamObject)\s*\(/ },
  { id: "checkout", label: "Stripe Checkout Session created", severity: "medium", re: /\.\s*checkout\s*\.\s*sessions\s*\.\s*create\s*\(/ },
];

export const FETCH_SINK = { id: "ai", label: "AI API call (fetch)", severity: "high", re: null };

// A route counts as limited only when it imports a real limiter AND uses it:
// - known packages, or a local module whose file name is ratelimit / rate-limit /
//   rate-limiter / limiter (not any path that merely contains "ratelimit");
// - then calls an imported binding (`enforce(...)`, `rateLimit(req)`, `x.limit(`/`x.protect(`)
//   or builds a value from one (`const rl = new Ratelimit(...)`, `const aj = arcjet(...)`)
//   and uses that value again (`rl.limit(id)`, `aj.protect(req)`, or passes it on).
export const LIMITER_PACKAGES = /^(?:@upstash\/ratelimit|@arcjet\/[\w-]+|arcjet|rate-limiter-flexible|express-rate-limit|@unkey\/ratelimit|limiter)$/;
export const LOCAL_LIMITER_MODULE = /^(?:\.{1,2}\/|[@~#]\/)(?:[^"']*\/)?(?:ratelimit|rate-limit|rate-limiter|ratelimiter|limiter)(?:\.[cm]?[jt]sx?)?$/i;
const IMPORT_STMT = /import\s+(?:type\s+)?([\w$\s{},*]{1,400}?)\s+from\s*["']([^"']{1,300})["']|(?:const|let|var)\s+([\w$\s{},:]{1,400}?)\s*=\s*require\s*\(\s*["']([^"']{1,300})["']\s*\)/g;
const esc = (x) => x.replace(/[$]/g, "\\$");

export function isLimiterModule(spec) { return LIMITER_PACKAGES.test(spec) || LOCAL_LIMITER_MODULE.test(spec); }

export function limiterBindings(src) {
  const names = new Set();
  for (const m of src.matchAll(IMPORT_STMT)) {
    const clause = m[1] ?? m[3], spec = m[2] ?? m[4];
    if (!isLimiterModule(spec) || /^\s*type\s/.test(m[0].slice(6))) continue;
    for (const part of clause.replace(/[{}]/g, ",").split(",")) {
      const t = part.trim().replace(/^type\s+/, "");
      if (!t) continue;
      const n = (t.match(/(?:\bas|:)\s*([\w$]+)$/) || t.match(/^\*\s+as\s+([\w$]+)$/) || t.match(/^([\w$]+)$/) || [])[1];
      if (n) names.add(n);
    }
  }
  return names;
}

export function hasLimiter(src) {
  const imported = limiterBindings(src);
  if (!imported.size) return false;
  // values built from imported bindings, two passes for chains
  const derived = new Set();
  for (let pass = 0; pass < 2; pass++) {
    for (const m of src.matchAll(/(?:const|let|var)\s+([\w$]+)\s*=\s*(?:await\s+)?(?:new\s+)?([\w$]+)\b/g)) {
      if (imported.has(m[2]) || derived.has(m[2])) derived.add(m[1]);
    }
  }
  for (const n of imported) {
    if (derived.has(n)) continue;
    const call = new RegExp(`(?<![\\w$.]|new\\s|=\\s{0,5})${esc(n)}\\s*(?:\\.\\s*(?:limit|protect)\\s*)?\\(`);
    if (call.test(src)) return true;
  }
  for (const v of derived) {
    const decl = new RegExp(`(?:const|let|var)\\s+${esc(v)}\\s*=`, "g");
    const uses = (src.match(new RegExp(`(?<![\\w$.])${esc(v)}(?![\\w$])`, "g")) || []).length;
    const decls = (src.match(decl) || []).length;
    if (uses > decls) return true;
  }
  return false;
}

/** Does a middleware matcher (array or string source) cover /api? Negative lookaheads that name api exclude it. */
export function matcherCoversApi(text) {
  if (text == null) return true;
  if (/\(\?![^)]{0,300}\bapi\b/.test(text)) return false;
  return /\bapi\b|\.\*\)|["'`]\/:path\*/.test(text);
}

const AI_HOST = String.raw`https:\/\/api\.(?:openai|anthropic)\.com(?=[\/"'\x60$]|$)`;
const AI_URL_LITERAL = new RegExp(String.raw`["'\x60]` + AI_HOST);
const AI_BASE_CONST = new RegExp(String.raw`(?:const|let|var)\s+([\w$]+)\s*=\s*["'\x60]` + AI_HOST, "g");

/** First AI fetch: a literal URL, or fetch(BASE...) / fetch(`${BASE}...`) where BASE is a const AI host URL. */
export function findAiFetch(src) {
  let best = -1;
  for (const m of src.matchAll(new RegExp(AI_URL_LITERAL.source, "g"))) {
    // a const base URL declaration is not a call by itself; its uses are found below
    if (/(?:const|let|var)\s+[\w$]+\s*=\s*$/.test(src.slice(Math.max(0, m.index - 120), m.index))) continue;
    best = m.index;
    break;
  }
  for (const m of src.matchAll(AI_BASE_CONST)) {
    const n = esc(m[1]);
    const use = new RegExp(String.raw`\bfetch\s*\(\s*(?:${n}\b|\x60\$\{\s*${n}\s*\}|new\s+URL\s*\([^)]{0,200}\b${n}\b)`).exec(src);
    if (use && (best < 0 || use.index < best)) best = use.index;
  }
  return best;
}

export function stripComments(src) {
  return src
    .replace(/\/\*[^*]*\*+(?:[^/*][^*]*\*+)*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/(^|[^:"'`\\])\/\/[^\n]*/g, "$1");
}

function walk(dir, out = []) {
  let entries;
  try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (e.isSymbolicLink()) continue;
    const p = join(dir, e.name);
    if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(p, out); }
    else if (CODE_EXT.has(extname(e.name))) out.push(p);
  }
  return out;
}

function read(p) {
  try { if (statSync(p).size > MAX_BYTES) return null; return stripComments(readFileSync(p, "utf8")); } catch { return null; }
}

export function isRouteFile(rel) {
  const r = rel.split("\\").join("/");
  return /(^|\/)app\/(?:.*\/)?route\.[cm]?[jt]sx?$/.test(r) || /(^|\/)pages\/api\//.test(r);
}

function resolveImport(root, fromFile, spec) {
  let base;
  if (spec.startsWith("./") || spec.startsWith("../")) base = resolve(dirname(fromFile), spec);
  else if (spec.startsWith("@/") || spec.startsWith("~/")) {
    const rest = spec.slice(2);
    base = existsSync(join(root, "src")) && !existsSync(join(root, rest.split("/")[0])) ? join(root, "src", rest) : join(root, rest);
  } else return null;
  for (const c of [base, ...[...CODE_EXT].map((x) => base + x), ...[...CODE_EXT].map((x) => join(base, "index" + x))]) {
    try { if (statSync(c).isFile()) return c; } catch {}
  }
  return null;
}

const IMPORT_RE = /(?:import|export)\s[^"'`;]{0,400}?from\s*["']([^"']+)["']|import\s*\(\s*["']([^"']+)["']\s*\)|require\s*\(\s*["']([^"']+)["']\s*\)/g;

function lineOf(src, idx) { let n = 1; for (let i = 0; i < idx; i++) if (src.charCodeAt(i) === 10) n++; return n; }

export function scan(root) {
  root = resolve(root);
  const findings = [];
  const mwFile = ["middleware", "proxy"].flatMap((n) => [...CODE_EXT].flatMap((x) => [join(root, n + x), join(root, "src", n + x)])).find(existsSync);
  const mwSrc = mwFile ? read(mwFile) : null;
  // Downgrade only if the middleware has a limiter and its matcher (if any) can cover /api.
  const matcher = mwSrc ? /matcher\s*:\s*(\[[^\]]{0,2000}\]|["'`][^"'`]{0,500}["'`])/.exec(mwSrc) : null;
  const mwLimiter = Boolean(mwSrc && hasLimiter(mwSrc) && matcherCoversApi(matcher ? matcher[1] : null));
  const files = walk(root).filter((f) => isRouteFile(relative(root, f)));
  for (const file of files) {
    const src = read(file);
    if (src === null) continue;
    const rel = relative(root, file).split("\\").join("/");
    const routeHasLimiter = hasLimiter(src);
    const hits = [];
    for (const s of SINKS) {
      const m = s.re.exec(src);
      if (m) hits.push({ sink: s, line: lineOf(src, m.index), via: null });
    }
    const f = findAiFetch(src);
    if (f >= 0) hits.push({ sink: FETCH_SINK, line: lineOf(src, f), via: null });
    // One level of local imports (e.g. route -> lib/ai.ts -> openai)
    let helperLimiter = false;
    for (const m of src.matchAll(IMPORT_RE)) {
      const target = resolveImport(root, file, m[1] || m[2] || m[3]);
      if (!target) continue;
      const hs = read(target);
      if (!hs) continue;
      if (hasLimiter(hs)) helperLimiter = true;
      const fs = findAiFetch(hs) >= 0 ? [FETCH_SINK] : [];
      for (const s of [...SINKS, ...fs]) if ((s === FETCH_SINK || s.re.test(hs)) && !hits.some((h) => h.sink.id === s.id)) hits.push({ sink: s, line: lineOf(src, m.index), via: relative(root, target).split("\\").join("/") });
    }
    if (!hits.length || routeHasLimiter || helperLimiter) continue;
    const seen = new Set();
    for (const h of hits) {
      if (seen.has(h.sink.id)) continue;
      seen.add(h.sink.id);
      findings.push({
        rule: h.sink.id === "ai" ? "U1-unthrottled-ai-route" : "U2-unthrottled-checkout-route",
        severity: mwLimiter ? "low" : h.sink.severity,
        file: rel, line: h.line, via: h.via,
        message: `${h.sink.label}${h.via ? ` (via ${h.via})` : ""} with no rate limiter in this route` + (mwLimiter ? `; ${relative(root, mwFile)} has a limiter, so confirm it matches this path and limits per user` : ""),
      });
    }
  }
  return { root, scannedRoutes: files.length, middlewareLimiter: mwLimiter, findings };
}

const isMain = process.argv[1] && resolve(process.argv[1]) === resolve(new URL(import.meta.url).pathname);
if (isMain) {
  const args = process.argv.slice(2);
  const dir = args.find((a) => !a.startsWith("--")) ?? ".";
  if (!existsSync(dir)) { console.error(`not found: ${dir}`); process.exit(2); }
  const res = scan(dir);
  if (args.includes("--json")) console.log(JSON.stringify(res, null, 2));
  else {
    console.log(`unthrottled-route-check: scanned ${res.scannedRoutes} route file(s) in ${res.root}`);
    for (const f of res.findings) console.log(`  [${f.severity}] ${f.rule} ${f.file}:${f.line}  ${f.message}`);
    console.log(res.findings.length ? `${res.findings.length} finding(s).` : "No unthrottled AI or checkout routes found by this scan.");
  }
  const blocking = res.findings.some((f) => f.severity !== "low");
  process.exit(blocking && !args.includes("--exit-zero") ? 1 : 0);
}
