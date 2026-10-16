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

export const SINKS = [
  { id: "ai", label: "AI API call", severity: "high", re: /\b(?:openai|client|ai)\s*\.\s*(?:chat\s*\.\s*completions|responses|completions|images|embeddings|audio\s*\.\s*\w+)\s*\.\s*(?:create|generate|stream)\s*\(/ },
  { id: "ai", label: "AI API call", severity: "high", re: /\b(?:anthropic|client|claude)\s*\.\s*messages\s*\.\s*(?:create|stream)\s*\(/ },
  { id: "ai", label: "AI SDK call", severity: "high", re: /\b(?:streamText|generateText|generateObject|streamObject)\s*\(/ },
  { id: "checkout", label: "Stripe Checkout Session created", severity: "medium", re: /\.\s*checkout\s*\.\s*sessions\s*\.\s*create\s*\(/ },
];

export const LIMITER_SIGNALS = [
  /from\s+["']@upstash\/ratelimit["']/, /from\s+["']@arcjet\/[\w-]+["']/, /from\s+["']rate-limiter-flexible["']/,
  /from\s+["']express-rate-limit["']/, /from\s+["']@unkey\/ratelimit["']/, /from\s+["']limiter["']/,
  /\b(?:ratelimit|rateLimit|rate_limit|RateLimiter|limiter|throttle)\b/i,
];

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

const IMPORT_RE = /(?:import|export)\s[^"'`;]*?from\s*["']([^"']+)["']|import\s*\(\s*["']([^"']+)["']\s*\)|require\s*\(\s*["']([^"']+)["']\s*\)/g;

function lineOf(src, idx) { let n = 1; for (let i = 0; i < idx; i++) if (src.charCodeAt(i) === 10) n++; return n; }
const hasLimiter = (src) => LIMITER_SIGNALS.some((re) => re.test(src));

export function scan(root) {
  root = resolve(root);
  const findings = [];
  const mwFile = ["middleware", "proxy"].flatMap((n) => [...CODE_EXT].flatMap((x) => [join(root, n + x), join(root, "src", n + x)])).find(existsSync);
  const mwSrc = mwFile ? read(mwFile) : null;
  const mwLimiter = Boolean(mwSrc && hasLimiter(mwSrc));
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
    // One level of local imports (e.g. route -> lib/ai.ts -> openai)
    let helperLimiter = false;
    for (const m of src.matchAll(IMPORT_RE)) {
      const target = resolveImport(root, file, m[1] || m[2] || m[3]);
      if (!target) continue;
      const hs = read(target);
      if (!hs) continue;
      if (hasLimiter(hs)) helperLimiter = true;
      for (const s of SINKS) if (s.re.test(hs) && !hits.some((h) => h.sink.id === s.id)) hits.push({ sink: s, line: lineOf(src, m.index), via: relative(root, target).split("\\").join("/") });
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
