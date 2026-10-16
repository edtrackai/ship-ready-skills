import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { scan, stripComments, isRouteFile } from "../scripts/scan-unthrottled.mjs";

const fx = (n) => fileURLToPath(new URL(`./fixtures/${n}`, import.meta.url));
const script = fileURLToPath(new URL("../scripts/scan-unthrottled.mjs", import.meta.url));
const key = (f) => `${f.rule} ${f.file}:${f.line} ${f.severity}`;

test("vulnerable fixture: AI, helper-AI, AI SDK, pages/api and checkout routes are flagged", () => {
  const r = scan(fx("vuln"));
  assert.equal(r.scannedRoutes, 5);
  assert.deepEqual(r.findings.map(key).sort(), [
    "U1-unthrottled-ai-route app/api/chat/route.ts:5 high",
    "U1-unthrottled-ai-route app/api/ok-comment/route.ts:3 high",
    "U1-unthrottled-ai-route app/api/summarize/route.ts:1 high",
    "U1-unthrottled-ai-route pages/api/gen.js:2 high",
    "U2-unthrottled-checkout-route app/api/checkout/route.ts:4 medium",
  ]);
  assert.equal(r.findings.find((f) => f.file.includes("summarize")).via, "lib/ai.ts");
});

test("a limiter mentioned only in a comment does not count", () => {
  assert.ok(scan(fx("vuln")).findings.some((f) => f.file === "app/api/ok-comment/route.ts"));
});

test("safe fixture: route limiter and imported helper limiter -> no findings", () => {
  const r = scan(fx("safe"));
  assert.equal(r.scannedRoutes, 2);
  assert.deepEqual(r.findings, []);
});

test("middleware limiter downgrades findings to low", () => {
  const r = scan(fx("mw"));
  assert.equal(r.middlewareLimiter, true);
  assert.deepEqual(r.findings.map((f) => f.severity), ["low"]);
});

test("CLI exit codes: 1 on high/medium, 0 with --exit-zero, 0 when only low, 0 when clean", () => {
  assert.equal(spawnSync(process.execPath, [script, fx("vuln")]).status, 1);
  assert.equal(spawnSync(process.execPath, [script, fx("vuln"), "--exit-zero"]).status, 0);
  assert.equal(spawnSync(process.execPath, [script, fx("mw")]).status, 0);
  const out = execFileSync(process.execPath, [script, fx("safe")], { encoding: "utf8" });
  assert.match(out, /No unthrottled AI or checkout routes found/);
  const json = JSON.parse(execFileSync(process.execPath, [script, fx("safe"), "--json"], { encoding: "utf8" }));
  assert.equal(json.findings.length, 0);
  assert.equal(spawnSync(process.execPath, [script, "/nonexistent-dir-xyz"]).status, 2);
});

test("stripComments keeps URLs in strings and line numbers", () => {
  const s = stripComments('const u = "https://x.y"; // ratelimit\n/* limiter\n */ ok');
  assert.ok(s.includes("https://x.y"));
  assert.ok(!/ratelimit|limiter/.test(s));
  assert.equal(s.split("\n").length, 3);
});

test("route file detection", () => {
  assert.ok(isRouteFile("app/api/x/route.ts"));
  assert.ok(isRouteFile("src/app/(group)/api/y/route.js"));
  assert.ok(isRouteFile("pages/api/z.ts"));
  assert.ok(!isRouteFile("app/page.tsx"));
  assert.ok(!isRouteFile("lib/route-helpers.ts"));
});

test("comment stripping and scan stay fast on 512 KB pathological input", () => {
  const big = "/*" + "*".repeat(200_000) + "a".repeat(100_000) + "//".repeat(50_000);
  const t = Date.now();
  stripComments(big);
  for (let i = 0; i < 3; i++) stripComments("/*" + "*/*".repeat(150_000));
  assert.ok(Date.now() - t < 1000, `took ${Date.now() - t} ms`);
});

test("MEDIUM-R1: AI calls found by method whatever the client is called; raw fetch too", () => {
  const r = scan(fx("evasion"));
  assert.equal(r.scannedRoutes, 5);
  assert.deepEqual(r.findings.map(key).sort(), [
    "U1-unthrottled-ai-route app/api/client2/route.ts:4 high",
    "U1-unthrottled-ai-route app/api/fakelimit/route.ts:7 high",
    "U1-unthrottled-ai-route app/api/llm/route.ts:3 high",
    "U1-unthrottled-ai-route app/api/rawfetch/route.ts:2 high",
    "U2-unthrottled-checkout-route app/api/words/route.ts:4 medium",
  ]);
});

test("LOW-R2: a query .limit(10) or the bare word limiter/throttle doesn't count as a limiter", () => {
  const files = scan(fx("evasion")).findings.map((f) => f.file);
  assert.ok(files.includes("app/api/fakelimit/route.ts"));
  assert.ok(files.includes("app/api/words/route.ts"));
});

test("limiter detection: real limiter import plus a call on it", async () => {
  const { hasLimiter } = await import("../scripts/scan-unthrottled.mjs");
  const yes = [
    'import { Ratelimit } from "@upstash/ratelimit"\nconst rl = new Ratelimit({});\nawait rl.limit(id)',
    'import { enforce, upstashLimiter } from "@/lib/ratelimit"\nconst l = upstashLimiter(x);\nawait enforce(l, id)',
    'import { rateLimit } from "../lib/rate-limit"\nawait rateLimit(req)',
    'import arcjet from "@arcjet/next"\nconst aj = arcjet({});\nawait aj.protect(req)',
    'import { limiter as lim } from "./limiter"\nawait lim.limit("u")',
    'import { upstashLimiter } from "@/lib/ratelimit"\nconst limiter = upstashLimiter(p);\nawait guardedCheckout({ limiter })',
  ];
  const no = [
    'import { enforce } from "@/lib/ratelimit"',
    "await ratelimit.limit(id)",
    "rateLimits.limit(5)",
    "aj.protect(req)",
    'import { notes } from "@/lib/ratelimit-docs/notes"\nnotes()',
    'import { Ratelimit } from "@upstash/ratelimit"\nconst rl = new Ratelimit({});',
    'import type { Limiter } from "./ratelimit"\nfoo()',
    'db.from("x").select().limit(10)',
  ];
  for (const src of yes) assert.ok(hasLimiter(src), src);
  for (const src of no) assert.ok(!hasLimiter(src), src);
});

test("LOW: path containing 'ratelimit', rateLimits.limit(, .protect( without Arcjet, unused limiter -> still flagged", () => {
  const r = scan(fx("noise"));
  assert.equal(r.scannedRoutes, 3);
  assert.deepEqual(r.findings.map((f) => f.file).sort(), ["app/api/protect/route.ts", "app/api/rlpath/route.ts", "app/api/unused/route.ts"]);
});

test("LOW: fetch with a const or template-literal base URL to the OpenAI/Anthropic hosts is an AI call", () => {
  const r = scan(fx("fetchbase"));
  assert.deepEqual(r.findings.map(key).sort(), [
    "U1-unthrottled-ai-route app/api/constbase/route.ts:3 high",
    "U1-unthrottled-ai-route app/api/newurl/route.ts:2 high",
    "U1-unthrottled-ai-route app/api/tpl/route.ts:3 high",
  ]);
});

test("MEDIUM: matcher with a negative lookahead excluding api keeps full severity and CI exits 1", async () => {
  const { matcherCoversApi } = await import("../scripts/scan-unthrottled.mjs");
  assert.equal(matcherCoversApi('["/((?!api|_next/static|_next/image|favicon.ico).*)"]'), false);
  assert.equal(matcherCoversApi('"/((?!_next/static|favicon.ico).*)"'), true);
  assert.equal(matcherCoversApi('["/api/:path*"]'), true);
  assert.equal(matcherCoversApi('["/dashboard/:path*"]'), false);
  assert.equal(matcherCoversApi(null), true);
  const r = scan(fx("mwlookahead"));
  assert.equal(r.middlewareLimiter, false);
  assert.deepEqual(r.findings.map((f) => f.severity), ["high"]);
  assert.equal(spawnSync(process.execPath, [script, fx("mwlookahead")]).status, 1);
});

test("middleware limiter whose matcher excludes /api does not downgrade", () => {
  const r = scan(fx("mwpages"));
  assert.equal(r.middlewareLimiter, false);
  assert.deepEqual(r.findings.map((f) => f.severity), ["high"]);
});

test("LOW-R1: import regex stays fast on a 500 KB route of 'import a '", async () => {
  const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
  const { join } = await import("node:path");
  const { tmpdir } = await import("node:os");
  const d = mkdtempSync(join(tmpdir(), "urc-"));
  mkdirSync(join(d, "app/api/x"), { recursive: true });
  writeFileSync(join(d, "app/api/x/route.ts"), "import a ".repeat(55_000));
  const t = Date.now();
  scan(d);
  assert.ok(Date.now() - t < 2000, `took ${Date.now() - t} ms`);
});

test("bounded regexes: limiter, import and fetch detection stay fast on pathological input", async () => {
  const { hasLimiter, findAiFetch } = await import("../scripts/scan-unthrottled.mjs");
  const inputs = ["import " + "{a,".repeat(60_000), "const x = ".repeat(60_000), 'import a from "./ratelimit"\n' + "a".repeat(400_000), 'const B = "https://api.openai.com"\n' + "fetch(new URL(".repeat(30_000)];
  const t = Date.now();
  for (const s of inputs) { hasLimiter(s); findAiFetch(s); }
  assert.ok(Date.now() - t < 1500, `took ${Date.now() - t} ms`);
});
