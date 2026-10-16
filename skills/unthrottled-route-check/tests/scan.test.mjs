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

test("limiter detection: imports and calls", async () => {
  const { hasLimiter } = await import("../scripts/scan-unthrottled.mjs");
  for (const src of ['import { Ratelimit } from "@upstash/ratelimit"', 'import { enforce } from "@/lib/ratelimit"', "await ratelimit.limit(id)", "await aiLimiter.limit(id)", "await rl.limit(ip)", "await rateLimit(req)", "await aj.protect(req)"]) assert.ok(hasLimiter(src), src);
  for (const src of ['db.from("x").select().limit(10)', 'const limiter = "x"', "// ratelimit later", "throttleMs = 5"]) assert.ok(!hasLimiter(src), src);
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
