#!/usr/bin/env node
// PreToolUse hook (Bash, WebFetch, WebSearch, mcp__*): blocks literal secrets and secret env vars leaving the machine.
// Fails closed: crash, bad JSON or timeout -> exit 2 (blocks the call).
const WATCHDOG_MS = Number(process.env.GUARDRAILS_WATCHDOG_MS) || 8000;
function block(why) { try { process.stderr.write(`[guardrails] Blocked because the safety check could not run (${why}).\n`); } catch {} process.exit(2); }
const watchdog = setTimeout(() => block("timeout"), WATCHDOG_MS);
process.on("uncaughtException", (e) => block(`crash: ${e?.message ?? e}`));
let raw = "";
process.stdin.setEncoding("utf8");
process.stdin.on("data", (c) => (raw += c));
process.stdin.on("end", async () => {
  let input; try { input = JSON.parse(raw); } catch { return block("hook input was not valid JSON"); }
  let r; try { const { evaluateEgress } = await import("./egress-core.mjs"); r = evaluateEgress(input); } catch (e) { return block(`crash: ${e?.message ?? e}`); }
  clearTimeout(watchdog);
  if (r) process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny", permissionDecisionReason: `[guardrails] ${r.reason}` } }));
  process.exit(0);
});
