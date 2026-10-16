---
name: unthrottled-route-check
description: Find Next.js API routes that call OpenAI, Anthropic or the Vercel AI SDK, or create a Stripe Checkout Session, with no rate limiter. Use when the user asks about rate limiting, AI cost per user, surprise API bills, refresh loops at checkout, or abuse protection before launch.
allowed-tools: Read Grep Glob
---

# unthrottled-route-check

Review only. Don't edit files unless the user asks for the fixes afterwards.

## Scope
Route handlers: `app/**/route.{ts,js}`, `src/app/**/route.{ts,js}`, `pages/api/**`, `src/pages/api/**`. Also read `middleware.ts` or `proxy.ts` at the project root (or in `src/`).

## Find the sinks
Grep the route files for:
- AI calls: `chat.completions.create`, `responses.create`, `images.generate`, `embeddings.create`, `messages.create`, `messages.stream`, `streamText(`, `generateText(`, `generateObject(`, `streamObject(`
- Checkout: `checkout.sessions.create`

For routes with no match, check their local imports (`./`, `../`, `@/`) one level deep: a helper such as `lib/ai.ts` may make the call.

## Look for a limiter
A route counts as limited when it (or the helper it imports) uses one of: `@upstash/ratelimit`, `@arcjet/*`, `rate-limiter-flexible`, `@unkey/ratelimit`, or calls a local limiter (`limiter.limit(`, `ratelimit`, `rateLimit(`) before the sink runs. Ignore mentions in comments.

If `middleware.ts`/`proxy.ts` has a limiter, check that its `matcher` covers the route and whether it keys on the user id or only the IP. IP-only limits let one signed-in user with several IPs (or a shared office IP) through or block wrongly.

## Report
For each finding give file:line, id, severity and fix.

| Id | Severity | Finding | Fix |
|---|---|---|---|
| U1 | high | AI call in a route with no limiter | Require a signed-in user, then limit per user id (for example Upstash `Ratelimit.slidingWindow(10, "60 s")`) and return 429 with `Retry-After`. Add a per-user monthly dollar cap and a provider-side project limit as a backstop. |
| U2 | medium | `checkout.sessions.create` in a route with no limiter | Limit per user, pass an `idempotencyKey`, reuse an open session for the same cart, and disable the button while the request runs. |
| U1/U2 | low | Same, but a middleware limiter exists | Confirm the matcher covers the route and the key is per user. |

End with: routes checked, findings by severity, and anything you couldn't confirm (dynamic imports, wrappers more than one import deep).

## Optional script
`scripts/scan-unthrottled.mjs` in this skill's folder runs the same check with Node 20+ and no dependencies. It is not run by this skill. To run it yourself: `node scripts/scan-unthrottled.mjs <project-dir>` (add `--json` or `--exit-zero`). It exits 1 when it finds a high or medium issue, so it can run in CI. It's a text scan: treat a clean result as "nothing found", not as proof the app is protected.
