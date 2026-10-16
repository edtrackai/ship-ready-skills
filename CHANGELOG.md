# Changelog

## 0.6.0 (2026-10-17)
- New skill `unthrottled-route-check` (Read, Grep, Glob): flags Next.js API routes that call OpenAI, Anthropic or the Vercel AI SDK (U1, high) or create a Stripe Checkout Session (U2, medium) with no rate limiter in the route, in a local helper it imports, or in `middleware.ts`/`proxy.ts` (then low).
- Its folder includes an optional zero-dependency Node 20+ script, `scripts/scan-unthrottled.mjs` (text or `--json` output; exit 1 on high/medium for CI, `--exit-zero` to report only), and 8 tests over 3 fixture apps (`node --test tests/` in the skill folder). The skill doesn't run the script. Static text scan: limits in the skill's SKILL.md.
- README: skill count, list and table updated; the "instructions only: no scripts" line now describes the optional script.

## 0.5.1 (2026-10-15)
- Docs only: `plugins/supabase-grants-guard` is now `supabase-grants-check` 0.1.6. Its README is no longer marked draft, and it has GitHub install lines, current test counts (166 unit, 22 `claude plugin test`), a block summary that matches the current block list, and narrowed limits (`GRANT ALL ON SCHEMA|DATABASE|TABLESPACE … TO authenticated` is allowed; `ALTER … SET SCHEMA` isn't checked). No code changes.

## 0.5.0 (2026-10-15)
- New plugin `plugins/supabase-grants-guard` (`supabase-grants-check` 0.1.5, MIT), listed in `.claude-plugin/marketplace.json`. It bundles the `supabase-grants-check` skill, the SQL checker (it only reads catalog views and makes no changes) and a mod (Claude Code 2.1.287+) that refuses SQL that grants `anon` more than `select` in Bash commands, file writes and MCP tool inputs: write-level grants to `anon` or `PUBLIC`, role grants to `anon`/`authenticated`, ownership transfers and role attributes for `anon`/`authenticated`. Pattern-based; dynamic SQL can't be fully caught (limits in the plugin README).
- Tests: `node tests/unit.mjs` 166/166 including 1 MB timing inputs; `claude plugin test` 22/22; `claude plugin validate --strict` passes. Not tested in a live interactive session.

## 0.4.0 (2026-10-15)
- New skill `supabase-grants-check` (Read, Grep, Glob): G1–G8 for the security side of the Data API grants change Supabase's changelog schedules for 30 Oct 2026, matching the free SQL checker's C1–C7.

## 0.3.1 (2026-10-15)
- secret-egress hook: curl/wget calls to api.stripe.com or `*.supabase.co` lose the official-host exemption when the command sets a proxy or curl/wget config variable (`*PROXY*=`, `*_proxy=`, `CURL_HOME=`, `CURLRC=`, `WGETRC=`, `CURLOPT*=`, any case), a CA-trust variable (`SSL_CERT*=`, `*CA_BUNDLE*=`, `*CA_CERT*=`), any `--proxy*`/`--socks*` option, `--proxytunnel` or a short-option cluster containing `p`. README limits now name base64 and split strings. 97 test cases.

## 0.3.0 (2026-10-15)
- New free hook `hooks/secret-egress`: pattern-based Claude Code PreToolUse hook that denies Bash, WebFetch, WebSearch and MCP calls carrying a live Stripe key, `whsec_`, `sb_secret_`, a GitHub token, an AWS access key id or a Supabase service-role JWT; a `.env` file in a network command; or a secret env variable sent to a host other than api.stripe.com / *.supabase.co. Linear-time checks; inputs over 64 K characters are denied; no official-host exemption with curl/wget redirect options. 77 test cases (`node hooks/secret-egress/tests/run.mjs`). Needs Claude Code 2.1.295+ for `onFailure: block`.
- README: describes the skills by their tools (Read, Grep, Glob) instead of 'read-only'.

## 0.2.0 (2026-10-14)
- New skill `launch-security-check`: a quick pre-launch pass for public tables without RLS (L1), service-role or secret keys reaching client code (L2), and Stripe webhooks without `constructEvent` signature verification (L3). `allowed-tools: Read Grep Glob`. Every grep pattern was checked against the free checker's `vulnerable-app` (hits) and `clean-app` (no hits) fixtures.
- QA fixes before release: L1 patterns allow any whitespace and line breaks (`\s+`, searched across lines) and count only `public`-schema tables; L3 globs `**/*webhook*/**/route.{ts,js,mjs}` (covering `app/` and `src/app/`) and `**/pages/api/**/*webhook*.{ts,js}`; L2 says `'use client'` must be the first statement (comments may come before it); L3 adds the Pages Router raw-body fix (`export const config = { api: { bodyParser: false } }`).
- README: skills table and usage updated; the Ad links now carry `utm_content` per product.

## 0.1.0 (2026-10-14)
- First release: `supabase-rls-review` and `stripe-webhook-review`.
