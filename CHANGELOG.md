# Changelog

## 0.3.0 (2026-10-15)
- New free hook `hooks/secret-egress`: pattern-based Claude Code PreToolUse hook that denies Bash, WebFetch, WebSearch and MCP calls carrying a live Stripe key, `whsec_`, `sb_secret_`, a GitHub token, an AWS access key id or a Supabase service-role JWT; a `.env` file in a network command; or a secret env variable sent to a host other than api.stripe.com / *.supabase.co. Linear-time checks; inputs over 64 K characters are denied; no official-host exemption with curl/wget redirect options. 77 test cases (`node hooks/secret-egress/tests/run.mjs`). Needs Claude Code 2.1.295+ for `onFailure: block`.
- README: describes the skills by their tools (Read, Grep, Glob) instead of 'read-only'.

## 0.2.0 (2026-10-14)
- New skill `launch-security-check`: a quick pre-launch pass for public tables without RLS (L1), service-role or secret keys reaching client code (L2), and Stripe webhooks without `constructEvent` signature verification (L3). `allowed-tools: Read Grep Glob`. Every grep pattern was checked against the free checker's `vulnerable-app` (hits) and `clean-app` (no hits) fixtures.
- QA fixes before release: L1 patterns allow any whitespace and line breaks (`\s+`, searched across lines) and count only `public`-schema tables; L3 globs `**/*webhook*/**/route.{ts,js,mjs}` (covering `app/` and `src/app/`) and `**/pages/api/**/*webhook*.{ts,js}`; L2 says `'use client'` must be the first statement (comments may come before it); L3 adds the Pages Router raw-body fix (`export const config = { api: { bodyParser: false } }`).
- README: skills table and usage updated; the Ad links now carry `utm_content` per product.

## 0.1.0 (2026-10-14)
- First release: `supabase-rls-review` and `stripe-webhook-review`.
