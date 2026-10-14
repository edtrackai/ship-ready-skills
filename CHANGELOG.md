# Changelog

## 0.2.0 (2026-10-14)
- New skill `launch-security-check`: a quick pre-launch pass for public tables without RLS (L1), service-role or secret keys reaching client code (L2), and Stripe webhooks without `constructEvent` signature verification (L3). `allowed-tools: Read Grep Glob`. Every grep pattern was checked against the free checker's `vulnerable-app` (hits) and `clean-app` (no hits) fixtures.
- QA fixes before release: L1 patterns allow any whitespace and line breaks (`\s+`, searched across lines) and count only `public`-schema tables; L3 globs `**/*webhook*/**/route.{ts,js,mjs}` (covering `app/` and `src/app/`) and `**/pages/api/**/*webhook*.{ts,js}`; L2 says `'use client'` must be the first statement (comments may come before it); L3 adds the Pages Router raw-body fix (`export const config = { api: { bodyParser: false } }`).
- README: skills table and usage updated; the Ad links now carry `utm_content` per product.

## 0.1.0 (2026-10-14)
- First release: `supabase-rls-review` and `stripe-webhook-review`.
