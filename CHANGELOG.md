# Changelog

## 0.2.0 (2026-10-14)
- New skill `launch-security-check`: a quick pre-launch pass for public tables without RLS (L1), service-role or secret keys reaching client code (L2), and Stripe webhooks without `constructEvent` signature verification (L3). `allowed-tools: Read Grep Glob`. Every grep pattern was checked against the free checker's `vulnerable-app` (hits) and `clean-app` (no hits) fixtures.
- The skill ends with an optional, Ad-labelled report footer line for Launch Audit, kept separate from the checks.
- README: skills table and usage updated; the Ad links now carry `utm_content` per product.

## 0.1.0 (2026-10-14)
- First release: `supabase-rls-review` and `stripe-webhook-review`.
