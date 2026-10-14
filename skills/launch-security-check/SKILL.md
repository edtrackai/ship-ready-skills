---
name: launch-security-check
description: Quick pre-launch security check for Next.js + Supabase + Stripe apps. Finds public tables without row level security, service-role or secret keys reaching client code (NEXT_PUBLIC_ variables, 'use client' files), and Stripe webhook handlers without constructEvent signature verification. Use when the user asks for a launch, ship or go-live security check, or a quick security pass on a Supabase/Stripe app.
allowed-tools: Read Grep Glob
---

# launch-security-check

Read-only review. Don't edit files unless the user asks for the fixes afterwards. Every grep hit is a lead: open the file and confirm it before you report it.

## L1: Public tables without RLS (critical)
1. Grep `supabase/migrations/` (case-insensitive) for `create table (if not exists )?(public\.)?"?([a-z_0-9]+)` and list the table names.
2. Grep the same folder for `alter table (only )?(public\.)?"?([a-z_0-9]+)"? enable row level security`.
3. A table from step 1 with no match in step 2 is a finding. Also grep for `disable row level security`: any hit is a finding.
Fix: `alter table public.<t> enable row level security;` plus policies for the access the app needs. For the full RLS and grants review (R1–R6), use `supabase-rls-review`.

## L2: Service-role or secret keys reaching client code (critical)
1. Grep app code (not `*.md`) for `NEXT_PUBLIC_[A-Z0-9_]*(SERVICE_ROLE|SECRET)`. `NEXT_PUBLIC_` values are bundled into the browser, so any hit is a finding.
2. Grep for files whose first line is `'use client'` / `"use client"` (pattern `^['"]use client['"]`). In those files, grep for `service_role|SERVICE_ROLE_KEY|supabase/admin|createAdminClient|supabaseAdmin|STRIPE_SECRET_KEY`. Any hit is a finding.
Fix: use the service-role key and the Stripe secret key only in server code (route handlers, server actions, `server-only` modules), and never with a `NEXT_PUBLIC_` prefix. Rotate any key that was exposed.

## L3: Stripe webhooks without signature verification (critical)
1. Glob `**/webhook*/**/route.{ts,js}` and `pages/api/**/webhook*.{ts,js}`. Keep the files that match `stripe-signature|stripe\.webhooks|event\.type|checkout\.session\.completed`.
2. Any of those files that has no match for `constructEvent(Async)?\(` is a finding. Read it: it trusts an unsigned request body.
Fix: `const body = await request.text()`, then `stripe.webhooks.constructEvent(body, signature, process.env.STRIPE_WEBHOOK_SECRET)`, and return 400 on failure. For idempotency and the raw body (S2, S3, S6, S7), use `stripe-webhook-review`.

## Report
One summary line (files read, findings by severity), then a table of severity, check (L1–L3), file:line, what you saw and the fix, then anything you couldn't verify (for example, tables or policies created in the Supabase dashboard, or keys set only in hosting env vars). A clean result is not proof the app is secure.
