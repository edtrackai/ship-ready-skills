# Ship-Ready Skills

Five free review skills for Claude Code (their only tools are Read, Grep and Glob) and one free guardrail hook, for apps built on Next.js + Supabase + Stripe:

- **`supabase-rls-review`**: reviews `supabase/migrations/*.sql` for row level security gaps (R1–R4) and for missing or blanket Data API grants (R5, R6). Supabase's changelog schedules a change for 30 Oct 2026 after which new `public` tables on existing projects get no automatic grants to `anon`/`authenticated`/`service_role`, so a table with no explicit `grant` returns `42501` from the Data API ([Supabase changelog](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically)). Existing tables keep their grants.
- **`supabase-grants-check`** (new): the security side of the same grants change. It flags `grant all`/write grants to `anon`, grants on tables with RLS off, policies whose role has no grant (42501), grants with no policy, `security definer` functions `anon` can execute, blanket default privileges, and a local `config.toml` that still auto-exposes new tables (G1–G8). It matches the C1–C7 checks of the free SQL checker you run in the Supabase SQL Editor. For a CI linter that replays migrations to find tables the Data API can't reach, see [supabase-grants-lint](https://github.com/guptaaman678/supabase-grants-lint) (MIT, a separate project, not ours).
- **`launch-security-check`**: a quick pre-launch pass for three critical mistakes: public tables without RLS, service-role or secret keys reaching client code (`NEXT_PUBLIC_` variables, `'use client'` files), and Stripe webhooks without `constructEvent` signature verification (L1–L3).
- **`stripe-webhook-review`**: reviews Stripe webhook route handlers for signature verification, raw-body parsing, pending/completed idempotency on `event.id` (including when reprocessing a pending event is safe), and `items.data[0]` billing periods.
- **`unthrottled-route-check`** (new): flags Next.js API routes that call OpenAI, Anthropic or the Vercel AI SDK, or create a Stripe Checkout Session, with no rate limiter in the route, in a local helper it imports (one level deep) or in `middleware.ts`/`proxy.ts` (U1, U2). It ships with an optional zero-dependency Node 20+ script, `skills/unthrottled-route-check/scripts/scan-unthrottled.mjs`, that runs the same check (8 tests over 3 fixture apps). The skill itself doesn't run the script.
- **`plugins/supabase-grants-guard`** (new, a separate Claude Code plugin, `supabase-grants-check` 0.1.5): bundles the `supabase-grants-check` skill, the SQL checker `checker/supabase-grants-check.sql` (it only reads catalog views and makes no changes) and a mod (Claude Code 2.1.287+) that refuses SQL granting `anon` more than `select` before Claude runs it. It checks Bash commands, file writes and MCP tool inputs. Pattern-based; see the limits in [its README](plugins/supabase-grants-guard/README.md).
- **`hooks/secret-egress`** (new, a Claude Code hook, not a skill): denies shell commands, URL fetches and MCP calls that would send a live Stripe/Supabase secret, a service-role key or a `.env` file off your machine. 97 tested cases; pattern-based, so rephrased commands can get past it. See [hooks/secret-egress/README.md](hooks/secret-egress/README.md).

The skills use the same check ids and fix text as the free [nextjs-supabase-stripe-security-checker](https://github.com/edtrackai/nextjs-supabase-stripe-security-checker) CLI (R1–R6, S1–S3, S6, S7); `launch-security-check` uses its own ids (L1–L3). Results can differ, because the skills are an AI-guided review, not the CLI's code. The skills are instructions; their `allowed-tools` are `Read`, `Grep` and `Glob`, so they run no scripts and make no network calls (Claude Code itself may). One skill, `unthrottled-route-check`, includes an optional Node script and its tests in its folder; you run it yourself (`node scripts/scan-unthrottled.mjs <project-dir>`), and it reads files only and makes no network calls. Findings are prompts to review, not proof of a vulnerability.

## Install

**skills CLI** (Claude Code, Cursor and other agents that read Agent Skills):
```bash
npx skills add edtrackai/ship-ready-skills
# or just one skill:
npx skills add edtrackai/ship-ready-skills --skill supabase-rls-review
# see what's in the repo without installing:
npx skills add edtrackai/ship-ready-skills --list
```
*(Tested 14 Oct 2026 with skills 1.7.2 on Node 22, which that CLI requires: both commands installed the skills into `./.agents/skills/` in an empty folder.)*

**Claude Code plugin:**

*(Validated with `claude plugin validate --strict`; install from GitHub tested 14 Oct 2026 with Claude Code 2.1.296 in a clean profile.)*
```
/plugin marketplace add edtrackai/ship-ready-skills
/plugin install ship-ready-skills@ship-ready-skills
```

**Supabase grants guard plugin** (same marketplace):
```
/plugin marketplace add edtrackai/ship-ready-skills
/plugin install supabase-grants-check@ship-ready-skills
```
*(Install from GitHub tested 15 Oct 2026 with Claude Code 2.1.300 in a clean profile. It includes the same `supabase-grants-check` skill as `ship-ready-skills`, so you only need one of the two for that skill.)*

**Or copy the skills** into your project (or `~/.claude/skills/` for every project):
```bash
git clone https://github.com/edtrackai/ship-ready-skills.git
mkdir -p .claude/skills
cp -r ship-ready-skills/skills/* .claude/skills/
```

## Skills

| Skill | What it reviews | Use when |
|---|---|---|
| `supabase-rls-review` | `supabase/migrations/*.sql`: tables without RLS, `using (true)` write policies, anon write policies, `security definer` without `search_path` (R1–R4), public tables with no explicit `grant`, blanket grants to `anon`/`authenticated` (R5, R6) | Reviewing RLS, Supabase policies or grants, a `42501` error, or database security before launch |
| `supabase-grants-check` | `supabase/migrations/*.sql` and `supabase/config.toml`: anon write grants, grants with RLS off, policy/grant mismatches, `security definer` functions anon can execute, default privileges, `auto_expose_new_tables` (G1–G8) | A `42501` error, the grants change Supabase's changelog schedules for 30 Oct (date may move), or checking whether a GRANT fix is safe |
| `launch-security-check` | Migrations, client components and webhook routes: tables without RLS, service-role/secret keys in `NEXT_PUBLIC_` variables or `'use client'` files, webhook handlers with no `constructEvent` (L1–L3) | A quick security check before launch or go-live |
| `stripe-webhook-review` | Stripe webhook route handlers: signature verification, raw body, idempotency on `event.id` with pending/completed status, `items.data[0]` billing periods (S1–S3, S6, S7) | Reviewing a Stripe webhook, idempotency, duplicate events, or payments before launch |
| `unthrottled-route-check` | API route handlers, `pages/api`, local helpers they import, `middleware.ts`/`proxy.ts`: AI calls or `checkout.sessions.create` with no rate limiter (U1, U2) | Rate limiting, AI cost per user, surprise API bills, checkout refresh loops, abuse before launch |

## Use
Ask Claude Code something like "review my RLS and grants" or "review my Stripe webhook". You can also call a skill by name: `/ship-ready-skills:supabase-rls-review` or `/ship-ready-skills:stripe-webhook-review` as a plugin, `/ship-ready-skills:launch-security-check`, or `/supabase-rls-review`, `/stripe-webhook-review` and `/launch-security-check` when copied (following Claude Code's naming; not yet tested live).

Example prompt:
```
Review my Supabase migrations for RLS and grants.
```
The skill asks for a report in this shape: one summary line (files read, findings by severity), then a table of severity, check id, file:line, what it saw and the fix, then anything it couldn't verify (for example, policies created in the dashboard).

## Limits
- Only SQL in your migration files is reviewed. Policies or grants created in the Supabase dashboard aren't visible.
- These are review heuristics for one stack. A clean result isn't proof your app is secure.

*Ad (paid, from the same author), if you're fixing grants:* [AI Rules v2](https://edtrackai.github.io/ai-rules?utm_source=skills&utm_medium=readme&utm_campaign=ship-ready-skills&utm_content=grants-check-ai-rules) ($19; UK buyers pay $22.80 incl. VAT) gives Claude Code and Cursor stack rules that steer agents to add RLS, policies and explicit grants together, and [Launch Audit](https://edtrackai.github.io/launch-audit?utm_source=skills&utm_medium=readme&utm_campaign=ship-ready-skills&utm_content=grants-check-launch-audit) ($12; UK buyers pay $14.40 incl. VAT) checks the whole app before launch.

*Ad (paid, from the same author):* the [AI Rules v2 pack](https://edtrackai.github.io/ai-rules?utm_source=skills&utm_medium=readme&utm_campaign=ship-ready-skills&utm_content=ai-rules) ($19; UK buyers pay $22.80 incl. VAT) adds rules, more skills and guardrail hooks for this stack.

*Ad (paid, from the same author):* [Launch Audit](https://edtrackai.github.io/launch-audit?utm_source=skills&utm_medium=readme&utm_campaign=ship-ready-skills&utm_content=launch-audit) ($12; UK buyers pay $14.40 incl. VAT) runs 28 automated checks plus an auditor agent with no Edit or Write tools, and gives a ready / not-ready report with a fix plan.

*Claude Code, Next.js, Supabase and Stripe are trademarks of their respective owners. This project isn't affiliated with or endorsed by them.*

Made by Stack & Ship: [edtrackai.github.io](https://edtrackai.github.io/?utm_source=github&utm_medium=readme&utm_campaign=ship-ready-skills)

## Related free tools

- [Next.js Supabase Stripe Security Checker](https://github.com/edtrackai/nextjs-supabase-stripe-security-checker): free CLI and GitHub Action, 24 static checks for keys, auth, RLS and Stripe webhooks.
- [Ship-Ready AI Rules (free sample)](https://github.com/edtrackai/ship-ready-ai-rules-free-sample): free Cursor/Claude rules that stop AI agents shipping these mistakes in Next.js + Supabase + Stripe.

## License
MIT. See [LICENSE](LICENSE).
