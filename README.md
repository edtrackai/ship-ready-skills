# Ship-Ready Skills

Two free, read-only review skills for Claude Code, for apps built on Next.js + Supabase + Stripe:

- **`supabase-rls-review`**: reviews `supabase/migrations/*.sql` for row level security gaps (R1–R4) and for missing or blanket Data API grants (R5, R6). Supabase's changelog schedules a change for 30 Oct 2026 after which new `public` tables on existing projects get no automatic grants to `anon`/`authenticated`/`service_role`, so a table with no explicit `grant` returns `42501` from the Data API ([Supabase changelog](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically)). Existing tables keep their grants.
- **`stripe-webhook-review`**: reviews Stripe webhook route handlers for signature verification, raw-body parsing, pending/completed idempotency on `event.id` (including when reprocessing a pending event is safe), and `items.data[0]` billing periods.

The skills use the same check ids and fix text as the free [nextjs-supabase-stripe-security-checker](https://github.com/edtrackai/nextjs-supabase-stripe-security-checker) CLI (R1–R6, S1–S3, S6, S7); results can differ, because the skills are an AI-guided review, not the CLI's code. The skills are instructions only: no scripts, and the skills make no network calls (Claude Code itself may), and their `allowed-tools` are `Read`, `Grep` and `Glob`. Findings are prompts to review, not proof of a vulnerability.

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
| `stripe-webhook-review` | Stripe webhook route handlers: signature verification, raw body, idempotency on `event.id` with pending/completed status, `items.data[0]` billing periods (S1–S3, S6, S7) | Reviewing a Stripe webhook, idempotency, duplicate events, or payments before launch |

## Use
Ask Claude Code something like "review my RLS and grants" or "review my Stripe webhook". You can also call a skill by name: `/ship-ready-skills:supabase-rls-review` or `/ship-ready-skills:stripe-webhook-review` as a plugin, or `/supabase-rls-review` and `/stripe-webhook-review` when copied (following Claude Code's naming; not yet tested live).

Example prompt:
```
Review my Supabase migrations for RLS and grants.
```
The skill asks for a report in this shape: one summary line (files read, findings by severity), then a table of severity, check id, file:line, what it saw and the fix, then anything it couldn't verify (for example, policies created in the dashboard).

## Limits
- Only SQL in your migration files is reviewed. Policies or grants created in the Supabase dashboard aren't visible.
- These are review heuristics for one stack. A clean result isn't proof your app is secure.

*Ad (paid, from the same author):* the [AI Rules v2 pack](https://edtrackai.github.io/ai-rules?utm_source=skills&utm_medium=readme&utm_campaign=ship-ready-skills) ($19; UK buyers pay $22.80 incl. VAT) adds rules, more skills and guardrail hooks for this stack.

*Claude Code, Next.js, Supabase and Stripe are trademarks of their respective owners. This project isn't affiliated with or endorsed by them.*

Made by Stack & Ship: [edtrackai.github.io](https://edtrackai.github.io/?utm_source=github&utm_medium=readme&utm_campaign=ship-ready-skills)

## Related free tools

- [Next.js Supabase Stripe Security Checker](https://github.com/edtrackai/nextjs-supabase-stripe-security-checker): free CLI and GitHub Action, 24 static checks for keys, auth, RLS and Stripe webhooks.
- [Ship-Ready AI Rules (free sample)](https://github.com/edtrackai/ship-ready-ai-rules-free-sample): free Cursor/Claude rules that stop AI agents shipping these mistakes in Next.js + Supabase + Stripe.

## License
MIT. See [LICENSE](LICENSE).
