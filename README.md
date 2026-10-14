# Ship-Ready Skills

Two free, read-only review skills for Claude Code, for apps built on Next.js + Supabase + Stripe:

- **`supabase-rls-review`**: reviews `supabase/migrations/*.sql` for row level security gaps (R1–R4) and for missing or blanket Data API grants (R5, R6). From 30 Oct 2026 Supabase stops granting new `public` tables to `anon`/`authenticated`/`service_role` on existing projects, so a table with no explicit `grant` returns `42501` from the Data API ([Supabase changelog](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically)).
- **`stripe-webhook-review`**: reviews Stripe webhook route handlers for signature verification, raw-body parsing, pending/completed idempotency on `event.id` (including when reprocessing a pending event is safe), and `items.data[0]` billing periods.

The check ids and rules match the free [nextjs-supabase-stripe-security-checker](https://github.com/edtrackai/nextjs-supabase-stripe-security-checker) CLI (R1–R6, S1–S3, S6, S7). The skills are instructions only: no scripts, no network calls, and their `allowed-tools` are `Read`, `Grep` and `Glob`. Findings are prompts to review, not proof of a vulnerability.

## Install

**Claude Code plugin:**
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

## Use
Ask Claude Code something like "review my RLS and grants" or "review my Stripe webhook", or call a skill directly: `/ship-ready-skills:supabase-rls-review` and `/ship-ready-skills:stripe-webhook-review` when installed as a plugin, or `/supabase-rls-review` and `/stripe-webhook-review` when copied into `.claude/skills/`.

## Limits
- Only SQL in your migration files is reviewed. Policies or grants created in the Supabase dashboard aren't visible.
- These are review heuristics for one stack. A clean result isn't proof your app is secure.

*Ad (paid, same author):* the [AI Rules v2 pack ($19)](https://edtrackai.github.io/ai-rules?utm_source=skills&utm_medium=readme&utm_campaign=ship-ready-skills) adds rules, more skills and guardrail hooks for this stack.

## License
MIT. See [LICENSE](LICENSE).
