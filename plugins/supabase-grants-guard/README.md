# supabase-grants-check (Claude Code plugin, free, MIT). DRAFT 0.1.5, not published

For the Supabase Data API grants change that Supabase's changelog schedules for 30 Oct 2026 (date may move; see supabase/cli PR #6337). The plugin bundles three things:

- **Skill `supabase-grants-check`** (tools: Read, Grep, Glob): reviews `supabase/migrations/*.sql` and `supabase/config.toml` (G1–G8).
- **SQL checker** `checker/supabase-grants-check.sql`: paste it into the Supabase SQL Editor and run it. It only reads catalog views and makes no changes (C1–C7).
- **Mod** (Claude Code 2.1.287+): refuses SQL that grants `anon` more than `select`, meaning `grant all`, `insert`, `update`, `delete` or `truncate ... to anon`. It checks Bash commands, file writes and MCP tool inputs before they run. `/grants-check` shows how to run the skill and the checker.

## Install
From a local copy:
```bash
claude plugin marketplace add /path/to/supabase-grants-check
claude plugin install supabase-grants-check@supabase-grants-check
```
(A GitHub install line will be added once the repo is public.)

## Tested
- `claude plugin validate --strict`: passes.
- `claude plugin test`: 6/6.
- `node tests/unit.mjs`: 20/20, including 1 MB timing inputs.
- Local marketplace add and install: works (Claude Code 2.1.300).
- The checker has its own Postgres test suite in the source repo.

Not tested: a live interactive session.

## Limits
- Pattern-based. SQL built in variables or split across strings (for example inside a DO block) can get past the mod.
- It blocks write-level grants (ALL, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, EXECUTE, CREATE, MAINTAIN, TEMPORARY/TEMP) to `anon` or `PUBLIC`, `CREATE` (for example on schema public) to `authenticated` as well (`USAGE` is allowed), any `GRANT <role> TO anon/authenticated`, and statements that make anon or authenticated a member of a role (`CREATE ROLE ... [WITH] ROLE|USER|ADMIN anon`, `ALTER GROUP ... ADD USER anon`). It does not trace write grants made to a role that anon or authenticated joined earlier.
- It also blocks `grant execute on function ... to anon`. If you mean to expose an RPC function to signed-out users, run that grant yourself.
- Comments are removed before matching, so a commented-out grant is ignored.
- It also blocks ownership transfers (`ALTER TABLE|SCHEMA|FUNCTION|VIEW|SEQUENCE ... OWNER TO anon/authenticated/public`, `REASSIGN OWNED BY ... TO anon/authenticated/public`, `CREATE SCHEMA ... AUTHORIZATION anon/authenticated/public`, `CREATE DATABASE ... OWNER anon/authenticated/public`) and `ALTER ROLE|USER anon/authenticated ... BYPASSRLS|SUPERUSER|CREATEROLE|CREATEDB|REPLICATION|LOGIN`.
- Unicode-escaped identifiers (`U&"\0061non"`) are not decoded. Instead, any `U&"` (including the backslash-escaped `U&\"` form inside `psql -c "..."`) in a grant, create, alter, reassign or owner statement is refused, even when it names a harmless role.
- Dynamic SQL (`EXECUTE format(...)`, DO blocks, role names built from strings or variables) can't be fully caught by a text check. Some cases are refused because the role name happens to appear literally; others get through.
- Policies are out of scope (`create policy ... to anon using (true)` runs). The separate checker and skill look at policies; this plugin doesn't.
- It only sees SQL in the command, file write or MCP input itself. `psql -f file.sql` or `supabase db push` of migration files that already exist (not written in this session) are not inspected. Run the checker or the skill on them.
- Grants merely mentioned inside strings or docs commands can be refused, for example `echo "never grant all on t to anon" >> docs/README.md` or a query containing `like 'grant all on x to anon'`.
- The mod doesn't stop grants made outside Claude Code (for example in the dashboard).
- The skill only sees migration files.
- A clean result is not proof the app is secure.

*Ad (paid, from the same author):* [Ship-Ready AI Rules](https://luxurydrive0.gumroad.com/l/ffjsf?utm_source=plugin&utm_medium=readme&utm_campaign=supabase-grants-check&utm_content=ai-rules) ($19; UK buyers pay $22.80 incl. VAT) gives Claude Code and Cursor stack rules that steer agents to add RLS, policies and explicit grants together. [Launch Audit](https://luxurydrive0.gumroad.com/l/launch-audit?utm_source=plugin&utm_medium=readme&utm_campaign=supabase-grants-check&utm_content=launch-audit) ($12; UK buyers pay $14.40 incl. VAT) is a pre-launch check of your Next.js + Supabase + Stripe app.

*Supabase and Claude Code are trademarks of their respective owners. This project isn't affiliated with or endorsed by them.*
