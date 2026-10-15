import { describe, expect, test } from 'claude-code/testing'

describe('supabase-grants-check mod', () => {
  test('grant all to anon in a Bash psql command is refused', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'Bash', command: 'psql "$DB" -c "grant all on public.profiles to anon;"' })
    expect(typeof r.deny).toBe('string')
  })
  test('grant insert, update to anon, authenticated in a migration Write is refused', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'Write', file_path: 'supabase/migrations/1_x.sql', content: 'create table t (id int);\nGRANT INSERT, UPDATE ON public.t TO anon, authenticated;\n' })
    expect(typeof r.deny).toBe('string')
  })
  test('Supabase MCP execute_sql with grant all to anon is refused', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'mcp__supabase__execute_sql', query: 'grant all on all tables in schema public to anon' })
    expect(typeof r.deny).toBe('string')
  })
  test('grant select to anon runs', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'Bash', command: 'psql -c "grant select on public.posts to anon;"' })
    expect(r.deny).toBeUndefined()
    expect(r.result).toBe('ran')
  })
  test('grant all to service_role and revoke from anon run', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'Write', file_path: 'supabase/migrations/2.sql', content: 'revoke all on public.t from anon, authenticated;\ngrant select, insert on public.t to authenticated;\ngrant all on public.t to service_role;\n' })
    expect(r.deny).toBeUndefined()
  })
  test('grant all to PUBLIC is refused (0.1.1)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'Bash', command: 'psql -c "GRANT ALL ON public.t TO PUBLIC;"' })
    expect(r.deny).toContain("Blocked")
  })
  test('role membership grant to anon is refused (0.1.1)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'mcp__supabase__execute_sql', query: 'create role w; grant all on t to w; grant w to anon' })
    expect(r.deny).toContain("Blocked")
  })
  test('comments between keywords are refused (0.1.1)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'Write', file_path: 'supabase/migrations/3.sql', content: 'grant/**/insert on t to/**/anon;' })
    expect(r.deny).toContain("Blocked")
  })
  test('grant references, trigger to anon is refused (0.1.1)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'Bash', command: 'psql -c "grant references, trigger on t to anon"' })
    expect(r.deny).toContain("Blocked")
  })
  test('grant execute on function to anon is refused (0.1.1)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'mcp__supabase__execute_sql', query: 'grant execute on function public.f() to anon' })
    expect(r.deny).toContain("Blocked")
  })
  test('a commented-out grant line runs (0.1.1)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'Write', file_path: 'supabase/migrations/4.sql', content: '-- grant all on t to anon\ngrant select on t to anon;' })
    expect(r.deny).toBeUndefined()
  })
  test('create role ... role anon is refused (0.1.2)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'mcp__supabase__execute_sql', query: 'create role w with role anon; grant all on t to w' })
    expect(r.deny).toContain('Blocked')
  })
  test('alter group ... add user anon is refused (0.1.2)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'Bash', command: 'psql -c "alter group w add user anon"' })
    expect(r.deny).toContain('Blocked')
  })
  test('create role ... in role authenticated runs (0.1.2)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'Bash', command: 'psql -c "create role w in role authenticated"' })
    expect(r.deny).toBeUndefined()
  })
  test('owner to anon is refused (0.1.4)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'mcp__supabase__execute_sql', query: 'alter table public.t owner to anon' })
    expect(r.deny).toContain('Blocked')
  })
  test('U&"" identifier is refused (0.1.4)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'Bash', command: 'psql -c \'grant all on t to U&"\\\\0061non"\'' })
    expect(r.deny).toContain('Blocked')
  })
  test('alter role anon bypassrls is refused (0.1.4)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'mcp__supabase__execute_sql', query: 'alter role anon bypassrls' })
    expect(r.deny).toContain('Blocked')
  })
  test('owner to postgres runs (0.1.4)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'Bash', command: 'psql -c "alter table t owner to postgres"' })
    expect(r.deny).toBeUndefined()
  })
  test('create schema ... authorization anon is refused (0.1.5)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'mcp__supabase__execute_sql', query: 'create schema s authorization anon' })
    expect(r.deny).toContain('Blocked')
  })
  test('grant create on schema public to anon is refused (0.1.5)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'mcp__supabase__execute_sql', query: 'grant create on schema public to anon' })
    expect(r.deny).toContain('Blocked')
  })
  test('grant usage on schema public to anon runs (0.1.5)', async ($, on) => {
    on('tool.call', () => ({ result: 'ran' }))
    const r = await $.tool.call({ tool: 'mcp__supabase__execute_sql', query: 'grant usage on schema public to anon' })
    expect(r.deny).toBeUndefined()
  })
  test('/grants-check explains how to run the checker', async ($, on) => {
    on('session.start', ($, e) => ({ cwd: e.cwd }))
    on('command.register', ($, e) => ({ value: { command: e.name } }))
    await $.session.start({ surface: 'terminal', isInteractive: true, cwd: '/app' })
    const { text } = await $.command.run({ command: 'grants-check', args: '' })
    expect(text).toContain('only reads catalog views and makes no changes')
  })
})
