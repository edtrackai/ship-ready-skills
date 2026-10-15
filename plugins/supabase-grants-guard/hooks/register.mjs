// Free Supabase grants guard, as a Claude Code mod (Claude Code 2.1.287+). MIT.
// Refuses SQL that grants anon (or PUBLIC, which every role inherits) more than SELECT: ALL, INSERT, UPDATE, DELETE,
// TRUNCATE, REFERENCES, TRIGGER or EXECUTE, and role-membership grants (GRANT <role> TO anon/authenticated),
// in Bash commands, file writes and MCP tool inputs. Comments are removed first. Linear-time: one pass to strip
// comments, then split into statements and check each one with indexOf/split (no backtracking regex).
const RESERVED = new Set(['tool', 'tool_use_id', 'consent', 'agentId'])
const MAX = 1 << 20
const WRITE_PRIVS = ['all', 'insert', 'update', 'delete', 'truncate', 'references', 'trigger', 'execute', 'create', 'maintain', 'temporary', 'temp']
// CREATE (e.g. on schema public) is refused for authenticated too; the other privileges only for anon/PUBLIC.
const CREATE_TARGETS = new Set(['anon', 'authenticated', 'public'])
const ANON_LIKE = new Set(['anon', 'public'])
const MEMBER_TARGETS = new Set(['anon', 'authenticated'])

/** Replace block comments and -- line comments with a space. Single pass, O(n). */
export function stripComments(t) {
  const parts = []
  const n = t.length
  let i = 0, nb = t.indexOf('/*'), nl = t.indexOf('--')
  while (i < n) {
    if (nb >= 0 && nb < i) nb = t.indexOf('/*', i) // cached positions only move forward: O(n) overall
    if (nl >= 0 && nl < i) nl = t.indexOf('--', i)
    const b = nb < 0 ? n : nb, l = nl < 0 ? n : nl
    const nx = Math.min(b, l)
    if (nx >= n) { parts.push(t.slice(i)); break }
    parts.push(t.slice(i, nx), ' ')
    if (nx === b) { const e = t.indexOf('*/', nx + 2); i = e < 0 ? n : e + 2 }
    else { const e = t.indexOf('\n', nx + 2); i = e < 0 ? n : e }
  }
  return parts.join('')
}

const ROLE_OPT_END = new Set(['in', 'role', 'user', 'admin', 'with', 'password', 'login', 'nologin', 'inherit', 'noinherit', 'superuser', 'nosuperuser', 'createdb', 'nocreatedb', 'createrole', 'nocreaterole', 'replication', 'noreplication', 'bypassrls', 'nobypassrls', 'connection', 'valid', 'sysid', 'encrypted', 'unencrypted'])

/** CREATE ROLE/GROUP/USER ... [WITH] ROLE|USER|ADMIN anon, and ALTER GROUP ... ADD USER anon, make anon (or authenticated)
 * a member of the new role, so it inherits whatever that role is granted later. IN ROLE anon is the other direction (harmless). */
export function findMembershipStatement(raw) {
  if (!raw.includes('anon') && !raw.includes('authenticated')) return null
  if (!raw.includes('create') && !raw.includes('alter')) return null
  const tok = raw.split(/[\s,"'`\\()]+/).filter(Boolean)
  for (let i = 0; i + 2 < tok.length; i++) {
    const verb = tok[i], kind = tok[i + 1]
    if (verb === 'create' && (kind === 'role' || kind === 'group' || kind === 'user')) {
      // tok[i+2] is the new role's name; scan its options until the statement ends.
      let inList = false
      for (let j = i + 3; j < tok.length; j++) {
        const t = tok[j]
        if (t === 'role' || t === 'user' || t === 'admin') { inList = tok[j - 1] !== 'in'; continue }
        if (ROLE_OPT_END.has(t)) { inList = false; continue }
        if (inList && MEMBER_TARGETS.has(t)) return tok.slice(i, j + 1).join(' ').slice(0, 200)
      }
      return null
    }
    if (verb === 'alter' && kind === 'group') {
      for (let j = i + 3; j + 1 < tok.length; j++)
        if (tok[j] === 'add' && tok[j + 1] === 'user') {
          for (let k = j + 2; k < tok.length; k++) if (MEMBER_TARGETS.has(tok[k])) return tok.slice(i, k + 1).join(' ').slice(0, 200)
          return null
        }
      return null
    }
  }
  return null
}

const STMT_WORDS = ['grant', 'create', 'alter', 'reassign', 'owner']
const ROLE_ATTRS = new Set(['bypassrls', 'superuser', 'createrole', 'createdb', 'replication', 'login'])
const OWNER_TARGETS = new Set(['anon', 'authenticated', 'public'])

/** Unicode-escaped identifiers (U&"\0061non") are not decoded: any U&" in a grant, role or owner statement is refused.
 *  OWNER TO / REASSIGN OWNED ... TO anon/authenticated/public, and ALTER ROLE|USER anon/authenticated with
 *  BYPASSRLS/SUPERUSER/CREATEROLE/CREATEDB/REPLICATION, are refused. One token pass per statement: O(n). */
export function findOwnerOrRoleAttr(raw) {
  const flat = raw.replace(/[\s\\]+/g, '') // backslashes too: psql -c "... U&\"\\0061non\""
  if (flat.includes('u&"') && STMT_WORDS.some((w) => raw.includes(w))) return raw.trim().replace(/\s+/g, ' ').slice(0, 200)
  if (!raw.includes('owner') && !raw.includes('owned') && !raw.includes('alter') && !raw.includes('authorization')) return null
  const tok = raw.split(/[\s,"'`\\()]+/).filter(Boolean)
  for (let i = 0; i < tok.length; i++) {
    const t = tok[i]
    if (t === 'owner' && tok[i + 1] === 'to' && OWNER_TARGETS.has(tok[i + 2])) return tok.slice(Math.max(0, i - 4), i + 3).join(' ')
    if (t === 'create' && tok[i + 1] === 'schema') {
      // CREATE SCHEMA [IF NOT EXISTS] [name] AUTHORIZATION role makes role the owner, like ALTER SCHEMA ... OWNER TO.
      for (let j = i + 2; j + 1 < tok.length; j++) if (tok[j] === 'authorization') return OWNER_TARGETS.has(tok[j + 1]) ? tok.slice(i, j + 2).join(' ') : null
      return null
    }
    if (t === 'create' && tok[i + 1] === 'database') {
      // CREATE DATABASE d [WITH] OWNER [=] role
      for (let j = i + 2; j < tok.length; j++) if (tok[j].startsWith('owner=')) return OWNER_TARGETS.has(tok[j].slice(6) || tok[j + 1]) ? tok.slice(i, j + 2).join(' ') : null
      else if (tok[j] === 'owner') { const k = tok[j + 1] === '=' ? j + 2 : j + 1; return OWNER_TARGETS.has(tok[k]) || OWNER_TARGETS.has((tok[j + 1] ?? '').replace(/^=/, '')) ? tok.slice(i, k + 1).join(' ') : null }
      return null
    }
    if (t === 'reassign' && tok[i + 1] === 'owned') {
      for (let j = i + 2; j + 1 < tok.length; j++) if (tok[j] === 'to') return OWNER_TARGETS.has(tok[j + 1]) ? tok.slice(i, j + 2).join(' ') : null
      return null
    }
    if (t === 'alter' && (tok[i + 1] === 'role' || tok[i + 1] === 'user') && MEMBER_TARGETS.has(tok[i + 2])) {
      for (let j = i + 3; j < tok.length; j++) if (ROLE_ATTRS.has(tok[j])) return tok.slice(i, j + 1).join(' ').slice(0, 200)
      return null
    }
  }
  return null
}

/** Returns the offending statement (trimmed) or null. */
export function findAnonWriteGrant(text) {
  if (typeof text !== 'string' || text.length === 0) return null
  if (text.length > MAX) text = text.slice(0, MAX)
  let lower = text.toLowerCase()
  if (!lower.includes('grant') && !lower.includes('role') && !lower.includes('group') && !lower.includes('user') && !lower.includes('owner') && !lower.includes('owned') && !lower.includes('u&') && !lower.includes('authorization')) return null
  if (lower.includes('/*') || lower.includes('--')) lower = stripComments(lower)
  for (const raw of lower.split(';')) {
    const m = findMembershipStatement(raw) ?? findOwnerOrRoleAttr(raw)
    if (m) return m
    if (!raw.includes('grant')) continue
    if (!raw.includes('anon') && !raw.includes('public') && !raw.includes('authenticated')) continue
    const norm = raw.replace(/\s+/g, ' ')
    const g = norm.indexOf('grant ')
    if (g < 0) continue
    const stmt = norm.slice(g)
    const to = stmt.lastIndexOf(' to ')
    if (to < 0) continue
    // Quotes, backticks and backslashes are dropped so a shell-quoted statement (psql -c "... to anon") and "anon" both match.
    const roles = stmt.slice(to + 4).split(/[\s,"'`\\()]+/).filter(Boolean)
    const on = stmt.indexOf(' on ')
    if (on < 0 || on > to) {
      // Role membership: GRANT <role>[, ...] TO anon/authenticated gives them every privilege that role has.
      if (roles.some((r) => MEMBER_TARGETS.has(r))) return stmt.trim().slice(0, 200)
      continue
    }
    const privs = stmt.slice(6, on).split(/[\s,()]+/).filter(Boolean)
    if (roles.some((r) => ANON_LIKE.has(r)) && privs.some((p) => WRITE_PRIVS.includes(p))) return stmt.trim().slice(0, 200)
    if (roles.some((r) => CREATE_TARGETS.has(r)) && privs.includes('create')) return stmt.trim().slice(0, 200)
  }
  return null
}

function textOf(e) {
  const parts = []
  for (const k of Object.keys(e ?? {})) {
    if (RESERVED.has(k)) continue
    const v = e[k]
    parts.push(typeof v === 'string' ? v : JSON.stringify(v ?? ''))
  }
  return parts.join('\n')
}

export function decide(e) {
  const hit = findAnonWriteGrant(textOf(e))
  if (!hit) return null
  return 'Blocked: this SQL grants the anon role (directly, through PUBLIC, or through role membership) more than select (' + hit + '). Signed-out visitors rarely need writes, and with RLS off this opens the table to anyone with the anon key. Safe order: enable RLS, add policies, then grant the minimum (usually select for anon, the needed commands for authenticated).'
}

export function register(on) {
  on('session.start', async ($, e, next) => {
    await $.command.register({ name: 'grants-check', description: 'How to run the Supabase grants checker and skill' })
    return next(e)
  })

  on('tool.call', async ($, e, next) => {
    const reason = decide(e)
    if (reason) return { deny: reason }
    return next(e)
  })

  on('command.run', { command: 'grants-check' }, async () => ({
    text: [
      'Supabase grants check (free, MIT):',
      '1. Migrations: ask "check my Supabase grants" to run the supabase-grants-check skill (G1-G8).',
      "2. Live database: open this plugin's checker/supabase-grants-check.sql, paste it into the Supabase SQL Editor and run it. It only reads catalog views and makes no changes.",
      'Safe fix order: enable RLS, add policies, then grant the minimum. Never grant all to anon.',
      'A clean result is not proof the app is secure.',
    ].join('\n'),
  }))
}
