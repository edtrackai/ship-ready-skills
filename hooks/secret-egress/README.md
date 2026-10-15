# secret-egress: a free, pattern-based Claude Code hook for secret leaks

A pattern-based PreToolUse hook for Claude Code, tested on 77 cases. Before the agent runs a shell command,
fetches a URL or calls an MCP tool, it checks the call against these patterns:

- a literal live Stripe key (`sk_live_`, `rk_live_`), webhook secret (`whsec_`), Supabase secret key (`sb_secret_`),
  GitHub token (`ghp_` and similar, `github_pat_`) or AWS access key id (`AKIA`/`ASIA`);
- a Supabase service-role JWT (it decodes the token; anon keys pass);
- a `.env` file (any path, such as `@./.env`) named in a command that uses the network (`curl -F file=@.env`,
  `nc ... < .env`, `node -e "fetch(...readFileSync('.env'))"`), or a `.env` file piped into another command;
- a secret variable name (`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `SUPABASE_SERVICE_ROLE_KEY`, `SUPABASE_SECRET_KEY`,
  `AWS_SECRET_ACCESS_KEY`, `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`; with or without `$`, including Python
  `os.environ[...]`) in a command that uses the network. Calls with curl, wget or httpie are exempt only when all URLs and
  hosts in the command are `api.stripe.com` or a `*.supabase.co` project, there is no `#` comment, and no option that
  can redirect or hide the target (such as `-K`/`--config`, `--resolve`, `--connect-to`, `-x`/`--proxy`, wget `-e`);
- in a command that uses the network: `env`, `env -0`, `printenv`, `set`, `export -p` or `declare -x` piped into another
  command, or `$(printenv ...)`, `process.env)` or `/proc/*/environ`;
- a curl/wget call to api.stripe.com or `*.supabase.co` that sets a proxy or curl/wget config variable in the command
  (`*PROXY*=`, `*_proxy=`, `CURL_HOME=`, `CURLRC=`, `WGETRC=`, `CURLOPT*=`, any case) or CA-trust variable
  (`SSL_CERT*=`, `*CA_BUNDLE*=`, `*CA_CERT*=`), or uses any `--proxy*`/`--socks*` option, `--proxytunnel` or a short-option
  cluster containing `p`;
- any command or tool input over 64 K characters (denied as too large to check).

When a call matches, the hook denies it and tells Claude why. Test-mode keys (`sk_test_`) pass. Calls that
don't match a pattern go through, so a rephrased, encoded or split command can get past it.

## Install
1. Copy `egress-core.mjs` and `secret-egress.mjs` into your repo's `.claude/hooks/`.
2. Merge `settings.snippet.json` into `.claude/settings.json`.
Requires Node 18+, no dependencies, and Claude Code 2.1.295+ for `"onFailure": "block"`; on older versions a hook that crashes or times out lets the call through.

## Tested
`node tests/run.mjs` runs the real hook script with Claude Code's documented hook input and checks the output:
97 cases (57 that must be denied, 27 that must pass, 8 for WebFetch/MCP inputs, 2 fail-closed cases where invalid
input and no input before the watchdog both exit 2, and 3 timing cases: 1 MB inputs are denied and a ~60 KB
worst-case command is checked, each in under 1s).
Not tested: a live Claude Code session.

## Limits
Pattern-based. A rephrased, encoded or split command can get past it, for example a key passed through base64,
a key or URL split across strings or variables, or a proxy set earlier in the session rather than in the command.
A curl/wget config file written first (for example a `proxy` line in `~/.curlrc`, `~/.config/curlrc` or `~/.wgetrc`)
can reroute a later call to an official host, and a `~/.netrc` entry can change which credentials it sends; the hook
does not check config files. It does not check the agent reading
secrets (pair it with a `Read(./.env)` deny rule) and does not inspect what an MCP server does.
A clean result is not proof the app is secure.

*Ad (paid, from the same author):* the [Stack & Ship Guardrails Pack](https://luxurydrive0.gumroad.com/l/tyziji?utm_source=github&utm_medium=readme&utm_campaign=ship-ready-skills-secret-egress) ($24; UK buyers pay $28.80 incl. VAT) adds the same pattern checks for Cursor and git pre-commit/pre-push, plus permission presets and fix guides.
