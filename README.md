# APIdoc

Paste a failing `curl` command; APIdoc re-runs it with a full trace and tells you **why** it
failed, what proves it, and how to fix it. When the fix is mechanical (a missing header, the
wrong method, the wrong URL after a redirect) it prints the corrected request.

```text
$ apidoc diagnose "curl -L -H 'Authorization: Bearer ...' http://127.0.0.1:8000/v1/old-me"
Cause: Your Authorization header was dropped when the redirect moved from 127.0.0.1:8000
       to localhost:8000, so the server never saw your token.
Fix:   HTTP clients (curl, httpx, browsers) strip Authorization on a redirect to a different
       host, so credentials are not leaked to it. Call the final URL directly with your token.
(auth_dropped_on_redirect, confidence 0.95, from rules)

Fixed request:
curl \
  -H 'Authorization: Bearer [REDACTED]' \
  -L \
  http://localhost:8000/v1/me
```

It is built for two audiences with one pipeline: beginners get a one-line cause and a fix;
experienced users add `-v` / `-vv` / `-vvv` for evidence, every redirect hop with timing, and
full (redacted) headers and bodies.

## How it works

```
curl command ─► parse (what curl *actually* sends) ─► re-run with a trace (every hop)
             ─► 23 deterministic rules ─► confident? ── yes ─► diagnosis
                                              │
                                              no ─► redacted context ─► LLM (Gemini)
                                                                          │
                          evidence must be quoted verbatim from the trace ◄┘
```

- **The parser reproduces curl's hidden behaviour.** `curl -d '{"a":1}'` silently sends
  `Content-Type: application/x-www-form-urlencoded` and switches to POST; APIdoc does the same
  and tells you it happened. Line continuations from bash (`\`), cmd (`^`) and PowerShell (`` ` ``)
  are understood.
- **Rules first.** 23 rules cover auth (missing, wrong scheme, expired / not-yet-valid JWT,
  missing scope, key in the query string), redirects (auth dropped across hosts, POST turned into
  GET by a 301), request shape (JSON with the wrong Content-Type, malformed JSON, validation
  errors, 405, 406) and server side (429, 5xx, 200 with an error body). Each returns evidence
  quoted from the trace and a confidence used for ranking.
- **The LLM only handles what the rules cannot.** With the default `--llm auto` it is consulted
  only when the rules are unsure (confidence below 0.85). A clean JSON `2xx` never goes to the
  LLM; a `200` that arrives as HTML or after a redirect does (a login page served as 200 OK is a
  real failure mode).
- **The LLM cannot invent evidence.** Every evidence string it returns must appear verbatim in
  the context it was given; anything else is dropped, and an answer with no grounded evidence is
  discarded. A rule finding that is proven by the trace overrules a disagreeing LLM.

## Install

Python 3.11+.

```bash
git clone < https://github.com/shravya-venkiteela/APIdoc > && cd APIdoc
python -m venv .venv
source .venv/bin/activate          # Windows: .\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Try it against the mock API

`mock_server/` is a deliberately broken API: every endpoint fails in one specific, realistic way.

```bash
uvicorn mock_server.app:app --port 8000      # or: docker compose up --build
```

In a second terminal:

```bash
apidoc diagnose "curl http://127.0.0.1:8000/v1/me"                           # no credentials
apidoc diagnose "curl -H 'Authorization: good-token' http://127.0.0.1:8000/v1/me"  # no "Bearer"
apidoc diagnose -vv "curl http://127.0.0.1:8000/v1/limited"                  # 429 + Retry-After
apidoc diagnose --allow-unsafe "curl -d '{\"name\": \"x\"}' http://127.0.0.1:8000/v1/items"
```

## Usage

```bash
apidoc diagnose "curl ..."                 # cause, fix, fixed request
apidoc diagnose -v "curl ..."              # + evidence, other possible causes, what the LLM did
apidoc diagnose -vv "curl ..."             # + every hop with status and timing
apidoc diagnose -vvv "curl ..."            # + full headers and bodies (redacted)
apidoc diagnose --json "curl ..."          # the Diagnosis as JSON
apidoc diagnose -f failing.txt             # read the command from a file
apidoc diagnose --save-trace t.json "curl ..."   # keep a redacted trace
apidoc diagnose --trace-file t.json        # re-analyse a saved trace without re-sending anything
apidoc diagnose --export fixed.sh "curl ..."     # write the fixed request (see the warning below)
apidoc convert "curl ..." --to httpx       # or --to powershell / curl
```

Logs go to stderr (`--log-json` for one JSON object per line); the diagnosis goes to stdout.

**Getting a curl command:** in Chrome or Edge DevTools, Network tab → right-click the request →
Copy → **Copy as cURL (bash)**. Use the *bash* variant even on Windows; the *cmd* variant uses
`^"` escaping that APIdoc does not parse.

**Windows PowerShell 5.1** strips inner double quotes when it passes an argument to a program,
so a JSON body inside `apidoc diagnose "curl -d '{"a": 1}' ..."` arrives mangled. Put the command
in a file and use `apidoc diagnose -f failing.txt`, or use PowerShell 7. (APIdoc recognises the
symptom, unquoted JSON keys, and says so.)

### Safety

- **Only safe methods are re-run by default.** GET, HEAD, OPTIONS and TRACE are re-sent; POST,
  PUT, PATCH and DELETE need `--allow-unsafe`, because re-running them can create, charge or
  delete things. `--trace-file` analyses a saved trace without sending anything.
- **Everything printed, logged or saved is redacted**: tokens, API keys, passwords, cookies
  (including ones the server sets), credentials in URLs and query strings, in their raw,
  URL-encoded and base64 forms. Property-based tests (Hypothesis) generate random secrets and
  check the redactor masks them and that they never reach the LLM prompt; CLI tests check the
  output and logs at every verbosity level, in text and JSON.
- **`--export` is the one exception.** The exported request has to work, so it contains your
  real credentials. Do not commit or share it.

## The LLM (optional)

APIdoc works without an LLM; only the "hard" cases need one. It uses Google Gemini
(`gemini-3.5-flash-lite` by default, override with `APIDOC_GEMINI_MODEL`), which has a free tier.

```bash
apidoc key set gemini        # hidden prompt; stored in the OS keyring, never in a file
apidoc diagnose --llm always "curl ..."   # force it;  --llm never  turns it off
```

`GEMINI_API_KEY` in the environment also works and takes precedence over the keyring.

**Privacy:** only redacted data is sent, and only when the rules are unsure. But on Google's
free tier, prompts may be used to improve Google's products. If the API you are debugging is
sensitive, use `--llm never` or a paid key.

## OAuth and stored credentials

```bash
apidoc auth login --scope "read"           # PKCE login against the mock server (opens a browser)
apidoc auth status                         # what is stored, without showing any secret
apidoc diagnose --profile mock --with-token "curl http://127.0.0.1:8000/v1/admin/users"
apidoc auth refresh                        # rotate the access token
apidoc auth logout                         # delete the profile and every secret it stored
```

- PKCE (S256) with a loopback redirect on a random port and a `state` check (RFC 7636 / 8252);
  client credentials with HTTP Basic (`--flow client-credentials`); rotating refresh tokens.
- `auth login` checks that the server answers before opening a browser.
- When a token lacks a scope, the fix names the exact command, e.g.
  `apidoc auth login --profile mock --scope "read admin"`.
- **Secrets live in the OS keyring** (Windows Credential Manager, macOS Keychain, Linux Secret
  Service); `profiles.json` only holds settings, and a test proves no secret reaches it. If no
  keyring is available, APIdoc refuses to store secrets rather than fall back to a plain file.
- **What the keyring does not do:** it keeps secrets out of files, shell history and the repo,
  and encrypted at rest. Any program running as your user can still read them.
- Presets exist for GitHub and Google, but **only the mock provider is tested**. Using a real
  provider needs an OAuth app registered with a loopback redirect URI.
- The authorization code briefly appears in the browser's address bar and history. That is
  inherent to the loopback flow; PKCE makes a captured code useless on its own.

## Evaluation

`evals/` runs 28 known-broken requests against the mock API and scores three setups. A case
counts as **diagnosed** only if the category is right *and* the explanation names the actual
cause (a keyword check).

| Cases | Rules only | LLM always | Auto (shipped) |
|---|---|---|---|
| beginner (12) | 12/12 | 12/12 | 12/12 |
| experienced (11) | 11/11 | 11/11 | 11/11 |
| hard (5) | 0/5 | 5/5 | 5/5 |

Machine-applied fixes made the request succeed in 7 of 7 cases where the rules proposed one.

**How to read this honestly:**

- The cases are self-authored, against a self-built mock API. Beginner and experienced cases
  each have a rule written for them, so 23/23 there shows the rules work as designed, not that
  they generalise.
- The 5 "hard" cases were written so that no rule matches them; they are the only part that
  measures what the LLM adds. Before any tuning it diagnosed **4 of 5**. The fifth (an SSO login
  page served as 200 OK) failed because of APIdoc's own policy, which let a "no rule matched,
  so OK" verdict overrule the LLM. That was fixed *after* seeing the case, so 5/5 is partly fit to
  this set.
- "Names the cause" is a keyword check, not a judgement of explanation quality, and each case
  uses one recorded LLM sample.
- Next: a held-out set of new hard cases, written before running anything against them.

Recorded LLM responses are committed, so the eval re-runs offline and for free:

```bash
python evals/run_eval.py                  # rules only, no key needed
python evals/run_eval.py --llm replay     # LLM columns from recordings, 0 API calls
python evals/run_eval.py --llm record     # call Gemini for cases without a recording
python evals/run_eval.py --llm replay --prune   # delete recordings no case uses any more
```

Full per-case results: [`evals/results.md`](evals/results.md).

## Limitations

- Input is a curl command (or a saved trace). Postman collections are not supported yet.
- `-F` / multipart bodies are not supported; one URL per command.
- The rules know common REST conventions (Bearer auth, `WWW-Authenticate`, FastAPI-style and
  `errors`-array validation bodies). Unusual APIs fall through to the LLM or to "unknown".
- Confidence values are ranking signals set by hand, not calibrated probabilities.

## Development

```bash
pytest -q                     # ~190 tests; starts the mock API in-process, no Docker needed
ruff check . && ruff format --check .
python evals/run_eval.py --llm replay
```

```
src/apidoc/
  curl.py        parse curl exactly as curl would send it
  runner.py      re-run with a per-hop trace (safe methods only by default)
  rules.py       the 23 deterministic rules
  diagnose.py    rules → redacted prompt → LLM → grounding → merge
  llm.py         Gemini over plain REST, a fake provider, record/replay cache
  redact.py      known-value + pattern redaction
  logs.py        logging that cannot leak (redacting filter, JSON lines)
  oauth.py       PKCE, client credentials, refresh
  profiles.py    settings in JSON, secrets in the OS keyring
  cli.py         the `apidoc` command
mock_server/     the deliberately broken API (+ a mock OAuth server)
evals/           cases, runner, recorded LLM responses, results
tests/           unit, integration and property-based tests
```