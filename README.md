# autoNod

**Frictionless-but-safe auto-approval for Claude Code.**

autoNod stops you from babysitting permission prompts on routine frontend work. It auto-approves safe file edits inside your project, while hard-blocking your secrets, backend paths, and network egress — in *every* permission mode, including `--dangerously-skip-permissions`.

Think of it as the convenience of "skip permissions" with a floor under it.

---

## What it actually does (and does not do)

**It controls what _Claude_ does through its own tools.** Specifically:

- ✅ **Auto-approves** edits/writes to safe frontend files inside your project (`.tsx`, `.jsx`, `.ts`, `.js`, `.css`, `.html`, etc. under `src/`, `app/`, `components/`, …).
- ✅ **Auto-approves** a curated allowlist of harmless bash (`npm run dev/build/lint/test`, `tsc`, `eslint`, `prettier`, `git status/diff/log`).
- ⛔ **Denies** any read/edit/write of `.env*`, keys, credentials, and files under `server/` / `backend/` (configurable).
- ⛔ **Denies** writing secret-looking content (private keys, tokens, DB connection strings) into any file.
- ⛔ **Denies** Claude's own network tools (`WebFetch`, `WebSearch`) so it can't send anything out.
- ⛔ **Denies** bash that dumps env vars or reaches the network (`curl`, `wget`, `ssh`, `scp`, `printenv`, anything touching `.env`).
- ⛔ **Denies** anything referencing *your* backend hosts once you list them in config.
- 🟡 **Falls through to a normal prompt** for anything it doesn't recognize — it never "fails open."

Deny always beats allow, and because these run as a `PreToolUse` hook, the denies hold even under `bypassPermissions` / `--dangerously-skip-permissions`.

### ⚠️ Honest limits — please read

autoNod is **not** a firewall, **not** server security, and **cannot** stop an external attacker or a real network breach. "Secrets can't be hacked from the network" is a different security domain that lives in your server config, secret management, and deployment — not in a Claude Code plugin. autoNod's job is narrow: keep *Claude* from reading your secrets or shipping them out through its own tools. Treat it as one useful layer, not a guarantee.

**Surface limitation:** As of now, hooks fire everywhere Claude Code runs as the CLI — any terminal, including VS Code's *integrated terminal*. They do **not** currently fire in the VS Code extension's *graphical panel* (a known, open Claude Code issue). Until that lands, run `claude` in a terminal to get autoNod's protection. This is a platform limitation, not something a plugin can work around.

---

## Install

```bash
# add the marketplace (a marketplace is just a git repo)
/plugin marketplace add YOUR_GITHUB_USERNAME/autonod

# install the plugin
/plugin install autonod@autonod-marketplace
```

Then run Claude Code from a terminal. Verify the hook is active by asking Claude to read `.env` — it should be denied.

---

## Configure

Edit `hooks/autonod.config.json`. Key fields:

| Field | What it does |
| --- | --- |
| `allowedDirs` | Directories whose files get auto-approved. |
| `allowedRootFiles` | Root-level config files that are safe to edit. |
| `allowedExtensions` | File types eligible for auto-approval. |
| `backendDomains` | **Add your backend hosts here.** Any edit writing one, or bash referencing one, is denied. Empty by default. |
| `extraDenyPaths` | Path substrings that are always off-limits. |
| `autoApproveSafeBash` | Toggle the safe-bash allowlist. |
| `denyAllNetworkTools` | Toggle blocking of Claude's `WebFetch`/`WebSearch`. |

**Tip:** the safest way to protect your real backend is to fill in `backendDomains` with your actual hosts. Until you do, autoNod can only guess with generic secret patterns.

---

## How a decision is made

```
tool call ──▶ DENY checks (secrets / backend / network)  ──▶ deny (final)
                     │ no match
                     ▼
              ALLOW checks (safe frontend file / safe bash) ──▶ allow
                     │ no match
                     ▼
              fall through to normal Claude Code prompt
```

---

## Security & contributing

autoNod ships a hook that runs on other people's machines, so trust matters:

- The repo is public **so you can read exactly what the script does** before installing. That transparency is the point.
- Only the maintainer can change what ships. Forks and pull requests can't alter this repo unless a maintainer reviews and merges them.
- Every PR is reviewed line-by-line before merge. Please keep dependencies at zero.

## License

MIT
