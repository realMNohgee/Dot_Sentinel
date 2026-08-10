# Dot_Sentinel 🔍

**.env security scanner.** Detect secrets, missing vars, weak values. Zero dependencies, pure Python stdlib.

> Part of the Hermtica security suite — CI/CD pipelines, compliance audits, pre-commit hooks.

## One tool, many domains

| Domain | What Dot_Sentinel does for you |
|---|---|
| 🔒 **DevSecOps** | Scan `.env` files in CI/CD for leaked secrets before deployment |
| 📋 **Compliance** | Audit entire repositories for `.env*` files and `.gitignore` coverage |
| 🧹 **Onboarding** | Generate clean templates from sample `.env` files for new team members |
| 🕵️ **Security Audit** | Detect 15+ secret types (AWS, Stripe, GitHub, JWT, Slack, etc.) with regex |
| 🤖 **Agentic AI** | JSON output for AI agents to programmatically validate environment configs |
| ⚡ **Pre-commit** | Compare `.env` files across branches to catch accidental secret changes |

## Install

```bash
git clone git@github.com:realMNohgee/Dot_Sentinel.git
cd Dot_Sentinel
python3 dot_sentinel.py --help
```

## Quick start

```bash
# Scan a .env file for secrets
python3 dot_sentinel.py scan .env

# Scan with high-entropy detection (flags strings >4.5 bits/char)
python3 dot_sentinel.py scan .env --high-entropy

# Compare two .env files
python3 dot_sentinel.py compare .env .env.example

# Create a template from a sample
python3 dot_sentinel.py template .env

# Audit an entire project directory
python3 dot_sentinel.py audit ./my-project

# Mask sensitive values for sharing
python3 dot_sentinel.py mask .env

# JSON output for pipelines / AI agents
python3 dot_sentinel.py scan .env --format json
```

## Subcommands

| Command | Description |
|---|---|
| `scan` | Scan `.env` file for secrets using built-in + custom regex patterns |
| `compare` | Compare two `.env` files — show added, removed, and changed keys |
| `template` | Extract keys from a sample `.env`, output empty-value template |
| `audit` | Recursively find `.env*` files, check for secrets and `.gitignore` coverage |
| `mask` | Print `.env` file with all values replaced by `***` |

## Built-in Secret Pattern Detection

Detects 15+ secret types out of the box:

- AWS Access Keys (`AKIA*`)
- Stripe Live/Test keys (`sk_live_*`, `pk_live_*`)
- GitHub tokens (`ghp_*`, `github_pat_*`)
- Private keys (`-----BEGIN ... PRIVATE KEY-----`)
- JWT tokens (`eyJ...`)
- Slack Webhooks and Bot Tokens
- Telegram Bot Tokens
- Database URLs with embedded passwords
- Generic API key heuristics

**High-entropy detection**: flags strings above 4.5 bits/char of Shannon entropy — catches custom secrets that don't match known patterns.

## Custom Patterns

Create a patterns file (`name:regex`):

```
GitLab Token: glpat-[a-zA-Z0-9_-]{20,}
Custom API Key: ck_[a-z0-9]{32}
```

Then scan with:

```bash
python3 dot_sentinel.py scan .env --patterns custom_patterns.txt
```

## Testing

```bash
python3 test_dot_sentinel.py -v
```

## License

MIT — see [LICENSE](LICENSE).

---

🧰 **[Tool on Hermtica Marketplace](https://hermtica.com/marketplace)** — the open, agent-agnostic marketplace for AI agent tools.
