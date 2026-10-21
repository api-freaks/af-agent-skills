# APIFreaks Agent Skills

[![skills.sh](https://skills.sh/b/api-freaks/af-agent-skills)](https://skills.sh/api-freaks/af-agent-skills)

Agent skills for the [APIFreaks](https://apifreaks.com) platform. Install them in Claude, Cursor, Codex, GitHub Copilot, or any client that supports [Agent Skills](https://agentskills.io/specification), and the agent works with live APIFreaks APIs from a conversation.

The [APIFreaks MCP server](https://apifreaks.com/integrations/mcp-server) is how an agent reaches the platform: its tools describe their own inputs and outputs. A skill covers what sits above a single call: setup, credit cost, working at volume, reading results correctly, and recovering from failures. It applies whether or not MCP is connected.

```bash
npx skills add api-freaks/af-agent-skills --skill apifreaks-platform
```

## Skills

### apifreaks-platform

Gives an agent a reliable way to use APIFreaks. It checks whether MCP is connected and helps the user connect it when it is not, states what a job will cost before it runs, works through bulk input, and reads every result before reporting it.

**Use when**

- Looking up WHOIS, DNS, SSL, domains, or IP intelligence
- Validating email, phone, VAT, IBAN, or SWIFT
- Taking screenshots, scraping pages, or processing PDFs
- Enriching a list of domains, IPs, or emails

Requires an APIFreaks API key. Instructions: [`SKILL.md`](skills/apifreaks-platform/SKILL.md).

## Install

```bash
# list skills in this repo
npx skills add api-freaks/af-agent-skills --list

# current project
npx skills add api-freaks/af-agent-skills --skill apifreaks-platform

# one agent
npx skills add api-freaks/af-agent-skills --skill apifreaks-platform --agent claude-code

# all projects
npx skills add api-freaks/af-agent-skills --skill apifreaks-platform -g
```

```bash
npx skills update apifreaks-platform
npx skills remove apifreaks-platform
```

Add `-g` on update or remove if you installed globally.

To install by hand, copy `skills/apifreaks-platform/` into your agent's skills directory.

## MCP setup

The skill works best with the APIFreaks MCP server connected, and helps the user connect it. Two things catch most people during setup:

- The server needs `ENABLE_MODULES` as well as the key. Without it, only `list_modules` appears and the server does nothing.
- It needs Node.js v24 or newer. An older version stops it starting at all.

Setup instructions for every supported client live at [apifreaks.com/integrations/mcp-server](https://apifreaks.com/integrations/mcp-server).

## API key

Create a key at [apifreaks.com](https://apifreaks.com). New accounts include 10,000 free credits, no card required.

The skill reads `APIFREAKS_API_KEY`. Put it where the agent can see it: the `env` block of your MCP client config, a gitignored `.env`, your shell profile, or the current session.

```bash
export APIFREAKS_API_KEY="your_key"
```

A key pasted into the chat is used for that session only, is never written to a file, and is never echoed back.

## Credits

Every call draws on one shared balance, and only successful calls are billed: a failed call deducts nothing and is refunded. Credit cost per endpoint is published in [llms-full.txt](https://apifreaks.com/llms-full.txt) and on each product page's pricing section. Plan details are machine-readable at [pricing.md](https://apifreaks.com/pricing.md).

## Usage

The skill is for work an agent cannot do from memory: live lookups, lists, logs, and files.

```
Enrich unique client IPs in access.log with country, ASN, and VPN/proxy.
Skip private ranges. Write a table of the suspicious ones only.
```

```
Validate every email and phone in signups.csv. Keep rows the APIs accept;
list failures with the returned reason, not a guess.
```

```
Check these 12 product names for domain availability, then run a typosquat
lookup on the one we pick.
```

```
Merge invoices/*.pdf, compress the result, and save it. Quote the credit
cost before you start the job.
```

## License

[MIT](LICENSE)
