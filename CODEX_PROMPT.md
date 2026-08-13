# Codex Prompt

You are extending an existing TypeScript/Fastify/PostgreSQL/Prisma project named `fivem-intel-api`.

## Goal

Build a private moderation evidence registry for FiveM communities. It must allow authorized staff to:

1. Maintain a vetted catalog of products/communities associated with cheating, leaking, exploit development, reselling, spoofers, or suspicious activity.
2. Store Discord server IDs only when they have been independently verified from an authorized or public source.
3. Search a Discord user ID against evidence that staff have manually submitted, imported from authorized exports, or obtained from legitimate internal moderation records.
4. Record role names observed in the supplied evidence, plus observation dates and end dates where known.
5. Never infer guilt from membership alone.
6. Expose an audit trail for every create/update/delete.
7. Add a simple staff-facing web dashboard later.

## Critical compliance constraints

Do NOT implement:
- Discord self-bots or user tokens.
- Guild/member scraping.
- Automated cross-server membership harvesting.
- Discord API features whose purpose is to profile users or their relationships across servers.
- Scraping Discord web pages.
- Hidden collection of message content.
- Any process that claims historical Discord roles unless an evidence record actually supports it.

Discord's current Developer Policy prohibits mining/scraping Discord and prohibits using API Data to profile Discord users, identities, or relationships. Keep Discord integration limited to ordinary commands inside an authorized server, such as a slash command that queries this application's own evidence database.

## Architecture

Keep:
- Node.js + TypeScript
- Fastify
- Prisma
- PostgreSQL
- Zod validation

Add:
- API-key or JWT/RBAC authentication for Admin, Analyst, ReadOnly
- audit_logs table
- evidence attachments metadata (do not store Discord CDN URLs as permanent evidence without an archival strategy)
- case_id / ticket_id
- evidence status: ACTIVE, DISPUTED, RETRACTED
- confidence reason field
- server aliases / historical names
- subject aliases
- pagination
- structured search
- CSV/JSON authorized-import endpoint with a dry-run mode
- export endpoint for a user's evidence record
- deletion / correction workflow
- unit tests and integration tests
- Dockerfile
- production docker-compose example
- OpenAPI/Swagger docs

## Search response

GET /api/v1/users/:discordId/evidence should return:
- discord_id
- evidence_count
- summarized classifications
- each associated server/community
- source type
- source reference
- first/last observed dates supported by evidence
- observed roles
- confidence
- evidence status
- explicit disclaimer: "Association evidence is not proof that the user cheated."

Do not create an automatic numeric "guilt score."

## Seed subjects

Seed these only as UNVERIFIED subjects; do not invent server IDs:
Eulen, RedEngine, Lynx, Brutan, Dopamine, FiveSense, Hydro, Lumia, Maestro, Phoenix, TiagoMenu, WolfMenu, Fallout, Alien Menu, Cobra, ChronoPulse, Hoax.

Before changing the schema, inspect all current project files. Use migrations, do not delete existing data. After implementation, run lint/typecheck/tests and give exact setup commands.
