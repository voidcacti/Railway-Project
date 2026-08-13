# FiveM Intel API

Private moderation evidence registry for FiveM-related cheating/leaking/exploit communities.

## Important design boundary

This starter does **not** automatically harvest Discord guild memberships or role histories.

It stores:
- a catalog of subjects/products;
- verified Discord server IDs you enter;
- evidence records you are authorized to use;
- role names and timestamps only when the underlying evidence supports them.

Association evidence should never be treated as automatic proof of cheating.

## Stack

- Node.js
- TypeScript
- Fastify
- PostgreSQL
- Prisma
- Zod
- Docker Compose for local PostgreSQL

## 1. Install prerequisites

Install:
- Node.js 20+ (Node 22 recommended)
- Docker Desktop
- Git
- VS Code / Codex environment if desired

## 2. Create environment file

Copy `.env.example` to `.env`.

Generate a long random value for `API_KEY`.

Example PowerShell:

```powershell
Copy-Item .env.example .env
```

Then edit `.env`.

## 3. Start PostgreSQL

```powershell
docker compose up -d
```

## 4. Install packages

```powershell
npm install
```

## 5. Generate Prisma client

```powershell
npm run prisma:generate
```

## 6. Create database migration

```powershell
npx prisma migrate dev --name init
```

## 7. Seed subjects

```powershell
npm run prisma:seed
```

The seed creates product/community subjects only. It intentionally does **not** invent Discord server IDs.

## 8. Run the API

```powershell
npm run dev
```

Health check:

```powershell
Invoke-RestMethod http://localhost:3000/health
```

Expected:

```json
{"ok":true}
```

## 9. Authenticate

All routes except `/health` require:

```http
x-api-key: YOUR_API_KEY
```

PowerShell example:

```powershell
$headers = @{ "x-api-key" = "YOUR_API_KEY" }
Invoke-RestMethod `
  -Uri http://localhost:3000/api/v1/subjects `
  -Headers $headers
```

## 10. Add a verified Discord server

First retrieve subjects:

```powershell
Invoke-RestMethod `
  -Uri http://localhost:3000/api/v1/subjects `
  -Headers $headers
```

Then POST a verified server. Do not guess the Discord server ID.

```powershell
$body = @{
  discordId = "123456789012345678"
  name = "Example Community"
  confidence = "CONFIRMED"
  sourceUrl = "https://example.com/source"
  active = $true
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri http://localhost:3000/api/v1/servers `
  -Headers $headers `
  -ContentType "application/json" `
  -Body $body
```

## 11. Add user evidence

```powershell
$userId = "342419658848206862"

$body = @{
  serverDiscordId = "123456789012345678"
  sourceType = "INTERNAL_MODERATION_RECORD"
  sourceRef = "CASE-2026-001"
  observedAt = "2026-08-13T13:00:00Z"
  confidence = "HIGH"
  roleNames = @("Customer", "FiveM")
  notes = "Only record what the underlying evidence supports."
  createdBy = "Josh"
} | ConvertTo-Json

Invoke-RestMethod `
  -Method Post `
  -Uri "http://localhost:3000/api/v1/users/$userId/evidence" `
  -Headers $headers `
  -ContentType "application/json" `
  -Body $body
```

## 12. Search a Discord ID

```powershell
Invoke-RestMethod `
  -Uri "http://localhost:3000/api/v1/users/$userId/evidence" `
  -Headers $headers
```

## Current API endpoints

- `GET /health`
- `GET /api/v1/subjects`
- `POST /api/v1/subjects`
- `GET /api/v1/servers`
- `POST /api/v1/servers`
- `GET /api/v1/users/:discordId/evidence`
- `POST /api/v1/users/:discordId/evidence`
- `DELETE /api/v1/evidence/:id`

## Recommended next phase

Use the included `CODEX_PROMPT.md` with Codex to add:
- staff accounts and RBAC;
- audit logging;
- cases;
- correction/dispute workflows;
- bulk authorized imports;
- dashboard;
- Discord slash command that queries this database only;
- Swagger/OpenAPI;
- tests;
- production deployment.

## Discord bot integration that is appropriate

A normal moderation-server slash command can call this API:

`/intel discord_id:342419658848206862`

The bot would query **this database** and display records your team already possesses. It should not crawl other servers to populate the database.

## Data quality rules

1. Never invent server IDs.
2. Keep unverified subjects marked UNVERIFIED.
3. Preserve source references.
4. Record observed roles only when evidence shows the roles.
5. Distinguish "present now" from "historically observed."
6. Provide a correction/removal process.
7. Do not treat server membership as proof of cheat usage.
