import "dotenv/config";
import Fastify from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import fastifyStatic from "@fastify/static";
import path from "node:path";
import { z } from "zod";
import { prisma } from "./lib/prisma.js";
import { requireApiKey } from "./lib/auth.js";

const app = Fastify({ logger: true });

await app.register(cors, { origin: false });
await app.register(rateLimit, {
  max: 120,
  timeWindow: "1 minute"
});

await app.register(fastifyStatic, {
  root: path.join(process.cwd(), "public"),
  prefix: "/"
});

app.get("/health", async () => ({ ok: true }));

app.addHook("preHandler", async (req, reply) => {
  const publicPaths = [
    "/",
    "/index.html",
    "/health"
  ];

  if (publicPaths.includes(req.url)) {
    return;
  }

  return requireApiKey(req, reply);
});

const discordIdSchema = z
  .string()
  .regex(/^\d{15,22}$/, "Invalid Discord ID");

app.get("/api/v1/subjects", async () => {
  return prisma.subject.findMany({
    orderBy: { name: "asc" },
    include: { servers: true }
  });
});

app.post("/api/v1/subjects", async (req, reply) => {
  const body = z.object({
    name: z.string().min(2).max(100),

    category: z.enum([
      "FIVEM_CHEAT",
      "GENERAL_GAME_CHEAT",
      "CHEAT_RESELLER",
      "CHEAT_DEVELOPMENT",
      "LEAKING",
      "EXPLOIT_COMMUNITY",
      "HWID_SPOOFER",
      "ACCOUNT_MARKETPLACE",
      "UNKNOWN_SUSPICIOUS"
    ]),

    confidence: z
      .enum([
        "UNVERIFIED",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CONFIRMED"
      ])
      .default("UNVERIFIED"),

    description: z.string().max(2000).optional(),
    sourceUrl: z.string().url().optional()
  }).parse(req.body);

  const subject = await prisma.subject.create({
    data: body
  });

  return reply.code(201).send(subject);
});

app.get("/api/v1/servers", async () => {
  return prisma.discordServer.findMany({
    orderBy: { name: "asc" },
    include: { subject: true }
  });
});

app.post("/api/v1/servers", async (req, reply) => {
  const body = z.object({
    discordId: discordIdSchema,
    name: z.string().min(1).max(150),
    subjectId: z.string().optional(),

    confidence: z
      .enum([
        "UNVERIFIED",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CONFIRMED"
      ])
      .default("UNVERIFIED"),

    sourceUrl: z.string().url().optional(),
    active: z.boolean().optional(),
    firstSeenAt: z.coerce.date().optional(),
    lastSeenAt: z.coerce.date().optional()
  }).parse(req.body);

  const server = await prisma.discordServer.create({
    data: body
  });

  return reply.code(201).send(server);
});

app.get(
  "/api/v1/users/:discordId/evidence",
  async (req, reply) => {
    const { discordId } = z.object({
      discordId: discordIdSchema
    }).parse(req.params);

    const user = await prisma.discordUser.findUnique({
      where: { discordId },

      include: {
        evidence: {
          orderBy: { observedAt: "desc" },

          include: {
            server: {
              include: {
                subject: true
              }
            }
          }
        }
      }
    });

    if (!user) {
      return reply.code(404).send({
        found: false,
        discordId
      });
    }

    return {
      found: true,
      discordId,
      evidenceCount: user.evidence.length,
      evidence: user.evidence
    };
  }
);

app.post(
  "/api/v1/users/:discordId/evidence",
  async (req, reply) => {
    const { discordId } = z.object({
      discordId: discordIdSchema
    }).parse(req.params);

    const body = z.object({
      serverDiscordId: discordIdSchema.optional(),

      sourceType: z.enum([
        "MANUAL",
        "PUBLIC_SOURCE",
        "AUTHORIZED_EXPORT",
        "INTERNAL_MODERATION_RECORD",
        "USER_SUBMITTED"
      ]),

      sourceRef: z.string().min(3).max(1000),
      observedAt: z.coerce.date(),
      endedAt: z.coerce.date().optional(),

      confidence: z
        .enum([
          "UNVERIFIED",
          "LOW",
          "MEDIUM",
          "HIGH",
          "CONFIRMED"
        ])
        .default("UNVERIFIED"),

      roleNames: z
        .array(z.string().max(100))
        .default([]),

      notes: z.string().max(4000).optional(),
      createdBy: z.string().max(100).optional()
    }).parse(req.body);

    const user = await prisma.discordUser.upsert({
      where: { discordId },
      update: {},
      create: { discordId }
    });

    let serverId: string | undefined;

    if (body.serverDiscordId) {
      const server =
        await prisma.discordServer.findUnique({
          where: {
            discordId: body.serverDiscordId
          }
        });

      if (!server) {
        return reply.code(400).send({
          error:
            "Unknown serverDiscordId. Add the Discord server to /api/v1/servers first."
        });
      }

      serverId = server.id;
    }

    const evidence =
      await prisma.evidence.create({
        data: {
          userId: user.id,
          serverId,
          sourceType: body.sourceType,
          sourceRef: body.sourceRef,
          observedAt: body.observedAt,
          endedAt: body.endedAt,
          confidence: body.confidence,
          roleNames: body.roleNames,
          notes: body.notes,
          createdBy: body.createdBy
        },

        include: {
          server: {
            include: {
              subject: true
            }
          }
        }
      });

    return reply.code(201).send(evidence);
  }
);

app.delete(
  "/api/v1/evidence/:id",
  async (req, reply) => {
    const { id } = z.object({
      id: z.string().min(1)
    }).parse(req.params);

    await prisma.evidence.delete({
      where: { id }
    });

    return reply.code(204).send();
  }
);

app.setErrorHandler((err, req, reply) => {
  if (err instanceof z.ZodError) {
    return reply.code(400).send({
      error: "Validation failed",
      details: err.flatten()
    });
  }

  req.log.error(err);

  return reply.code(500).send({
    error: "Internal server error"
  });
});

const port = Number(
  process.env.PORT ?? 3000
);

const host =
  process.env.HOST ?? "0.0.0.0";

await app.listen({
  port,
  host
});
