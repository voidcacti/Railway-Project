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

app.get("/health", async () => ({
  ok: true
}));

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

/*
|--------------------------------------------------------------------------
| SUBJECTS
|--------------------------------------------------------------------------
*/

app.get("/api/v1/subjects", async () => {
  return prisma.subject.findMany({
    orderBy: {
      name: "asc"
    },
    include: {
      servers: true
    }
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

    description: z
      .string()
      .max(2000)
      .optional(),

    sourceUrl: z
      .string()
      .url()
      .optional()
  }).parse(req.body);

  const existingSubject =
    await prisma.subject.findUnique({
      where: {
        name: body.name
      }
    });

  if (existingSubject) {
    return reply.code(409).send({
      error: "Subject already exists",
      message: `${body.name} is already registered.`,
      existing: existingSubject
    });
  }

  const subject =
    await prisma.subject.create({
      data: body
    });

  return reply
    .code(201)
    .send(subject);
});

/*
|--------------------------------------------------------------------------
| DISCORD SERVERS / COMMUNITIES
|--------------------------------------------------------------------------
*/

app.get("/api/v1/servers", async () => {
  return prisma.discordServer.findMany({
    orderBy: {
      name: "asc"
    },
    include: {
      subject: true
    }
  });
});

app.post("/api/v1/servers", async (req, reply) => {
  const body = z.object({
    discordId: discordIdSchema,

    name: z
      .string()
      .min(1)
      .max(150),

    subjectId: z
      .string()
      .optional(),

    confidence: z
      .enum([
        "UNVERIFIED",
        "LOW",
        "MEDIUM",
        "HIGH",
        "CONFIRMED"
      ])
      .default("UNVERIFIED"),

    sourceUrl: z
      .string()
      .url()
      .optional(),

    active: z
      .boolean()
      .optional(),

    firstSeenAt: z
      .coerce
      .date()
      .optional(),

    lastSeenAt: z
      .coerce
      .date()
      .optional()
  }).parse(req.body);

  const existingServer =
    await prisma.discordServer.findUnique({
      where: {
        discordId: body.discordId
      },
      include: {
        subject: true
      }
    });

  if (existingServer) {
    return reply.code(409).send({
      error: "Discord community already exists",
      message:
        `Guild ID ${body.discordId} is already registered as ${existingServer.name}.`,
      existing: existingServer
    });
  }

  if (body.subjectId) {
    const subject =
      await prisma.subject.findUnique({
        where: {
          id: body.subjectId
        }
      });

    if (!subject) {
      return reply.code(400).send({
        error: "Unknown subjectId",
        message:
          "The selected product/community does not exist."
      });
    }
  }

  const server =
    await prisma.discordServer.create({
      data: body,
      include: {
        subject: true
      }
    });

  return reply
    .code(201)
    .send(server);
});

/*
|--------------------------------------------------------------------------
| USER LOOKUP
|--------------------------------------------------------------------------
*/

app.get(
  "/api/v1/users/:discordId/evidence",
  async (req, reply) => {
    const { discordId } = z.object({
      discordId: discordIdSchema
    }).parse(req.params);

    const user =
      await prisma.discordUser.findUnique({
        where: {
          discordId
        },

        include: {
          evidence: {
            orderBy: {
              observedAt: "desc"
            },

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
        discordId,
        evidenceCount: 0,
        evidence: []
      });
    }

    return {
      found: true,
      discordId,
      evidenceCount:
        user.evidence.length,
      evidence:
        user.evidence
    };
  }
);

/*
|--------------------------------------------------------------------------
| ADD USER ↔ COMMUNITY ASSOCIATION
|--------------------------------------------------------------------------
*/

app.post(
  "/api/v1/users/:discordId/evidence",
  async (req, reply) => {
    const { discordId } = z.object({
      discordId: discordIdSchema
    }).parse(req.params);

    const body = z.object({
      serverDiscordId:
        discordIdSchema.optional(),

      sourceType: z.enum([
        "MANUAL",
        "PUBLIC_SOURCE",
        "AUTHORIZED_EXPORT",
        "INTERNAL_MODERATION_RECORD",
        "USER_SUBMITTED"
      ]),

      sourceRef: z
        .string()
        .min(3)
        .max(1000),

      observedAt:
        z.coerce.date(),

      endedAt:
        z.coerce
          .date()
          .optional(),

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
        .array(
          z.string().max(100)
        )
        .default([]),

      notes: z
        .string()
        .max(4000)
        .optional(),

      createdBy: z
        .string()
        .max(100)
        .optional()
    }).parse(req.body);

    const user =
      await prisma.discordUser.upsert({
        where: {
          discordId
        },

        update: {},

        create: {
          discordId
        }
      });

    let serverId:
      string | undefined;

    if (body.serverDiscordId) {
      const server =
        await prisma.discordServer.findUnique({
          where: {
            discordId:
              body.serverDiscordId
          }
        });

      if (!server) {
        return reply.code(400).send({
          error:
            "Unknown serverDiscordId",
          message:
            "Add the Discord community before adding user associations."
        });
      }

      serverId = server.id;

      const existingEvidence =
        await prisma.evidence.findFirst({
          where: {
            userId:
              user.id,

            serverId:
              server.id
          }
        });

      if (existingEvidence) {
        return reply.code(409).send({
          error:
            "Association already exists",

          message:
            `Discord user ${discordId} is already associated with guild ${body.serverDiscordId}.`,

          existing:
            existingEvidence
        });
      }
    }

    const evidence =
      await prisma.evidence.create({
        data: {
          userId:
            user.id,

          serverId,

          sourceType:
            body.sourceType,

          sourceRef:
            body.sourceRef,

          observedAt:
            body.observedAt,

          endedAt:
            body.endedAt,

          confidence:
            body.confidence,

          roleNames:
            body.roleNames,

          notes:
            body.notes,

          createdBy:
            body.createdBy
        },

        include: {
          server: {
            include: {
              subject: true
            }
          }
        }
      });

    return reply
      .code(201)
      .send(evidence);
  }
);

/*
|--------------------------------------------------------------------------
| DELETE EVIDENCE
|--------------------------------------------------------------------------
*/

app.delete(
  "/api/v1/evidence/:id",
  async (req, reply) => {
    const { id } = z.object({
      id: z
        .string()
        .min(1)
    }).parse(req.params);

    const existing =
      await prisma.evidence.findUnique({
        where: {
          id
        }
      });

    if (!existing) {
      return reply.code(404).send({
        error:
          "Evidence record not found"
      });
    }

    await prisma.evidence.delete({
      where: {
        id
      }
    });

    return reply
      .code(204)
      .send();
  }
);

/*
|--------------------------------------------------------------------------
| ERROR HANDLING
|--------------------------------------------------------------------------
*/

app.setErrorHandler(
  (err, req, reply) => {
    if (
      err instanceof z.ZodError
    ) {
      return reply.code(400).send({
        error:
          "Validation failed",

        details:
          err.flatten()
      });
    }

    req.log.error(err);

    return reply.code(500).send({
      error:
        "Internal server error"
    });
  }
);

/*
|--------------------------------------------------------------------------
| START SERVER
|--------------------------------------------------------------------------
*/

const port =
  Number(
    process.env.PORT ??
    3000
  );

const host =
  process.env.HOST ??
  "0.0.0.0";

await app.listen({
  port,
  host
});
