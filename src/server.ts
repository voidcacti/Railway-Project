import "dotenv/config";

import Fastify from "fastify";
import cors from "@fastify/cors";
import rateLimit from "@fastify/rate-limit";
import fastifyStatic from "@fastify/static";
import fastifyCookie from "@fastify/cookie";
import fastifyJwt from "@fastify/jwt";

import bcrypt from "bcryptjs";
import path from "node:path";
import { z } from "zod";

import { prisma } from "./lib/prisma.js";

const app = Fastify({
  logger: true
});

const jwtSecret = process.env.JWT_SECRET;

if (!jwtSecret) {
  throw new Error(
    "JWT_SECRET environment variable is required."
  );
}

await app.register(cors, {
  origin: false
});

await app.register(rateLimit, {
  max: 120,
  timeWindow: "1 minute"
});

await app.register(fastifyCookie);

await app.register(fastifyJwt, {
  secret: jwtSecret,
  cookie: {
    cookieName: "intel_session",
    signed: false
  }
});

await app.register(fastifyStatic, {
  root: path.join(process.cwd(), "public"),
  prefix: "/"
});

const discordIdSchema = z
  .string()
  .regex(/^\d{15,22}$/, "Invalid Discord ID");

type StaffRole =
  | "ADMIN"
  | "ANALYST"
  | "READ_ONLY";

type SessionUser = {
  id: string;
  username: string;
  role: StaffRole;
};

async function bootstrapAdmin() {
  const username =
    process.env.BOOTSTRAP_ADMIN_USERNAME?.trim();

  const password =
    process.env.BOOTSTRAP_ADMIN_PASSWORD;

  if (!username || !password) {
    return;
  }

  const existing =
    await prisma.staffUser.findUnique({
      where: {
        username
      }
    });

  if (existing) {
    return;
  }

  if (
    password.length < 12 ||
    bcrypt.truncates(password)
  ) {
    throw new Error(
      "BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters and no more than bcrypt's supported input length."
    );
  }

  const passwordHash =
    await bcrypt.hash(password, 12);

  await prisma.staffUser.create({
    data: {
      username,
      passwordHash,
      role: "ADMIN",
      active: true
    }
  });

  app.log.info(
    `Bootstrap admin '${username}' created.`
  );
}

async function getCurrentUser(
  req: any
): Promise<SessionUser | null> {
  try {
    await req.jwtVerify();

    const tokenUser =
      req.user as SessionUser;

    const dbUser =
      await prisma.staffUser.findUnique({
        where: {
          id: tokenUser.id
        }
      });

    if (!dbUser || !dbUser.active) {
      return null;
    }

    return {
      id: dbUser.id,
      username: dbUser.username,
      role: dbUser.role
    };
  } catch {
    return null;
  }
}

async function requireLogin(
  req: any,
  reply: any
) {
  const user =
    await getCurrentUser(req);

  if (!user) {
    return reply.code(401).send({
      error: "Unauthorized"
    });
  }

  req.staffUser = user;
}

function requireRole(
  roles: StaffRole[]
) {
  return async (
    req: any,
    reply: any
  ) => {
    const user =
      await getCurrentUser(req);

    if (!user) {
      return reply.code(401).send({
        error: "Unauthorized"
      });
    }

    if (!roles.includes(user.role)) {
      return reply.code(403).send({
        error: "Forbidden"
      });
    }

    req.staffUser = user;
  };
}

/*
|--------------------------------------------------------------------------
| PUBLIC
|--------------------------------------------------------------------------
*/

app.get("/health", async () => ({
  ok: true
}));

/*
|--------------------------------------------------------------------------
| AUTH
|--------------------------------------------------------------------------
*/

app.post(
  "/api/v1/auth/login",
  {
    config: {
      rateLimit: {
        max: 10,
        timeWindow: "15 minutes"
      }
    }
  },
  async (req, reply) => {
    const body = z.object({
      username: z
        .string()
        .min(2)
        .max(100),

      password: z
        .string()
        .min(1)
        .max(200)
    }).parse(req.body);

    const user =
      await prisma.staffUser.findUnique({
        where: {
          username: body.username
        }
      });

    if (!user || !user.active) {
      return reply.code(401).send({
        error:
          "Invalid username or password"
      });
    }

    const passwordValid =
      await bcrypt.compare(
        body.password,
        user.passwordHash
      );

    if (!passwordValid) {
      return reply.code(401).send({
        error:
          "Invalid username or password"
      });
    }

    const token =
      await reply.jwtSign(
        {
          id: user.id,
          username: user.username,
          role: user.role
        },
        {
          expiresIn: "8h"
        }
      );

    reply.setCookie(
      "intel_session",
      token,
      {
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 60 * 60 * 8
      }
    );

    return {
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role
      }
    };
  }
);

app.post(
  "/api/v1/auth/logout",
  async (_req, reply) => {
    reply.clearCookie(
      "intel_session",
      {
        path: "/"
      }
    );

    return {
      ok: true
    };
  }
);

app.get(
  "/api/v1/auth/me",
  {
    preHandler: requireLogin
  },
  async (req: any) => {
    return {
      authenticated: true,
      user: req.staffUser
    };
  }
);

/*
|--------------------------------------------------------------------------
| STAFF MANAGEMENT
|--------------------------------------------------------------------------
*/

app.get(
  "/api/v1/staff",
  {
    preHandler:
      requireRole(["ADMIN"])
  },
  async () => {
    return prisma.staffUser.findMany({
      orderBy: {
        username: "asc"
      },
      select: {
        id: true,
        username: true,
        role: true,
        active: true,
        createdAt: true,
        updatedAt: true
      }
    });
  }
);

app.post(
  "/api/v1/staff",
  {
    preHandler:
      requireRole(["ADMIN"])
  },
  async (req, reply) => {
    const body = z.object({
      username: z
        .string()
        .min(2)
        .max(100),

      password: z
        .string()
        .min(12)
        .max(72),

      role: z.enum([
        "ADMIN",
        "ANALYST",
        "READ_ONLY"
      ])
    }).parse(req.body);

    if (
      bcrypt.truncates(body.password)
    ) {
      return reply.code(400).send({
        error:
          "Password is too long."
      });
    }

    const existing =
      await prisma.staffUser.findUnique({
        where: {
          username:
            body.username
        }
      });

    if (existing) {
      return reply.code(409).send({
        error:
          "Staff username already exists"
      });
    }

    const passwordHash =
      await bcrypt.hash(
        body.password,
        12
      );

    const user =
      await prisma.staffUser.create({
        data: {
          username:
            body.username,

          passwordHash,

          role:
            body.role,

          active: true
        },

        select: {
          id: true,
          username: true,
          role: true,
          active: true,
          createdAt: true
        }
      });

    return reply
      .code(201)
      .send(user);
  }
);

app.patch(
  "/api/v1/staff/:id",
  {
    preHandler:
      requireRole(["ADMIN"])
  },
  async (req, reply) => {
    const params = z.object({
      id: z.string().min(1)
    }).parse(req.params);

    const body = z.object({
      role: z
        .enum([
          "ADMIN",
          "ANALYST",
          "READ_ONLY"
        ])
        .optional(),

      active: z
        .boolean()
        .optional(),

      password: z
        .string()
        .min(12)
        .max(72)
        .optional()
    }).parse(req.body);

    let passwordHash:
      string | undefined;

    if (body.password) {
      if (
        bcrypt.truncates(
          body.password
        )
      ) {
        return reply.code(400).send({
          error:
            "Password is too long."
        });
      }

      passwordHash =
        await bcrypt.hash(
          body.password,
          12
        );
    }

    const updated =
      await prisma.staffUser.update({
        where: {
          id: params.id
        },

        data: {
          role: body.role,
          active: body.active,
          passwordHash
        },

        select: {
          id: true,
          username: true,
          role: true,
          active: true,
          updatedAt: true
        }
      });

    return updated;
  }
);

/*
|--------------------------------------------------------------------------
| SUBJECTS
|--------------------------------------------------------------------------
*/

app.get(
  "/api/v1/subjects",
  {
    preHandler:
      requireRole([
        "ADMIN",
        "ANALYST"
      ])
  },
  async () => {
    return prisma.subject.findMany({
      orderBy: {
        name: "asc"
      },
      include: {
        servers: true
      }
    });
  }
);

app.post(
  "/api/v1/subjects",
  {
    preHandler:
      requireRole(["ADMIN"])
  },
  async (req, reply) => {
    const body = z.object({
      name: z
        .string()
        .min(2)
        .max(100),

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
        .default(
          "UNVERIFIED"
        ),

      description: z
        .string()
        .max(2000)
        .optional(),

      sourceUrl: z
        .string()
        .url()
        .optional()
    }).parse(req.body);

    const existing =
      await prisma.subject.findUnique({
        where: {
          name: body.name
        }
      });

    if (existing) {
      return reply.code(409).send({
        error:
          "Subject already exists"
      });
    }

    const subject =
      await prisma.subject.create({
        data: body
      });

    return reply
      .code(201)
      .send(subject);
  }
);

/*
|--------------------------------------------------------------------------
| COMMUNITIES
|--------------------------------------------------------------------------
*/

app.get(
  "/api/v1/servers",
  {
    preHandler:
      requireRole([
        "ADMIN",
        "ANALYST"
      ])
  },
  async () => {
    return prisma.discordServer.findMany({
      orderBy: {
        name: "asc"
      },
      include: {
        subject: true
      }
    });
  }
);

app.post(
  "/api/v1/servers",
  {
    preHandler:
      requireRole(["ADMIN"])
  },
  async (req, reply) => {
    const body = z.object({
      discordId:
        discordIdSchema,

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
        .default(
          "UNVERIFIED"
        ),

      sourceUrl: z
        .string()
        .url()
        .optional(),

      active: z
        .boolean()
        .optional()
    }).parse(req.body);

    const existing =
      await prisma.discordServer.findUnique({
        where: {
          discordId:
            body.discordId
        }
      });

    if (existing) {
      return reply.code(409).send({
        error:
          "Discord community already exists"
      });
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
  }
);

/*
|--------------------------------------------------------------------------
| USER LOOKUP
|--------------------------------------------------------------------------
*/

app.get(
  "/api/v1/users/:discordId/evidence",
  {
    preHandler:
      requireRole([
        "ADMIN",
        "ANALYST",
        "READ_ONLY"
      ])
  },
  async (req, reply) => {
    const { discordId } =
      z.object({
        discordId:
          discordIdSchema
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
      return reply
        .code(404)
        .send({
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
| ERROR HANDLER
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

const port =
  Number(
    process.env.PORT ??
    3000
  );

const host =
  process.env.HOST ??
  "0.0.0.0";

await bootstrapAdmin();

await app.listen({
  port,
  host
});
