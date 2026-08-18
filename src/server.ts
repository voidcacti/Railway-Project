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

/*
|--------------------------------------------------------------------------
| CONFIG
|--------------------------------------------------------------------------
*/

const jwtSecret = process.env.JWT_SECRET;
const flomkkToken = process.env.FLOMKK_API_TOKEN;

const FLOMKK_BASE_URL = "https://api.flomkk.work";

if (!jwtSecret) {
  throw new Error(
    "JWT_SECRET environment variable is required."
  );
}

/*
|--------------------------------------------------------------------------
| PLUGINS
|--------------------------------------------------------------------------
*/

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

/*
|--------------------------------------------------------------------------
| TYPES / VALIDATION
|--------------------------------------------------------------------------
*/

const discordIdSchema = z
  .string()
  .regex(
    /^\d{15,22}$/,
    "Invalid Discord ID"
  );

type StaffRole =
  | "ADMIN"
  | "ANALYST"
  | "READ_ONLY";

type SessionUser = {
  id: string;
  username: string;
  role: StaffRole;
};

type FlomkkRole = {
  role_id?: string;
  role_name?: string;
  timestamp?: number;
};

type FlomkkServer = {
  server_id?: string;
  server_name?: string;
  roles?: FlomkkRole[];
};

type FlomkkResult = {
  discord_id?: string;
  servers?: FlomkkServer[];
  timestamp?: number;
};

type FlomkkResponse = {
  success: boolean;
  status?: string;
  message?: string;
  result?: FlomkkResult | null;
  error?: string;
};

/*
|--------------------------------------------------------------------------
| BOOTSTRAP ADMIN
|--------------------------------------------------------------------------
*/

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
      "BOOTSTRAP_ADMIN_PASSWORD must be at least 12 characters and within bcrypt's supported length."
    );
  }

  const passwordHash =
    await bcrypt.hash(
      password,
      12
    );

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

/*
|--------------------------------------------------------------------------
| AUTH HELPERS
|--------------------------------------------------------------------------
*/

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
    return reply
      .code(401)
      .send({
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
      return reply
        .code(401)
        .send({
          error: "Unauthorized"
        });
    }

    if (
      !roles.includes(
        user.role
      )
    ) {
      return reply
        .code(403)
        .send({
          error: "Forbidden"
        });
    }

    req.staffUser = user;
  };
}

/*
|--------------------------------------------------------------------------
| FLOMKK API
|--------------------------------------------------------------------------
*/

async function flomkkRequest(
  endpoint: string,
  discordId?: string
): Promise<{
  ok: boolean;
  statusCode: number;
  data: FlomkkResponse | null;
}> {
  if (!flomkkToken) {
    return {
      ok: false,
      statusCode: 503,
      data: {
        success: false,
        status: "TOKEN_NOT_CONFIGURED",
        message:
          "FLOMKK_API_TOKEN is not configured."
      }
    };
  }

  try {
    const response =
      await fetch(
        `${FLOMKK_BASE_URL}${endpoint}`,
        {
          method:
            discordId
              ? "POST"
              : "GET",

          headers: {
            Authorization:
              `Bearer ${flomkkToken}`,
            "Content-Type":
              "application/json",
            Accept:
              "application/json"
          },

          body:
            discordId
              ? JSON.stringify({
                  discord:
                    discordId
                })
              : undefined
        }
      );

    let data:
      FlomkkResponse | null =
        null;

    try {
      data =
        (await response.json()) as FlomkkResponse;
    } catch {
      data = null;
    }

    return {
      ok: response.ok,
      statusCode:
        response.status,
      data
    };
  } catch (error) {
    app.log.error(
      error,
      `Failed Flomkk request to ${endpoint}`
    );

    return {
      ok: false,
      statusCode: 502,
      data: {
        success: false,
        status:
          "PROVIDER_UNAVAILABLE",
        message:
          "Unable to reach intelligence provider."
      }
    };
  }
}

function normalizeFlomkkServers(
  servers:
    FlomkkServer[] | undefined
) {
  return (
    servers ?? []
  ).map(
    (server) => ({
      serverId:
        server.server_id ??
        null,

      serverName:
        server.server_name ??
        "Unknown Server",

      roles:
        (
          server.roles ??
          []
        ).map(
          (role) => ({
            roleId:
              role.role_id ??
              null,

            roleName:
              role.role_name ??
              "Unknown Role",

            timestamp:
              role.timestamp ??
              null,

            observedAt:
              role.timestamp
                ? new Date(
                    role.timestamp *
                      1000
                  ).toISOString()
                : null
          })
        )
    })
  );
}

/*
|--------------------------------------------------------------------------
| HEALTH / VERSION
|--------------------------------------------------------------------------
*/

app.get(
  "/health",
  async () => ({
    ok: true
  })
);

app.get(
  "/version",
  async () => ({
    version: "flomkk-v1",
    intelRoute: true
  })
);

/*
|--------------------------------------------------------------------------
| AUTH ROUTES
|--------------------------------------------------------------------------
*/

app.post(
  "/api/v1/auth/login",
  {
    config: {
      rateLimit: {
        max: 10,
        timeWindow:
          "15 minutes"
      }
    }
  },
  async (
    req,
    reply
  ) => {
    const body =
      z.object({
        username:
          z
            .string()
            .min(2)
            .max(100),

        password:
          z
            .string()
            .min(1)
            .max(200)
      })
      .parse(
        req.body
      );

    const user =
      await prisma.staffUser.findUnique({
        where: {
          username:
            body.username
        }
      });

    if (!user || !user.active) {
      return reply
        .code(401)
        .send({
          error:
            "Invalid username or password"
        });
    }

    const valid =
      await bcrypt.compare(
        body.password,
        user.passwordHash
      );

    if (!valid) {
      return reply
        .code(401)
        .send({
          error:
            "Invalid username or password"
        });
    }

    await prisma.staffUser.update({
      where: {
        id: user.id
      },
      data: {
        lastLoginAt:
          new Date()
      }
    });

    const token =
      await reply.jwtSign(
        {
          id: user.id,
          username:
            user.username,
          role:
            user.role
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
        maxAge:
          60 * 60 * 8
      }
    );

    return {
      ok: true,
      user: {
        id: user.id,
        username:
          user.username,
        role:
          user.role
      }
    };
  }
);

app.post(
  "/api/v1/auth/logout",
  async (
    _req,
    reply
  ) => {
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
    preHandler:
      requireLogin
  },
  async (
    req: any
  ) => ({
    authenticated: true,
    user:
      req.staffUser
  })
);

/*
|--------------------------------------------------------------------------
| LIVE INTELLIGENCE CHECK
|--------------------------------------------------------------------------
*/

app.get(
  "/api/v1/intel/check/:discordId",
  {
    preHandler:
      requireRole([
        "ADMIN",
        "ANALYST",
        "READ_ONLY"
      ])
  },
  async (
    req,
    reply
  ) => {
    const {
      discordId
    } =
      z.object({
        discordId:
          discordIdSchema
      })
      .parse(
        req.params
      );

    const internalUser =
      await prisma.discordUser.findUnique({
        where: {
          discordId
        },

        include: {
          evidence: {
            orderBy: {
              observedAt:
                "desc"
            },

            include: {
              server: {
                include: {
                  subject:
                    true
                }
              }
            }
          }
        }
      });

    const [
      blacklistResponse,
      cheaterResponse
    ] =
      await Promise.all([
        flomkkRequest(
          "/v1/check-user",
          discordId
        ),

        flomkkRequest(
          "/v1/check-cheater",
          discordId
        )
      ]);

    const blacklistData =
      blacklistResponse.data;

    const cheaterData =
      cheaterResponse.data;

    const blacklistedServers =
      normalizeFlomkkServers(
        blacklistData
          ?.result
          ?.servers
      );

    const cheaterServers =
      normalizeFlomkkServers(
        cheaterData
          ?.result
          ?.servers
      );

    return reply.send({
      success: true,

      discordId,

      provider: {
        name: "Flomkk",

        configured:
          Boolean(
            flomkkToken
          ),

        tokenExpired:
          blacklistResponse.statusCode ===
            401 ||
          cheaterResponse.statusCode ===
            401,

        blacklistRequest: {
          ok:
            blacklistResponse.ok,

          statusCode:
            blacklistResponse.statusCode,

          providerStatus:
            blacklistData
              ?.status ??
            null,

          providerMessage:
            blacklistData
              ?.message ??
            null
        },

        cheaterRequest: {
          ok:
            cheaterResponse.ok,

          statusCode:
            cheaterResponse.statusCode,

          providerStatus:
            cheaterData
              ?.status ??
            null,

          providerMessage:
            cheaterData
              ?.message ??
            null
        }
      },

      internal: {
        found:
          Boolean(
            internalUser
          ),

        evidenceCount:
          internalUser
            ?.evidence
            .length ??
          0,

        evidence:
          internalUser
            ?.evidence ??
          []
      },

      blacklist: {
        found:
          Boolean(
            blacklistData
              ?.success &&
            blacklistData
              ?.result
          ),

        serverCount:
          blacklistedServers
            .length,

        timestamp:
          blacklistData
            ?.result
            ?.timestamp ??
          null,

        servers:
          blacklistedServers
      },

      confirmedCheater: {
        found:
          Boolean(
            cheaterData
              ?.success &&
            cheaterData
              ?.result
          ),

        serverCount:
          cheaterServers
            .length,

        timestamp:
          cheaterData
            ?.result
            ?.timestamp ??
          null,

        servers:
          cheaterServers
      }
    });
  }
);

/*
|--------------------------------------------------------------------------
| LICENSE INFORMATION
|--------------------------------------------------------------------------
*/

app.get(
  "/api/v1/intel/license",
  {
    preHandler:
      requireRole([
        "ADMIN"
      ])
  },
  async (
    _req,
    reply
  ) => {
    const result =
      await flomkkRequest(
        "/v1/license-information"
      );

    if (
      result.statusCode ===
      401
    ) {
      return reply
        .code(401)
        .send({
          success: false,
          expired: true,
          provider:
            "Flomkk",
          data:
            result.data
        });
    }

    return reply.send({
      success:
        result.ok,

      expired: false,

      provider:
        "Flomkk",

      data:
        result.data
    });
  }
);

/*
|--------------------------------------------------------------------------
| STAFF
|--------------------------------------------------------------------------
*/

app.get(
  "/api/v1/staff",
  {
    preHandler:
      requireRole([
        "ADMIN"
      ])
  },
  async () => {
    return prisma.staffUser.findMany({
      orderBy: {
        username:
          "asc"
      },

      select: {
        id: true,
        username: true,
        role: true,
        active: true,
        lastLoginAt: true,
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
      requireRole([
        "ADMIN"
      ])
  },
  async (
    req,
    reply
  ) => {
    const body =
      z.object({
        username:
          z
            .string()
            .min(2)
            .max(100),

        password:
          z
            .string()
            .min(12)
            .max(72),

        role:
          z.enum([
            "ADMIN",
            "ANALYST",
            "READ_ONLY"
          ])
      })
      .parse(
        req.body
      );

    if (
      bcrypt.truncates(
        body.password
      )
    ) {
      return reply
        .code(400)
        .send({
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
      return reply
        .code(409)
        .send({
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
          lastLoginAt: true,
          createdAt: true
        }
      });

    return reply
      .code(201)
      .send(
        user
      );
  }
);

app.patch(
  "/api/v1/staff/:id",
  {
    preHandler:
      requireRole([
        "ADMIN"
      ])
  },
  async (
    req,
    reply
  ) => {
    const params =
      z.object({
        id:
          z
            .string()
            .min(1)
      })
      .parse(
        req.params
      );

    const body =
      z.object({
        role:
          z
            .enum([
              "ADMIN",
              "ANALYST",
              "READ_ONLY"
            ])
            .optional(),

        active:
          z
            .boolean()
            .optional(),

        password:
          z
            .string()
            .min(12)
            .max(72)
            .optional()
      })
      .parse(
        req.body
      );

    let passwordHash:
      string | undefined;

    if (
      body.password
    ) {
      if (
        bcrypt.truncates(
          body.password
        )
      ) {
        return reply
          .code(400)
          .send({
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

    return prisma.staffUser.update({
      where: {
        id:
          params.id
      },

      data: {
        role:
          body.role,

        active:
          body.active,

        passwordHash
      },

      select: {
        id: true,
        username: true,
        role: true,
        active: true,
        lastLoginAt: true,
        createdAt: true,
        updatedAt: true
      }
    });
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
        name:
          "asc"
      },

      include: {
        servers:
          true
      }
    });
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
        name:
          "asc"
      },

      include: {
        subject:
          true
      }
    });
  }
);

app.post(
  "/api/v1/servers",
  {
    preHandler:
      requireRole([
        "ADMIN"
      ])
  },
  async (
    req,
    reply
  ) => {
    const body =
      z.object({
        discordId:
          discordIdSchema,

        name:
          z
            .string()
            .min(1)
            .max(150),

        subjectId:
          z
            .string()
            .optional(),

        confidence:
          z
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

        sourceUrl:
          z
            .string()
            .url()
            .optional(),

        active:
          z
            .boolean()
            .optional()
      })
      .parse(
        req.body
      );

    const existing =
      await prisma.discordServer.findUnique({
        where: {
          discordId:
            body.discordId
        }
      });

    if (existing) {
      return reply
        .code(409)
        .send({
          error:
            "Discord community already exists"
        });
    }

    if (body.subjectId) {
      const subject =
        await prisma.subject.findUnique({
          where: {
            id:
              body.subjectId
          }
        });

      if (!subject) {
        return reply
          .code(400)
          .send({
            error:
              "Unknown subjectId"
          });
      }
    }

    const server =
      await prisma.discordServer.create({
        data: body,

        include: {
          subject:
            true
        }
      });

    return reply
      .code(201)
      .send(
        server
      );
  }
);

/*
|--------------------------------------------------------------------------
| INTERNAL USER LOOKUP
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
  async (
    req,
    reply
  ) => {
    const {
      discordId
    } =
      z.object({
        discordId:
          discordIdSchema
      })
      .parse(
        req.params
      );

    const user =
      await prisma.discordUser.findUnique({
        where: {
          discordId
        },

        include: {
          evidence: {
            orderBy: {
              observedAt:
                "desc"
            },

            include: {
              server: {
                include: {
                  subject:
                    true
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
| ADD INTERNAL MEMBERSHIP
|--------------------------------------------------------------------------
*/

app.post(
  "/api/v1/users/:discordId/evidence",
  {
    preHandler:
      requireRole([
        "ADMIN",
        "ANALYST"
      ])
  },
  async (
    req: any,
    reply
  ) => {
    const {
      discordId
    } =
      z.object({
        discordId:
          discordIdSchema
      })
      .parse(
        req.params
      );

    const body =
      z.object({
        serverDiscordId:
          discordIdSchema,

        observedAt:
          z.coerce.date(),

        endedAt:
          z.coerce
            .date()
            .optional(),

        confidence:
          z
            .enum([
              "UNVERIFIED",
              "LOW",
              "MEDIUM",
              "HIGH",
              "CONFIRMED"
            ])
            .default(
              "HIGH"
            ),

        roleNames:
          z
            .array(
              z
                .string()
                .max(100)
            )
            .default([])
      })
      .parse(
        req.body
      );

    const server =
      await prisma.discordServer.findUnique({
        where: {
          discordId:
            body.serverDiscordId
        }
      });

    if (!server) {
      return reply
        .code(400)
        .send({
          error:
            "Unknown community"
        });
    }

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

    const existing =
      await prisma.evidence.findFirst({
        where: {
          userId:
            user.id,

          serverId:
            server.id
        }
      });

    if (existing) {
      return reply
        .code(409)
        .send({
          error:
            "Association already exists"
        });
    }

    const evidence =
      await prisma.evidence.create({
        data: {
          userId:
            user.id,

          serverId:
            server.id,

          sourceType:
            "INTERNAL_MODERATION_RECORD",

          sourceRef:
            "Dashboard membership entry",

          observedAt:
            body.observedAt,

          endedAt:
            body.endedAt,

          confidence:
            body.confidence,

          roleNames:
            body.roleNames,

          createdBy:
            req.staffUser.username
        },

        include: {
          server: {
            include: {
              subject:
                true
            }
          }
        }
      });

    return reply
      .code(201)
      .send(
        evidence
      );
  }
);

/*
|--------------------------------------------------------------------------
| ERROR HANDLER
|--------------------------------------------------------------------------
*/

app.setErrorHandler(
  (
    err,
    req,
    reply
  ) => {
    if (
      err instanceof
      z.ZodError
    ) {
      return reply
        .code(400)
        .send({
          error:
            "Validation failed",

          details:
            err.flatten()
        });
    }

    req.log.error(err);

    return reply
      .code(500)
      .send({
        error:
          "Internal server error"
      });
  }
);

/*
|--------------------------------------------------------------------------
| START
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

await bootstrapAdmin();

await app.listen({
  port,
  host
});
