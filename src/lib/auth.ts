import type { FastifyRequest, FastifyReply } from "fastify";

export async function requireApiKey(req: FastifyRequest, reply: FastifyReply) {
  const expected = process.env.API_KEY;
  const provided = req.headers["x-api-key"];

  if (!expected) {
    return reply.code(500).send({ error: "Server API key is not configured" });
  }

  if (provided !== expected) {
    return reply.code(401).send({ error: "Unauthorized" });
  }
}
