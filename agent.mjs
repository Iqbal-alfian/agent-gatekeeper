// Vercel serverless entry for the Proof Gatekeeper agent.
// Register the deployed URL of this function (…/api/agent) as the agent endpoint.
import { handlePost, signResponse } from "../lib/gatekeeper.mjs";

export const config = { api: { bodyParser: false }, maxDuration: 60 };

async function readRaw(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString("utf8");
}

export default async function handler(req, res) {
  if (req.method === "GET") {
    res.status(200).json({ ok: true, agent: "proof-gatekeeper", version: "v1" });
    return;
  }
  if (req.method !== "POST") {
    res.status(405).end();
    return;
  }
  const raw = await readRaw(req);
  try {
    const { status, body } = await handlePost(raw, req.headers["x-agent-games-signature"]);
    const out = JSON.stringify(body);
    res.setHeader("x-agent-games-signature", signResponse(out));
    res.status(status).send(out);
  } catch {
    const out = JSON.stringify({ decision: "REJECT", reason_code: "INTERNAL_ERROR" });
    res.setHeader("x-agent-games-signature", signResponse(out));
    res.status(200).send(out);
  }
}
