// Local dev server for the Proof Gatekeeper agent (testing only).
import { createServer } from "node:http";
import { handlePost, signResponse } from "./lib/gatekeeper.mjs";

const PORT = process.env.PORT || 8791;

const server = createServer(async (req, res) => {
  if (req.method === "GET") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, agent: "proof-gatekeeper", version: "v1" }));
    return;
  }
  if (req.method !== "POST") {
    res.writeHead(405).end();
    return;
  }
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const raw = Buffer.concat(chunks).toString("utf8");
  try {
    const { status, body } = await handlePost(raw, req.headers["x-agent-games-signature"]);
    const out = JSON.stringify(body);
    res.writeHead(status, {
      "content-type": "application/json",
      "x-agent-games-signature": signResponse(out),
    });
    res.end(out);
  } catch (e) {
    // Fail closed with a signed REJECT rather than silence.
    const out = JSON.stringify({ decision: "REJECT", reason_code: "INTERNAL_ERROR" });
    res.writeHead(200, {
      "content-type": "application/json",
      "x-agent-games-signature": signResponse(out),
    });
    res.end(out);
  }
});

server.listen(PORT, () => console.log(`gatekeeper listening on :${PORT}`));
