import http from "node:http";

const port = Number(process.env.PORT || 8789);
const server = http.createServer(async (req, res) => {
  if (req.url === "/healthz") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
    return;
  }

  if (req.url !== "/mcp" || req.method !== "POST") {
    res.writeHead(404, { "content-type": "application/json" });
    res.end(JSON.stringify({ error: "not_found" }));
    return;
  }

  let raw = "";
  for await (const chunk of req) raw += chunk;
  let body = null;
  try { body = raw ? JSON.parse(raw) : null; } catch { body = raw; }

  const response = {
    ok: true,
    service: "contextgateway-private-echo",
    method: req.headers["mcp-method"] || body?.method || null,
    name: req.headers["mcp-name"] || body?.params?.name || null,
  };

  res.writeHead(200, {
    "content-type": "application/json",
    "cache-control": "no-store",
  });
  res.end(JSON.stringify(response));
});

server.listen(port, "127.0.0.1", () => {
  console.log(`Private MCP echo listening on http://127.0.0.1:${port}/mcp`);
});
