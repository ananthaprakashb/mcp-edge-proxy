export interface McpOperation {
  method: string | null;
  name: string | null;
}

function stringField(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

export async function extractMcpOperation(request: Request): Promise<McpOperation> {
  let method = stringField(request.headers.get("Mcp-Method"));
  let name = stringField(request.headers.get("Mcp-Name"));

  if (method) return { method, name };

  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.toLowerCase().includes("application/json")) return { method, name };

  try {
    const body = (await request.clone().json()) as Record<string, unknown>;
    method = stringField(body.method);
    if (!name && body.params && typeof body.params === "object") {
      const params = body.params as Record<string, unknown>;
      name = stringField(params.name);
    }
  } catch {
    // A malformed or non-JSON body will fail closed later because method remains null.
  }

  return { method, name };
}
