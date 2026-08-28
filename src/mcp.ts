export interface McpOperation {
  method: string | null;
  name: string | null;
  arguments: unknown;
  hasArguments: boolean;
  consistent: boolean;
}

function stringField(value: unknown): string | null {
  return typeof value === "string" && value.length > 0 ? value : null;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

export async function extractMcpOperation(request: Request): Promise<McpOperation> {
  const headerMethod = stringField(request.headers.get("Mcp-Method"));
  const headerName = stringField(request.headers.get("Mcp-Name"));
  let bodyMethod: string | null = null;
  let bodyName: string | null = null;
  let argumentsValue: unknown = undefined;
  let hasArguments = false;
  let parsedBody = false;

  const contentType = request.headers.get("content-type") ?? "";
  if (contentType.toLowerCase().includes("application/json")) {
    try {
      const body = (await request.clone().json()) as unknown;
      if (isRecord(body)) {
        parsedBody = true;
        bodyMethod = stringField(body.method);
        if (isRecord(body.params)) {
          bodyName = stringField(body.params.name);
          if (Object.prototype.hasOwnProperty.call(body.params, "arguments")) {
            argumentsValue = body.params.arguments;
            hasArguments = true;
          }
        }
      }
    } catch {
      // Malformed JSON will fail closed through a missing operation or upstream parsing.
    }
  }

  const consistent = !(
    (headerMethod && bodyMethod && headerMethod !== bodyMethod)
    || (headerName && bodyName && headerName !== bodyName)
  );

  return {
    method: headerMethod ?? bodyMethod,
    name: headerName ?? bodyName,
    arguments: argumentsValue,
    hasArguments,
    consistent: parsedBody ? consistent : true,
  };
}
