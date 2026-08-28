import { handleAppApi } from "./app-api";
import { createAuth } from "./auth";
import edgeWorker from "./index";
import type { Env, ExecutionContextLike } from "./types";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContextLike): Promise<Response> {
    const path = new URL(request.url).pathname;

    if (path.startsWith("/api/auth/")) {
      return createAuth(env, request).handler(request);
    }

    if (path.startsWith("/v1/app/")) {
      return handleAppApi(request, env, path);
    }

    return edgeWorker.fetch(request, env, ctx);
  },
};
