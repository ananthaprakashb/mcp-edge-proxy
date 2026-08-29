import { handleAuditApi } from "./audit-api";
import { handleContextAccessApi } from "./context-access-api";
import { handleContextApi } from "./context-api";
import { handleGovernedContextMcp } from "./context-mcp";
import { runScheduledGatewayHealthChecks } from "./gateway-health";
import { handleHealthApi } from "./health-api";
import { runRetentionLifecycle } from "./retention";
import worker from "./worker";
import type { Env, ExecutionContextLike, ScheduledControllerLike } from "./types";

const RETENTION_CRON = "17 8 * * *";
const HEALTH_CRON = "*/15 * * * *";

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContextLike): Promise<Response> {
    const path = new URL(request.url).pathname;
    if (path.startsWith("/v1/app/workspaces/")) {
      const accessResponse = await handleContextAccessApi(request, env, path);
      if (accessResponse) return accessResponse;
      const contextResponse = await handleContextApi(request, env, path);
      if (contextResponse) return contextResponse;
      const healthResponse = await handleHealthApi(request, env, path);
      if (healthResponse) return healthResponse;
      const auditResponse = await handleAuditApi(request, env, path);
      if (auditResponse) return auditResponse;
    }

    const mcpMatch = /^\/v1\/mcp\/([^/]+)$/.exec(path);
    if (mcpMatch) {
      const governed = await handleGovernedContextMcp(request, env, ctx, decodeURIComponent(mcpMatch[1]));
      if (governed) return governed;
    }

    return worker.fetch(request, env, ctx);
  },

  async scheduled(controller: ScheduledControllerLike, env: Env, ctx: ExecutionContextLike): Promise<void> {
    if (controller.cron === HEALTH_CRON) {
      ctx.waitUntil(runScheduledGatewayHealthChecks(env).then(() => undefined));
      return;
    }

    if (controller.cron === RETENTION_CRON) {
      ctx.waitUntil((async () => {
        const results = await runRetentionLifecycle(env.DB, {
          triggerType: "scheduled",
          scheduledTime: controller.scheduledTime,
        });
        const failed = results.filter((result) => result.status === "failed");
        if (failed.length) {
          throw new Error(`Retention cleanup failed for ${failed.length} account(s)`);
        }
      })());
      return;
    }

    controller.noRetry?.();
  },
};
