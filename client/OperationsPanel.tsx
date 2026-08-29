import { GatewayHealthPanel } from "./GatewayHealthPanel";
import { SecurityPanel } from "./SecurityPanel";

type WorkspaceRole = "owner" | "admin" | "member";

type Props = {
  workspace: { id: string; role: WorkspaceRole; plan: "free" | "pro" | "team" };
};

export function OperationsPanel({ workspace }: Props) {
  return <div className="stack-lg">
    <div className="page-intro-card">
      <div>
        <span className="kicker">OPERATIONS</span>
        <h2>Health, credentials, audit, and retention</h2>
        <p>Use this workspace to diagnose upstream connectivity, rotate secrets, review security events, verify audit integrity, and run retention controls.</p>
      </div>
      <div className="privacy-chip">Metadata-first operations</div>
    </div>
    <GatewayHealthPanel workspace={workspace} />
    <SecurityPanel workspace={workspace} />
  </div>;
}
