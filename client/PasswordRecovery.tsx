import { useState } from "react";
import type { FormEvent } from "react";
import { authClient } from "./auth-client";
import "./password-recovery.css";

function RecoveryShell({ children }: { children: React.ReactNode }) {
  return <main className="recovery-shell"><section className="recovery-card"><a className="recovery-brand" href="/">ContextGateway</a>{children}</section></main>;
}

export function ForgotPasswordEntry() {
  const { data: session, isPending } = authClient.useSession();
  if (isPending || session?.user || window.location.pathname !== "/") return null;
  return <a className="forgot-password-entry" href="/forgot-password">Forgot password?</a>;
}

function ForgotPasswordPage() {
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [sent, setSent] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    setError("");
    const result = await authClient.requestPasswordReset({
      email,
      redirectTo: `${window.location.origin}/reset-password`,
    });
    setBusy(false);
    if (result.error) {
      setError("Could not submit the reset request. Please try again.");
      return;
    }
    setSent(true);
  }

  return <RecoveryShell>
    <span className="recovery-kicker">ACCOUNT RECOVERY</span>
    <h1>Forgot your password?</h1>
    {sent ? <>
      <div className="recovery-success"><strong>Check your email.</strong><p>If an account exists for <b>{email}</b>, a reset link has been sent. The link expires in 30 minutes.</p></div>
      <a className="recovery-primary-link" href="/">Back to sign in</a>
    </> : <>
      <p>Enter the email address used for your ContextGateway account. For privacy, the response is the same whether or not the account exists.</p>
      <form onSubmit={submit}>
        <label>Email<input type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="email" required autoFocus /></label>
        {error && <div className="recovery-error">{error}</div>}
        <button className="recovery-primary" disabled={busy}>{busy ? "Sending…" : "Send reset link"}</button>
      </form>
      <a className="recovery-secondary-link" href="/">Back to sign in</a>
    </>}
  </RecoveryShell>;
}

function ResetPasswordPage() {
  const params = new URLSearchParams(window.location.search);
  const token = params.get("token");
  const invalid = params.get("error") === "INVALID_TOKEN" || !token;
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [complete, setComplete] = useState(false);
  const [error, setError] = useState("");

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!token) return;
    if (password.length < 12) {
      setError("Password must be at least 12 characters.");
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }
    setBusy(true);
    setError("");
    const result = await authClient.resetPassword({ newPassword: password, token });
    setBusy(false);
    if (result.error) {
      setError("This reset link is invalid or expired. Request a new one.");
      return;
    }
    window.history.replaceState({}, "", "/reset-password");
    setComplete(true);
  }

  return <RecoveryShell>
    <span className="recovery-kicker">SECURE PASSWORD RESET</span>
    <h1>{complete ? "Password updated" : "Choose a new password"}</h1>
    {complete ? <>
      <div className="recovery-success"><strong>Your password has been changed.</strong><p>Other active sessions were revoked as a security precaution. Sign in again with your new password.</p></div>
      <a className="recovery-primary-link" href="/">Sign in</a>
    </> : invalid ? <>
      <div className="recovery-error">This password reset link is invalid or has expired.</div>
      <a className="recovery-primary-link" href="/forgot-password">Request a new reset link</a>
    </> : <>
      <p>Use at least 12 characters. The reset link can be used only while its token is valid.</p>
      <form onSubmit={submit}>
        <label>New password<input type="password" minLength={12} value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required autoFocus /></label>
        <label>Confirm new password<input type="password" minLength={12} value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} autoComplete="new-password" required /></label>
        {error && <div className="recovery-error">{error}</div>}
        <button className="recovery-primary" disabled={busy}>{busy ? "Updating…" : "Reset password"}</button>
      </form>
    </>}
  </RecoveryShell>;
}

export function PasswordRecoveryRouter({ app }: { app: React.ReactNode }) {
  if (window.location.pathname === "/forgot-password") return <ForgotPasswordPage />;
  if (window.location.pathname === "/reset-password") return <ResetPasswordPage />;
  return <>{app}<ForgotPasswordEntry /></>;
}
