import { describe, expect, it } from "vitest";
import {
  canChangeMemberRole,
  canInviteRole,
  canRemoveMember,
  canRevokeInvite,
  normalizeInviteEmail,
  parseInvitableRole,
  seatUsage,
} from "../src/collaboration";

describe("workspace collaboration policy", () => {
  it("normalizes invite email addresses", () => {
    expect(normalizeInviteEmail("  PERSON@Example.COM ")).toBe("person@example.com");
  });

  it("rejects malformed invite email addresses", () => {
    expect(() => normalizeInviteEmail("not-an-email")).toThrow(/valid email/);
  });

  it("defaults invites to member and rejects owner invitations", () => {
    expect(parseInvitableRole(undefined)).toBe("member");
    expect(parseInvitableRole("admin")).toBe("admin");
    expect(() => parseInvitableRole("owner")).toThrow(/admin or member/);
  });

  it("lets owners invite admins or members", () => {
    expect(canInviteRole("owner", "admin")).toBe(true);
    expect(canInviteRole("owner", "member")).toBe(true);
  });

  it("lets admins invite members but not admins", () => {
    expect(canInviteRole("admin", "member")).toBe(true);
    expect(canInviteRole("admin", "admin")).toBe(false);
    expect(canInviteRole("member", "member")).toBe(false);
  });

  it("uses the same boundary for revoking invites", () => {
    expect(canRevokeInvite("admin", "member")).toBe(true);
    expect(canRevokeInvite("admin", "admin")).toBe(false);
  });

  it("reserves pending invitations against the plan seat limit", () => {
    expect(seatUsage(1, 1, 3)).toEqual({ used: 1, reserved: 1, limit: 3, available: 1, full: false });
    expect(seatUsage(1, 2, 3)).toEqual({ used: 1, reserved: 2, limit: 3, available: 0, full: true });
  });

  it("allows only owners to change non-owner member roles", () => {
    expect(canChangeMemberRole("owner", "member", "admin")).toBe(true);
    expect(canChangeMemberRole("owner", "admin", "member")).toBe(true);
    expect(canChangeMemberRole("admin", "member", "admin")).toBe(false);
    expect(canChangeMemberRole("owner", "owner", "admin")).toBe(false);
  });

  it("protects owners and self-removal while letting admins remove members", () => {
    expect(canRemoveMember("owner", "admin", false)).toBe(true);
    expect(canRemoveMember("admin", "member", false)).toBe(true);
    expect(canRemoveMember("admin", "admin", false)).toBe(false);
    expect(canRemoveMember("owner", "owner", false)).toBe(false);
    expect(canRemoveMember("admin", "member", true)).toBe(false);
  });
});
