import { parse as parseYaml } from "yaml";
import { sha256Hex } from "./crypto";

export type ContextDocumentFormat = "json" | "yaml" | "markdown" | "text" | "okf";

export interface ParsedContextDocument {
  format: ContextDocumentFormat;
  contentHash: string;
  byteSize: number;
  normalized: unknown;
  normalizedJson: string;
  topLevelKeys: string[];
}

export const MAX_CONTEXT_DOCUMENT_BYTES = 256 * 1024;

function assertJsonCompatible(value: unknown, path = "$"): void {
  if (value === null || typeof value === "string" || typeof value === "boolean") return;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error(`Non-finite number at ${path}`);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertJsonCompatible(item, `${path}[${index}]`));
    return;
  }
  if (value && typeof value === "object") {
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      assertJsonCompatible(child, `${path}.${key}`);
    }
    return;
  }
  throw new Error(`Unsupported value at ${path}`);
}

function markdownSlug(value: string): string {
  return value
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "") || "section";
}

function normalizeMarkdown(content: string): Record<string, unknown> {
  const sections: Record<string, { heading: string; level: number; text: string }> = {};
  const intro: string[] = [];
  let current: { slug: string; heading: string; level: number; lines: string[] } | null = null;

  const flush = () => {
    if (!current) return;
    let slug = current.slug;
    let suffix = 2;
    while (sections[slug]) slug = `${current.slug}-${suffix++}`;
    sections[slug] = {
      heading: current.heading,
      level: current.level,
      text: current.lines.join("\n").trim(),
    };
  };

  for (const line of content.replace(/\r\n?/g, "\n").split("\n")) {
    const match = /^(#{1,6})\s+(.+?)\s*$/.exec(line);
    if (match) {
      flush();
      const heading = match[2].trim();
      current = { slug: markdownSlug(heading), heading, level: match[1].length, lines: [] };
    } else if (current) {
      current.lines.push(line);
    } else {
      intro.push(line);
    }
  }
  flush();

  return {
    intro: intro.join("\n").trim(),
    sections,
  };
}

function parseStructured(format: ContextDocumentFormat, content: string): unknown {
  if (format === "json") return JSON.parse(content) as unknown;
  if (format === "yaml") return parseYaml(content) as unknown;
  if (format === "okf") {
    let parsed: unknown;
    try {
      parsed = JSON.parse(content) as unknown;
    } catch {
      parsed = parseYaml(content) as unknown;
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("OKF content must be a structured object");
    }
    return parsed;
  }
  throw new Error(`Unsupported structured format: ${format}`);
}

export function parseContextDocumentFormat(value: unknown): ContextDocumentFormat {
  if (value === "json" || value === "yaml" || value === "markdown" || value === "text" || value === "okf") return value;
  throw new Error("format must be one of: json, yaml, markdown, text, okf");
}

export async function parseContextDocument(format: ContextDocumentFormat, content: string): Promise<ParsedContextDocument> {
  if (!content.trim()) throw new Error("content must not be empty");
  const byteSize = new TextEncoder().encode(content).byteLength;
  if (byteSize > MAX_CONTEXT_DOCUMENT_BYTES) {
    throw new Error(`content exceeds the ${MAX_CONTEXT_DOCUMENT_BYTES} byte document limit`);
  }

  const normalized = format === "markdown"
    ? normalizeMarkdown(content)
    : format === "text"
      ? { text: content }
      : parseStructured(format, content);
  assertJsonCompatible(normalized);
  const normalizedJson = JSON.stringify(normalized);
  const topLevelKeys = normalized && typeof normalized === "object" && !Array.isArray(normalized)
    ? Object.keys(normalized as Record<string, unknown>).sort()
    : [];

  return {
    format,
    contentHash: await sha256Hex(content),
    byteSize,
    normalized,
    normalizedJson,
    topLevelKeys,
  };
}

export function normalizeDocumentKey(value: unknown): string {
  if (typeof value !== "string") throw new Error("documentKey must be a string");
  const key = value.trim().toLowerCase();
  if (!/^[a-z0-9][a-z0-9._-]{0,95}$/.test(key)) {
    throw new Error("documentKey must be 1-96 lowercase letters, numbers, dots, underscores, or hyphens");
  }
  return key;
}

export function normalizeAllowedPaths(value: unknown): string[] {
  if (value === undefined) return ["*"];
  if (!Array.isArray(value) || value.length === 0 || value.length > 64) {
    throw new Error("allowedPaths must be a non-empty array with at most 64 entries");
  }
  const paths = value.map((item) => {
    if (typeof item !== "string") throw new Error("allowedPaths entries must be strings");
    const path = item.trim();
    if (path === "*") return path;
    if (!path.startsWith("/") || path.length > 300 || /[\r\n]/.test(path)) {
      throw new Error("allowedPaths entries must be * or JSON-pointer-style paths beginning with /");
    }
    return path;
  });
  return [...new Set(paths)];
}

export function normalizeAllowedOperations(value: unknown): Array<"read" | "list"> {
  if (value === undefined) return ["read", "list"];
  if (!Array.isArray(value) || value.length === 0) throw new Error("allowedOperations must be a non-empty array");
  const operations = value.map((item) => {
    if (item !== "read" && item !== "list") throw new Error("allowedOperations entries must be read or list");
    return item;
  });
  return [...new Set(operations)];
}

function decodePointerSegment(value: string): string {
  return value.replace(/~1/g, "/").replace(/~0/g, "~");
}

export function readJsonPointer(value: unknown, pointer: string | null): unknown {
  if (!pointer || pointer === "/") return value;
  if (!pointer.startsWith("/")) throw new Error("path must be a JSON-pointer-style path beginning with /");
  let current: unknown = value;
  for (const segment of pointer.slice(1).split("/").map(decodePointerSegment)) {
    if (Array.isArray(current)) {
      if (!/^\d+$/.test(segment)) throw new Error("path does not exist");
      const index = Number(segment);
      if (index < 0 || index >= current.length) throw new Error("path does not exist");
      current = current[index];
    } else if (current && typeof current === "object" && Object.prototype.hasOwnProperty.call(current, segment)) {
      current = (current as Record<string, unknown>)[segment];
    } else {
      throw new Error("path does not exist");
    }
  }
  return current;
}

export function pathAllowed(allowedPaths: string[], requestedPath: string | null): boolean {
  if (allowedPaths.includes("*")) return true;
  if (!requestedPath) return false;
  return allowedPaths.some((rule) => {
    if (rule.endsWith("/*")) {
      const prefix = rule.slice(0, -2);
      return requestedPath === prefix || requestedPath.startsWith(`${prefix}/`);
    }
    return requestedPath === rule;
  });
}
