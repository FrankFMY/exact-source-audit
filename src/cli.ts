#!/usr/bin/env node
import { createHash, randomUUID } from "node:crypto";
import { chmod, readFile, rename, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import { buildCycloneDx, parseIndexEntries, scanSecretText } from "./index.js";

const requiredFlag = (args: string[], name: string): string => {
  const index = args.indexOf(name);
  const value = index >= 0 ? args[index + 1] : null;
  if (!value) throw new Error(`Missing required flag: ${name}`);
  return value;
};

const runGit = async (cwd: string, args: string[]): Promise<string> => {
  const child = Bun.spawn(["git", "--no-replace-objects", ...args], { cwd, stderr: "pipe", stdout: "pipe" });
  const [exitCode, stdout] = await Promise.all([child.exited, new Response(child.stdout).text()]);
  if (exitCode !== 0) throw new Error(`Git command failed: ${args[0] ?? "unknown"}`);
  return stdout;
};

const runGitBytes = async (cwd: string, args: string[]): Promise<Uint8Array> => {
  const child = Bun.spawn(["git", "--no-replace-objects", ...args], { cwd, stderr: "pipe", stdout: "pipe" });
  const [exitCode, stdout] = await Promise.all([child.exited, new Response(child.stdout).arrayBuffer()]);
  if (exitCode !== 0) throw new Error(`Git command failed: ${args[0] ?? "unknown"}`);
  return new Uint8Array(stdout);
};

const run = async (args: string[]): Promise<void> => {
  const [command, ...rest] = args;
  if (command === "sbom") {
    const root = resolve(requiredFlag(rest, "--root"));
    const revision = requiredFlag(rest, "--revision");
    const output = resolve(requiredFlag(rest, "--output"));
    const lockText = await readFile(resolve(root, "bun.lock"), "utf8");
    const bom = buildCycloneDx(lockText, revision);
    const temporary = `${output}.tmp-${process.pid}-${randomUUID()}`;
    try {
      await writeFile(temporary, `${JSON.stringify(bom, null, 2)}
`, { mode: 0o600 });
      await rename(temporary, output);
      await chmod(output, 0o600);
    } finally {
      await Bun.file(temporary).delete().catch(() => undefined);
    }
    console.log(JSON.stringify({ components: bom.components.length, output, status: "sbom_written" }));
    return;
  }
  if (command === "secrets") {
    const root = resolve(requiredFlag(rest, "--root"));
    const indexSnapshot = await runGit(root, ["ls-files", "--stage", "-z"]);
    const entries = parseIndexEntries(indexSnapshot);
    const indexDigest = createHash("sha256").update(indexSnapshot).digest("hex");
    const findings = [];
    const blobCache = new Map<string, Uint8Array>();
    for (const entry of entries) {
      let bytes = blobCache.get(entry.oid);
      if (!bytes) {
        bytes = await runGitBytes(root, ["cat-file", "blob", entry.oid]);
        blobCache.set(entry.oid, bytes);
      }
      if (bytes.includes(0)) continue;
      let text: string;
      try {
        text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch {
        continue;
      }
      findings.push(...scanSecretText(entry.path, text));
    }
    const finalSnapshot = await runGit(root, ["ls-files", "--stage", "-z"]);
    if (finalSnapshot !== indexSnapshot) throw new Error("Git index changed during secret scan");
    console.log(JSON.stringify({ files: entries.length, findings, indexDigest, status: findings.length ? "findings" : "clean" }));
    if (findings.length) process.exitCode = 1;
    return;
  }
  throw new Error("Usage: source-audit <sbom --root DIR --revision SHA --output FILE | secrets --root DIR>");
};

await run(Bun.argv.slice(2)).catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : "Source audit failed");
  process.exitCode = 1;
});
