import { describe, expect, test } from "bun:test";
import { chmod, mkdtemp, readFile, rm, stat, symlink, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

const cli = new URL("../src/cli.ts", import.meta.url).pathname;
const runCommand = async (command: string[], cwd: string): Promise<string> => {
  const child = Bun.spawn(command, { cwd, stderr: "pipe", stdout: "pipe" });
  const [exitCode, stdout] = await Promise.all([child.exited, new Response(child.stdout).text()]);
  if (exitCode !== 0) throw new Error(`Command failed: ${command[0]}`);
  return stdout;
};

const runSecrets = async (root: string) => {
  const child = Bun.spawn(["bun", cli, "secrets", "--root", root], { stderr: "pipe", stdout: "pipe" });
  const [exitCode, stdout] = await Promise.all([child.exited, new Response(child.stdout).text()]);
  return { exitCode, stdout };
};

describe("source-audit CLI", () => {
  test("fails closed on a missing indexed blob without activating a promisor helper", async () => {
    const directory = await mkdtemp(join(tmpdir(), "source-audit-promisor-"));
    try {
      await runCommand(["git", "init", "-q"], directory);
      await writeFile(join(directory, "tracked.txt"), "owned fixture\n");
      await runCommand(["git", "add", "tracked.txt"], directory);
      const oid = (await runCommand(["git", "rev-parse", ":tracked.txt"], directory)).trim();
      const marker = join(directory, "helper-executed");
      const helper = join(directory, "helper.sh");
      await writeFile(helper, `#!/bin/sh\nprintf executed > '${marker}'\nexit 1\n`);
      await chmod(helper, 0o755);
      await runCommand(["git", "remote", "add", "origin", `ext::${helper}`], directory);
      await runCommand(["git", "config", "remote.origin.promisor", "true"], directory);
      await runCommand(["git", "config", "remote.origin.partialclonefilter", "blob:none"], directory);
      await runCommand(["git", "config", "protocol.ext.allow", "always"], directory);
      await unlink(join(directory, ".git", "objects", oid.slice(0, 2), oid.slice(2)));
      const result = await runSecrets(directory);
      expect(result.exitCode).toBe(1);
      expect(await Bun.file(marker).exists()).toBe(false);
    } finally { await rm(directory, { force: true, recursive: true }); }
  });

  test("reads exact index blobs, ignores untracked content, and does not follow symlinks", async () => {
    const directory = await mkdtemp(join(tmpdir(), "source-audit-index-"));
    const outside = await mkdtemp(join(tmpdir(), "source-audit-outside-"));
    const token = `ghp_${"B".repeat(36)}`;
    try {
      await runCommand(["git", "init", "-q"], directory);
      await writeFile(join(directory, "tracked.env"), `GITHUB_TOKEN=${token}
`);
      await writeFile(join(directory, "untracked.env"), `GITHUB_TOKEN=ghp_${"C".repeat(36)}
`);
      const target = join(outside, "outside.env");
      await writeFile(target, `GITHUB_TOKEN=ghp_${"D".repeat(36)}
`);
      await symlink(target, join(directory, "tracked-link"));
      await runCommand(["git", "add", "tracked.env", "tracked-link"], directory);
      const detected = await runSecrets(directory);
      expect(detected.exitCode).toBe(1);
      expect(JSON.parse(detected.stdout)).toMatchObject({ files: 2, findings: [{ detector: "github_token", path: "tracked.env" }], status: "findings" });
      expect(detected.stdout).not.toContain(token);
      expect(detected.stdout).not.toContain("C".repeat(36));
      expect(detected.stdout).not.toContain("D".repeat(36));
    } finally {
      await rm(directory, { force: true, recursive: true });
      await rm(outside, { force: true, recursive: true });
    }
  });

  test("writes a private deterministic SBOM artifact", async () => {
    const directory = await mkdtemp(join(tmpdir(), "source-audit-sbom-"));
    try {
      await writeFile(join(directory, "bun.lock"), `{"lockfileVersion":3,"configVersion":1,"workspaces":{"":{"name":"fixture"}},"packages":{}}`);
      const output = join(directory, "sbom.json");
      const child = Bun.spawn(["bun", cli, "sbom", "--root", directory, "--revision", "e".repeat(40), "--output", output], {
        stderr: "pipe",
        stdout: "pipe",
      });
      expect(await child.exited).toBe(0);
      expect(JSON.parse(await readFile(output, "utf8"))).toMatchObject({ bomFormat: "CycloneDX", specVersion: "1.6" });
      expect((await stat(output)).mode & 0o777).toBe(0o600);
    } finally {
      await rm(directory, { force: true, recursive: true });
    }
  });

  test("keeps non-UTF-8 Git paths distinct in index digests and findings", async () => {
    const directories = [await mkdtemp(join(tmpdir(), "source-audit-byte-path-a-")), await mkdtemp(join(tmpdir(), "source-audit-byte-path-b-"))];
    try {
      const outputs = [];
      for (const [index, directory] of directories.entries()) {
        await runCommand(["git", "init", "-q"], directory);
        const path = Buffer.concat([Buffer.from(`${directory}/`), Buffer.from([0x80 + index])]);
        await writeFile(path, `GITHUB_TOKEN=ghp_${"E".repeat(36)}\n`);
        await runCommand(["git", "add", "--all"], directory);
        const result = await runSecrets(directory);
        expect(result.exitCode).toBe(1);
        outputs.push(JSON.parse(result.stdout));
      }
      expect(outputs[0].indexDigest).not.toBe(outputs[1].indexDigest);
      expect(outputs[0].findings[0].path).toBe("git-path-bytes:80");
      expect(outputs[1].findings[0].path).toBe("git-path-bytes:81");
    } finally {
      await Promise.all(directories.map((directory) => rm(directory, { force: true, recursive: true })));
    }
  });
});
