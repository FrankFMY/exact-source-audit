import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const target = mkdtempSync(join(tmpdir(), "exact-source-audit-consumer-"));

try {
  const output = execFileSync("npm", ["pack", "--silent", "--pack-destination", target], {
    cwd: root,
    encoding: "utf8",
  }).trim();
  const tarball = join(target, output.split("\n").at(-1));
  writeFileSync(join(target, "package.json"), '{"name":"exact-source-audit-consumer","private":true,"type":"module"}\n');
  execFileSync("npm", ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball], {
    cwd: target,
    stdio: "pipe",
  });
  const manifest = JSON.parse(readFileSync(join(target, "node_modules/@frankfmy/exact-source-audit/package.json"), "utf8"));
  if (manifest.bin?.["source-audit"] !== "dist/cli.js") throw new Error("installed bin contract failed");
  const fixture = join(target, "fixture");
  execFileSync("mkdir", ["-p", fixture]);
  execFileSync("git", ["init", "-q"], { cwd: fixture });
  writeFileSync(join(fixture, "safe.txt"), "safe\n");
  execFileSync("git", ["add", "safe.txt"], { cwd: fixture });
  const cliOutput = execFileSync(join(target, "node_modules/.bin/source-audit"), ["secrets", "--root", fixture], {
    cwd: target,
    encoding: "utf8",
  });
  const result = JSON.parse(cliOutput);
  if (result.status !== "clean" || result.files !== 1) throw new Error("installed CLI smoke failed");
  writeFileSync(
    join(target, "check.mjs"),
    'import("@frankfmy/exact-source-audit").then((module) => { if (module.scanSecretText("safe.txt", "safe").length !== 0) process.exit(1); });\n',
  );
  execFileSync(process.execPath, [join(target, "check.mjs")], { cwd: target, stdio: "inherit" });
  console.log("isolated exact-source-audit package/bin: PASS");
} finally {
  rmSync(target, { force: true, recursive: true });
}
