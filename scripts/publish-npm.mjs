import { execFileSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const manifest = JSON.parse(execFileSync(process.execPath, ["-p", "JSON.stringify(require('./package.json'))"], { cwd: root, encoding: "utf8" }));
const expectedTag = `v${manifest.version}`;
const releaseTag = process.env.RELEASE_TAG;
if (
  process.env.GITHUB_ACTIONS !== "true" ||
  !process.env.ACTIONS_ID_TOKEN_REQUEST_URL ||
  process.env.GITHUB_REF_TYPE !== "tag" ||
  process.env.GITHUB_REF_NAME !== expectedTag ||
  releaseTag !== expectedTag
) {
  throw new Error("npm publication is restricted to the matching GitHub release tag with OIDC");
}
const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
const tagCommit = execFileSync("git", ["rev-parse", `${releaseTag}^{commit}`], { cwd: root, encoding: "utf8" }).trim();
if (!process.env.GITHUB_SHA || head !== process.env.GITHUB_SHA || tagCommit !== head) {
  throw new Error("release tag does not resolve to the event commit");
}

const target = mkdtempSync(join(tmpdir(), "totp-recovery-publish-"));
try {
  const output = execFileSync("npm", ["pack", "--json", "--pack-destination", target], {
    cwd: root,
    encoding: "utf8",
  });
  const parsed = JSON.parse(output);
  const packed = Array.isArray(parsed) ? parsed[0] : Object.values(parsed)[0];
  if (packed.name !== manifest.name || packed.version !== manifest.version) throw new Error("package identity mismatch");
  const response = await fetch(
    `https://registry.npmjs.org/${encodeURIComponent(manifest.name)}/${encodeURIComponent(manifest.version)}`,
  );
  if (response.ok) {
    const existing = await response.json();
    if (existing.dist?.integrity !== packed.integrity) throw new Error("existing npm version integrity mismatch");
    console.log(`${manifest.name}@${manifest.version}: existing registry integrity verified`);
  } else if (response.status === 404) {
    execFileSync("npm", ["publish", join(target, packed.filename), "--access", "public", "--provenance"], {
      cwd: root,
      stdio: "inherit",
    });
  } else {
    throw new Error(`npm registry HTTP ${response.status}`);
  }
} finally {
  rmSync(target, { force: true, recursive: true });
}
