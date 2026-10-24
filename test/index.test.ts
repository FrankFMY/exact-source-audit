import { describe, expect, test } from "bun:test";
import { buildCycloneDx, parseIndexEntries, scanSecretText } from "../src/index.js";

const lockFixture = `{
  "lockfileVersion": 3,
  "configVersion": 1,
  "workspaces": {
    "": { "name": "workspace-root" },
    "server": { "name": "@example/server" }
  },
  "packages": {
    "zeta": ["zeta@1.0.0", "", {}, "sha512-${Buffer.alloc(64, 1).toString("base64")}"],
    "zeta-copy": ["zeta@1.0.0", "", {}, "sha512-${Buffer.alloc(64, 1).toString("base64")}"],
    "@scope/alpha": ["@scope/alpha@2.0.0", "", {}, "sha512-${Buffer.alloc(64, 2).toString("base64")}"],
    "@example/server": ["@example/server@workspace:server"]
  }
}`;

describe("exact source audit", () => {
  test("rejects object identifiers that are neither SHA-1 nor SHA-256", () => {
    const snapshot = new TextEncoder().encode(`100644 ${"a".repeat(41)} 0\tfile.txt\0`);
    expect(() => parseIndexEntries(snapshot)).toThrow("Unsupported");
  });

  test("orders SBOM components independently of locale collation", () => {
    const first = buildCycloneDx(lockFixture, "a".repeat(40));
    const original = String.prototype.localeCompare;
    try {
      String.prototype.localeCompare = function (other: string): number { return -original.call(this, other); };
      expect(buildCycloneDx(lockFixture, "a".repeat(40))).toEqual(first);
    } finally { String.prototype.localeCompare = original; }
  });

  test("rejects malformed SHA-512 integrity instead of emitting an invalid SBOM hash", () => {
    const malformed = lockFixture.replaceAll(Buffer.alloc(64, 1).toString("base64"), "AQID");
    expect(() => buildCycloneDx(malformed, "a".repeat(40))).toThrow("integrity");
  });

  test("builds a deterministic sorted CycloneDX BOM", () => {
    const first = buildCycloneDx(lockFixture, "a".repeat(40));
    const second = buildCycloneDx(lockFixture, "a".repeat(40));
    expect(JSON.stringify(first)).toBe(JSON.stringify(second));
    expect(first.metadata.component).toEqual({ name: "workspace-root", type: "application", version: "a".repeat(40) });
    expect(first.components.map((item) => item.purl)).toEqual([
      "pkg:npm/%40example/server@workspace",
      "pkg:npm/%40scope/alpha@2.0.0",
      "pkg:npm/zeta@1.0.0",
    ]);
    expect(new Set(first.components.map((item) => item["bom-ref"])).size).toBe(first.components.length);
  });

  test("redacts secret values and ignores placeholders or references", () => {
    const token = `ghp_${"A".repeat(36)}`;
    const findings = scanSecretText("production.env", `LOCAL_PASSWORD=local-test-password
GITHUB_TOKEN=${token}
SERVICE_SECRET_FILE=/run/secrets/service
`);
    expect(findings).toMatchObject([{ detector: "github_token", line: 2, path: "production.env" }]);
    expect(scanSecretText("config.json", '"auth_token_env": "DEVICE_TOKEN_PUMP_01"')).toEqual([]);
    expect(JSON.stringify(findings)).not.toContain(token);
    expect(findings[0]?.digest).toMatch(/^[0-9a-f]{12}$/u);
  });

  test("parses and distinguishes non-UTF-8 Git paths without lossy decoding", () => {
    const header = new TextEncoder().encode(`100644 ${"a".repeat(40)} 0\t`);
    const snapshot = (pathByte: number) => Uint8Array.from([...header, pathByte, 0]);
    const first = parseIndexEntries(snapshot(0x80))[0]!;
    const second = parseIndexEntries(snapshot(0x81))[0]!;
    expect(first.path).not.toBe(second.path);
    expect([...first.pathBytes]).toEqual([0x80]);
    expect([...second.pathBytes]).toEqual([0x81]);
  });
});
