import { describe, expect, test } from "bun:test";
import { buildCycloneDx, scanSecretText } from "../src/index.js";

const lockFixture = `{
  "lockfileVersion": 3,
  "configVersion": 1,
  "workspaces": {
    "": { "name": "workspace-root" },
    "server": { "name": "@example/server" }
  },
  "packages": {
    "zeta": ["zeta@1.0.0", "", {}, "sha512-AQID"],
    "zeta-copy": ["zeta@1.0.0", "", {}, "sha512-AQID"],
    "@scope/alpha": ["@scope/alpha@2.0.0", "", {}, "sha512-BAUG"],
    "@example/server": ["@example/server@workspace:server"]
  }
}`;

describe("exact source audit", () => {
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
});
