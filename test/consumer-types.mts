import { buildCycloneDx, scanSecretText, parseIndexEntries } from "@frankfmy/exact-source-audit";
import type { SecretFinding, IndexEntry, CycloneDxBom } from "@frankfmy/exact-source-audit";
const findings: SecretFinding[] = scanSecretText("safe.txt", "safe");
const entries: IndexEntry[] = parseIndexEntries(new Uint8Array());
const bom: CycloneDxBom = buildCycloneDx('{"packages":{},"workspaces":{}}', "a".repeat(40));
// @ts-expect-error exact index input is bytes, not decoded text
parseIndexEntries("index");
// @ts-expect-error path and text are required
scanSecretText("file");
// @ts-expect-error raw candidate credentials are not a report field
findings[0]?.value;
void [entries, bom];
