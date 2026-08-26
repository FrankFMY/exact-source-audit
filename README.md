# Exact Source Audit

Exact Git-index secret scanning and deterministic CycloneDX SBOM generation for Bun and TypeScript repositories.

I built this tool for release pipelines where evidence must describe the exact staged source—not an ambient worktree, dereferenced symlink, ignored file, or mutable replacement ref.

## Core guarantees

- reads one byte-exact `git ls-files --stage -z` snapshot;
- reads indexed blobs by immutable object ID;
- disables Git replacement refs for scanner-owned reads;
- scans symlink blob bytes without following filesystem targets;
- ignores untracked and unstaged files by design;
- rechecks the complete index snapshot and fails on drift;
- reports detector, path, line and an irreversible digest prefix—never the candidate secret value;
- generates deterministic CycloneDX 1.6 components from Bun's JSONC lockfile;
- deduplicates identical package references and fails on conflicting duplicate content;
- writes SBOM artifacts with mode `0600`.

## Installation

The source repository is public. Registry publication is intentionally deferred, so the package remains marked private until a separate npm release gate is completed.

```bash
git clone https://github.com/FrankFMY/exact-source-audit.git
cd exact-source-audit
bun install --frozen-lockfile
bun run verify
```

## CLI

Scan the exact staged index:

```bash
bun src/cli.ts secrets --root .
```

Generate a deterministic CycloneDX SBOM:

```bash
bun src/cli.ts sbom \
  --root . \
  --revision "$(git rev-parse HEAD)" \
  --output /tmp/source-sbom.cdx.json
```

## Library API

```ts
import {
  buildCycloneDx,
  scanSecretText,
} from "@frankfmy/exact-source-audit";
```

## Threat model

This tool is designed to prevent several common evidence mistakes:

- scanning the worktree while committing different bytes;
- following a staged symlink into an unrelated local file;
- hiding an indexed secret behind a Git replacement ref;
- printing the secret value into CI logs;
- producing duplicate CycloneDX `bom-ref` identities.

It is a release evidence tool, not a substitute for credential rotation, repository access control, dependency vulnerability scanning, or runtime security testing.

## Development

```bash
bun install --frozen-lockfile
bun run verify
```

## Author

**Artem Prianishnikov**

- GitHub: https://github.com/FrankFMY
- Website: https://frankfmy.com
- Email: Pryanishnikovartem@gmail.com

## License

Apache-2.0 © 2026 Artem Prianishnikov. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
