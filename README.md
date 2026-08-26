# Exact Source Audit

Exact Git-index secret scanning and deterministic CycloneDX SBOM generation for Bun and TypeScript repositories. The CLI and SBOM parser require Bun 1.4 or newer.

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

```bash
bun add --global @frankfmy/exact-source-audit
```

The first npm version is bootstrapped once from its clean exact tag with interactive account 2FA using `scripts/bootstrap-first-npm-release.sh`; subsequent releases use the repository's OIDC trusted publisher.

## CLI

Scan the exact staged index:

```bash
source-audit secrets --root .
```

Generate a deterministic CycloneDX SBOM:

```bash
source-audit sbom \
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
