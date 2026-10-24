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
- reports detector, path, line and a 12-hex SHA-256 digest prefix—never the candidate secret value;
- generates deterministic CycloneDX 1.6 components from Bun's JSONC lockfile;
- deduplicates identical package references and fails on conflicting duplicate content;
- writes SBOM artifacts with mode `0600`.

## Installation

```bash
bun add --global @frankfmy/exact-source-audit
```

[npm package](https://www.npmjs.com/package/@frankfmy/exact-source-audit) · [source](https://github.com/FrankFMY/exact-source-audit). Use the registry command when the desired version is public. Otherwise clone this repository, run `bun install --frozen-lockfile && bun run build && npm pack`, and install that tarball. Automatic release-triggered registry publication is not enabled.

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
  --output source-sbom.cdx.json
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

It is a release evidence tool, not a substitute for credential rotation, repository access control, dependency vulnerability scanning, or runtime security testing. It is not a complete secret detector or a cryptographic audit. Digest prefixes are correlation hints, not anonymization: low-entropy values may be guessed. Reports still contain paths and must be treated as sensitive.

Scanner Git children cannot activate transports or remote helpers; missing local indexed blobs fail closed, including on Git versions that do not honor the newer no-lazy-fetch flag. Index entries accept exact 40-hex SHA-1 or 64-hex SHA-256 object IDs.

SBOM generation reads the supplied worktree `bun.lock` and caller-provided 40-hex SHA-1 revision. It does not prove that the lockfile belongs to that revision, validate every dependency license, resolve vulnerabilities, or construct a complete dependency graph. Enforce that custody in the calling release workflow. Components use locale-independent code-unit ordering; supplied SHA-512 integrity must decode canonically to 64 bytes. Bun 1.4+ and local Git are required for the CLI; ordinary Node-only execution of the SBOM parser is not supported.

## Development

```bash
bun install --frozen-lockfile
bun run verify
```

## Author

**Artem Prianishnikov**

- GitHub: https://github.com/FrankFMY
- Website: https://frankfmy.com
- Email: Pryanishnikovartem@gmail.com · frankfmy@proton.me
- Telegram: https://t.me/FrankFMY
- LinkedIn: https://www.linkedin.com/in/frankfmy/
- X: https://x.com/FrankFMY
- npm: https://www.npmjs.com/~frankfmy

## License

Apache-2.0 © 2026 Artem Prianishnikov. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
