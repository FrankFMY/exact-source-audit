# Changelog

## 0.1.1 — 2026-08-26

- Treat credential variable names stored in `_ENV` fields as indirect references rather than secret values.
- Preserve, hash, and compare raw Git index bytes, including non-UTF-8 paths.
- Make the installed CLI explicitly Bun-only and correct its npm bin target.
- Add clean installed-bin and package-consumer release gates.

## 0.1.0

- Initial public source release of the library and CLI.
- Exact Git-index secret scanning.
- Deterministic CycloneDX 1.6 SBOM generation for Bun lockfiles.
