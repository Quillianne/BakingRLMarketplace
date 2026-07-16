# BakingRL Marketplace

Static signed trust index for BakingRL plugin packages. The generated catalogue
uses `bakingrl.marketplace/2`.

The repository does not mirror bundles or media. It signs normalized listing
snapshots, media hashes, reviewed permissions, developer keys, and exact bundle
hashes. A catalogue signature covers the exact bytes of
`public/marketplace.json`.

## Files

```txt
developers.json
sections.json
packages/<package-id>.json
schemas/
scripts/marketplace.mjs
tests/
```

- `developers.json` records developer kind, verification, and identified
  Ed25519 package signing keys.
- `sections.json` curates `recommended`, `new`, and `firstRun` package ids.
- `packages/*.json` contains signed listing snapshots and reviewed versions.
- `public/marketplace.json` is the generated Marketplace 2 catalogue.
- `public/marketplace.sig` is its detached signature envelope.

`public/` is generated and is not committed.

## Runtime Policy

Only stable Runtime API `2.3.x` versions may have status `active`. Older bundle
records may remain `yanked` as non-installable history, but the marketplace does
not provide a 2.2 compatibility path. Storage permissions are relative paths;
`plugin://self` is rejected.

Packages, versions, and signing keys use `active`, `yanked`, or `revoked`.
Revoked records require a reason and timestamp. A package version references its
developer key by `signingKeyId`; public keys are not duplicated in artifacts.

The current 1.0.5 bundles target Runtime API 2.0 and are therefore yanked. The
`firstRun` section remains empty until actual 2.3 bundles are reviewed. No new
bundle URL or hash has been invented during the Marketplace 2 migration.

## Version Records

```json
{
  "version": "2.0.0",
  "status": "active",
  "channel": "stable",
  "runtimeApi": "2.3.0",
  "minBakingrlVersion": "0.10.0",
  "runtime": {
    "node": true,
    "sidecars": [],
    "webviews": []
  },
  "dependencies": [],
  "permissions": {
    "bus": { "read": [], "publish": [] },
    "registry": { "read": [], "write": [] },
    "network": { "http": [], "websocket": [], "listen": [] },
    "storage": { "read": ["*"], "write": ["*"] }
  },
  "nativeCapabilities": {
    "node": { "platforms": ["any"] },
    "sidecars": [],
    "surfaces": []
  },
  "artifacts": [
    {
      "platform": "any",
      "bundleUrl": "https://github.com/<owner>/<repo>/releases/download/<tag>/<package>.brlp",
      "bundleSha256": "<sha256>",
      "signingKeyId": "developer-release-1"
    }
  ],
  "reviewedAt": "2026-07-16T00:00:00Z"
}
```

Supported artifact platforms are `any`, `darwin-arm64`, `darwin-x64`,
`linux-arm64`, `linux-x64`, and `windows-x64`. `nativeCapabilities` is checked against the
reviewed runtime declarations and artifact platforms; it cannot be entered
independently.

Network permissions use structured endpoint objects. Direct network access by
a Node runtime or sidecar remains a consent declaration, not a sandbox.

## Commands

```sh
npm run validate
npm test
npm run build
npm run keygen -- --key-id marketplace-root-1 --out bakingrl-marketplace-signing-key.json
npm run sign -- --key bakingrl-marketplace-signing-key.json
npm run verify -- --key bakingrl-marketplace-verification-key.json
```

`build` generates a millisecond timestamp sequence, a current `generatedAt`,
and an `expiresAt` seven days later. CI supplies its own monotone sequence. For
reproducible builds, pass `--sequence`, `--generated-at`, and `--expires-at`.

The signature envelope contains only `keyId`, never a key to trust. Verification
requires an external key document:

```json
{
  "schema": "bakingrl.marketplace-verification-key/1",
  "keyId": "marketplace-root-1",
  "algorithm": "ed25519",
  "publicKey": "<base64-ed25519-public-key>"
}
```

`verify` enforces the signature, digest, schema, optional sequence floor, and
the 24-hour clock tolerance. `--allow-expired` verifies an expired cache for
read-only inspection; it does not make the cache installable.

Generate production private keys outside the repository and store the signing
key document in the GitHub secret `BAKINGRL_MARKETPLACE_SIGNING_KEY_JSON`. No
private key belongs in source control.
