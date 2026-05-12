# BakingRL Marketplace

Static trust index for BakingRL plugin packages.

The marketplace does not mirror plugin bundles or media. Plugin repositories own
their listing metadata, images, and GitHub releases. This repository references
those remote URLs and approves exact package versions through reviewed bundle
hashes, signature public keys, and effective permissions.

## Files

```txt
developers.json
sections.json
packages/<package-id>.json
schemas/
scripts/marketplace.mjs
```

- `developers.json`: verified developers and known package signing keys.
- `sections.json`: manually curated marketplace rows such as `recommended` and
  `new`.
- `packages/*.json`: reviewed packages and approved versions.
- `public/marketplace.json`: generated signed index source for GitHub Pages.
- `public/marketplace.sig`: signature for the generated index.

## Commands

```sh
npm run validate
npm run build
npm run sign -- --key bakingrl-marketplace-signing-key.json
```

`public/` is generated and should not be committed.

Generate the production signing key outside this repository and store it as the
GitHub secret `BAKINGRL_MARKETPLACE_SIGNING_KEY_JSON`. Only the public key should
be embedded in the BakingRL host as a trusted marketplace key.
