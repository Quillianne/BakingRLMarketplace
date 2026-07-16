import assert from "node:assert/strict";
import { readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { mkdtempSync } from "node:fs";
import test, { after } from "node:test";

import {
  MarketplaceError,
  buildMarketplace,
  deriveNativeCapabilities,
  generateSigningKey,
  marketplaceRoot,
  signMarketplace,
  validateCatalogue,
  validateMarketplaceSources,
  verifyMarketplace
} from "../scripts/marketplace.mjs";

const temporaryDirectories = [];

function temporaryDirectory() {
  const directory = mkdtempSync(join(tmpdir(), "bakingrl-marketplace-test-"));
  temporaryDirectories.push(directory);
  return directory;
}

function clone(value) {
  return structuredClone(value);
}

function buildFixture(sequence = 23000) {
  const outputDir = temporaryDirectory();
  const result = buildMarketplace({
    rootDir: marketplaceRoot,
    outputDir,
    sequence,
    generatedAt: "2026-07-16T10:00:00.000Z",
    expiresAt: "2026-07-23T10:00:00.000Z"
  });
  return { ...result, outputDir };
}

function publicVerificationKey(signingKey) {
  return {
    schema: "bakingrl.marketplace-verification-key/1",
    keyId: signingKey.keyId,
    algorithm: signingKey.algorithm,
    publicKey: signingKey.publicKey
  };
}

after(() => {
  for (const directory of temporaryDirectories) {
    rmSync(directory, { recursive: true, force: true });
  }
});

test("validates and builds a strict Marketplace 2 snapshot", () => {
  const source = validateMarketplaceSources({ rootDir: marketplaceRoot });
  assert.equal(source.packages.length, 7);

  const { catalogue } = buildFixture(23001);
  assert.equal(catalogue.schema, "bakingrl.marketplace/2");
  assert.equal(catalogue.sequence, 23001);
  assert.deepEqual(catalogue.sections.firstRun, [
    "bakingrl.stats-extended",
    "bakingrl.layout-studio",
    "bakingrl.broadcast-visuals",
    "bakingrl.obs-gateway"
  ]);
  const versions = catalogue.packages.flatMap((pkg) => pkg.versions);
  const activeVersions = versions.filter((version) => version.status === "active");
  const legacyVersions = versions.filter((version) => version.runtimeApi === "2.0.0");
  assert.equal(activeVersions.length, 6);
  assert.ok(activeVersions.every((version) => version.runtimeApi === "2.3.0"));
  assert.equal(legacyVersions.length, 4);
  assert.ok(legacyVersions.every((version) => version.status === "yanked"));
  assert.ok(catalogue.packages.every((pkg) => (
    pkg.versions.every((version) => !Object.hasOwn(version, "dataMigrations"))
  )));
  assert.ok(catalogue.packages.every((pkg) => (
    pkg.versions.every((version) => version.artifacts.every((artifact) => artifact.signingKeyId))
  )));
  assert.ok(!JSON.stringify(catalogue).includes("plugin://self"));
});

test("rejects unknown fields, legacy storage paths, and active pre-2.3 runtimes", () => {
  const { catalogue } = buildFixture(23002);

  const unknownField = clone(catalogue);
  unknownField.packages[0].unexpected = true;
  assert.throws(
    () => validateCatalogue(unknownField),
    (error) => error instanceof MarketplaceError && /unknown field unexpected/.test(error.message)
  );

  const legacyStorage = clone(catalogue);
  legacyStorage.packages[0].versions[0].permissions.storage.read = ["plugin://self/*"];
  assert.throws(
    () => validateCatalogue(legacyStorage),
    (error) => error instanceof MarketplaceError && /relative storage path/.test(error.message)
  );

  const activeLegacyRuntime = clone(catalogue);
  const legacyPackage = activeLegacyRuntime.packages.find((pkg) => pkg.id === "com.bakingrl.cast-package");
  legacyPackage.status = "active";
  legacyPackage.versions[0].status = "active";
  assert.throws(
    () => validateCatalogue(activeLegacyRuntime),
    (error) => error instanceof MarketplaceError && /Runtime API 2\.3\.x/.test(error.message)
  );

  const removedMigrationContract = clone(catalogue);
  removedMigrationContract.packages[0].versions[0].dataMigrations = [];
  assert.throws(
    () => validateCatalogue(removedMigrationContract),
    (error) => error instanceof MarketplaceError && /unknown field dataMigrations/.test(error.message)
  );
});

test("derives native capabilities from runtime declarations and artifact platforms", () => {
  const { catalogue } = buildFixture(23003);
  const changed = clone(catalogue);
  const version = changed.packages.find((pkg) => pkg.id === "com.bakingrl.cast-package").versions[0];
  version.runtime.webviews.push({ id: "scoreSurface", kind: "surface" });

  assert.deepEqual(deriveNativeCapabilities(version), {
    node: { platforms: ["any"] },
    sidecars: [],
    surfaces: [{ id: "scoreSurface", platforms: ["any"] }]
  });
  assert.throws(
    () => validateCatalogue(changed),
    (error) => error instanceof MarketplaceError && /must be derived/.test(error.message)
  );

  version.nativeCapabilities = deriveNativeCapabilities(version);
  assert.doesNotThrow(() => validateCatalogue(changed));
});

test("signs exact catalogue bytes and verifies with an external trusted public key", () => {
  const { indexPath, outputDir } = buildFixture(23004);
  const keyPath = join(outputDir, "signing-key.json");
  const verificationKeyPath = join(outputDir, "verification-key.json");
  const signaturePath = join(outputDir, "marketplace.sig");
  const signingKey = generateSigningKey({ targetPath: keyPath, keyId: "test-root-1" });
  writeFileSync(verificationKeyPath, `${JSON.stringify(publicVerificationKey(signingKey), null, 2)}\n`);

  const { signature } = signMarketplace({ indexPath, signaturePath, keyPath });
  assert.equal(signature.keyId, "test-root-1");
  assert.ok(!Object.hasOwn(signature, "publicKey"));
  assert.doesNotThrow(() => verifyMarketplace({
    indexPath,
    signaturePath,
    keyPath: verificationKeyPath,
    minSequence: 23004,
    now: new Date("2026-07-16T12:00:00.000Z")
  }));

  const tampered = JSON.parse(readFileSync(indexPath, "utf8"));
  tampered.sequence += 1;
  writeFileSync(indexPath, `${JSON.stringify(tampered, null, 2)}\n`);
  assert.throws(
    () => verifyMarketplace({
      indexPath,
      signaturePath,
      keyPath: verificationKeyPath,
      now: new Date("2026-07-16T12:00:00.000Z")
    }),
    (error) => error instanceof MarketplaceError && /SHA-256/.test(error.message)
  );
});

test("enforces sequence floors and expiry while allowing cache inspection", () => {
  const { indexPath, outputDir } = buildFixture(23005);
  const keyPath = join(outputDir, "signing-key.json");
  const verificationKeyPath = join(outputDir, "verification-key.json");
  const signaturePath = join(outputDir, "marketplace.sig");
  const signingKey = generateSigningKey({ targetPath: keyPath, keyId: "test-root-2" });
  writeFileSync(verificationKeyPath, `${JSON.stringify(publicVerificationKey(signingKey), null, 2)}\n`);
  signMarketplace({ indexPath, signaturePath, keyPath });

  assert.throws(
    () => verifyMarketplace({
      indexPath,
      signaturePath,
      keyPath: verificationKeyPath,
      minSequence: 23006,
      now: new Date("2026-07-16T12:00:00.000Z")
    }),
    (error) => error instanceof MarketplaceError && /below required sequence/.test(error.message)
  );
  assert.throws(
    () => verifyMarketplace({
      indexPath,
      signaturePath,
      keyPath: verificationKeyPath,
      now: new Date("2026-07-25T12:00:00.000Z")
    }),
    (error) => error instanceof MarketplaceError && /expired/.test(error.message)
  );
  assert.doesNotThrow(() => verifyMarketplace({
    indexPath,
    signaturePath,
    keyPath: verificationKeyPath,
    now: new Date("2026-07-25T12:00:00.000Z"),
    allowExpired: true
  }));
});

test("does not contain a committed private key", () => {
  const ignoredDirectories = new Set([".git", "node_modules", "public"]);
  const privateKeyMarker = ["-----BEGIN", " PRIVATE KEY-----"].join("");
  const visit = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      if (ignoredDirectories.has(entry.name)) continue;
      const path = join(directory, entry.name);
      if (entry.isDirectory()) {
        visit(path);
      } else {
        assert.ok(!readFileSync(path, "utf8").includes(privateKeyMarker), path);
      }
    }
  };
  visit(marketplaceRoot);
});
