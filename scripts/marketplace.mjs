#!/usr/bin/env node
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";

const root = resolve(dirname(new URL(import.meta.url).pathname), "..");
const publicDir = join(root, "public");
const indexPath = join(publicDir, "marketplace.json");
const signaturePath = join(publicDir, "marketplace.sig");

function fail(message) {
  console.error(message);
  process.exit(1);
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`Unable to read valid JSON at ${path}: ${error.message}`);
  }
}

function writeJson(path, value) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`);
}

function requireString(value, label) {
  if (typeof value !== "string" || value.trim() === "") fail(`${label} must be a non-empty string.`);
  return value;
}

function requireHttpsUrl(value, label) {
  requireString(value, label);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail(`${label} must be a valid URL.`);
  }
  if (parsed.protocol !== "https:") fail(`${label} must use HTTPS.`);
  return parsed;
}

function githubRepoParts(repoUrl, label) {
  const parsed = requireHttpsUrl(repoUrl, label);
  if (parsed.hostname !== "github.com") fail(`${label} must use github.com.`);
  const [owner, repo, ...rest] = parsed.pathname.split("/").filter(Boolean);
  if (!owner || !repo || rest.length > 0) fail(`${label} must use https://github.com/<owner>/<repo>.`);
  return { owner, repo: repo.replace(/\.git$/, "") };
}

function requireSha256(value, label) {
  requireString(value, label);
  if (!/^[a-fA-F0-9]{64}$/.test(value)) fail(`${label} must be a 64-character SHA-256 hex digest.`);
}

function requireBase64Key(value, label) {
  requireString(value, label);
  const decoded = Buffer.from(value, "base64");
  if (decoded.length !== 32) fail(`${label} must be a base64 Ed25519 public key.`);
}

function validatePermissions(value, label) {
  if (!value || typeof value !== "object" || Array.isArray(value)) fail(`${label} must be an object.`);
  for (const group of ["bus", "registry", "network", "storage"]) {
    if (!value[group] || typeof value[group] !== "object" || Array.isArray(value[group])) {
      fail(`${label}.${group} must be an object.`);
    }
  }
}

function loadPackages() {
  const packagesDir = join(root, "packages");
  return readdirSync(packagesDir)
    .filter((file) => file.endsWith(".json"))
    .sort()
    .map((file) => readJson(join(packagesDir, file)));
}

function validate() {
  const developers = readJson(join(root, "developers.json"));
  if (developers.schema !== "bakingrl.marketplace-developers/1") fail("developers.json has an unsupported schema.");
  if (!Array.isArray(developers.developers)) fail("developers.json developers must be an array.");
  const developerIds = new Set();
  for (const developer of developers.developers) {
    requireString(developer.id, "developer.id");
    requireString(developer.name, `developer ${developer.id} name`);
    if (developerIds.has(developer.id)) fail(`Duplicate developer id: ${developer.id}`);
    developerIds.add(developer.id);
    if (developer.verified !== true) fail(`Developer ${developer.id} must be verified to appear in the official marketplace.`);
    if (!Array.isArray(developer.packageSigningKeys)) fail(`Developer ${developer.id} packageSigningKeys must be an array.`);
    for (const key of developer.packageSigningKeys) requireBase64Key(key, `Developer ${developer.id} packageSigningKeys entry`);
  }

  const packages = loadPackages();
  const packageIds = new Set();
  for (const pkg of packages) {
    if (pkg.schema !== "bakingrl.marketplace-package/1") fail(`Package ${pkg.id ?? "unknown"} has an unsupported schema.`);
    requireString(pkg.id, "package.id");
    requireString(pkg.developerId, `package ${pkg.id} developerId`);
    if (!developerIds.has(pkg.developerId)) fail(`Package ${pkg.id} references unknown developer ${pkg.developerId}.`);
    if (packageIds.has(pkg.id)) fail(`Duplicate package id: ${pkg.id}`);
    packageIds.add(pkg.id);
    const repoParts = githubRepoParts(pkg.repo, `package ${pkg.id} repo`);
    const listingUrl = requireHttpsUrl(pkg.listingUrl, `package ${pkg.id} listingUrl`);
    if (!isGitHubUrlForRepo(listingUrl, repoParts)) fail(`Package ${pkg.id} listingUrl must point to its GitHub repository.`);
    if (!Array.isArray(pkg.approvedVersions)) fail(`Package ${pkg.id} approvedVersions must be an array.`);
    for (const version of pkg.approvedVersions) {
      requireString(version.version, `package ${pkg.id} version`);
      const bundleUrl = requireHttpsUrl(version.bundleUrl, `package ${pkg.id}@${version.version} bundleUrl`);
      if (!isGitHubReleaseAssetUrlForRepo(bundleUrl, repoParts)) {
        fail(`Package ${pkg.id}@${version.version} bundleUrl must be a GitHub release asset from the package repo.`);
      }
      requireSha256(version.bundleSha256, `package ${pkg.id}@${version.version} bundleSha256`);
      requireBase64Key(version.signaturePublicKey, `package ${pkg.id}@${version.version} signaturePublicKey`);
      if (!version.review || version.review.status !== "approved") fail(`Package ${pkg.id}@${version.version} must have an approved review.`);
      requireString(version.review.reviewedAt, `package ${pkg.id}@${version.version} review.reviewedAt`);
      validatePermissions(version.review.permissions, `package ${pkg.id}@${version.version} review.permissions`);
    }
  }

  const sections = readJson(join(root, "sections.json"));
  if (sections.schema !== "bakingrl.marketplace-sections/1") fail("sections.json has an unsupported schema.");
  for (const section of ["recommended", "new"]) {
    if (!Array.isArray(sections.sections?.[section])) fail(`sections.${section} must be an array.`);
    for (const packageId of sections.sections[section]) {
      if (!packageIds.has(packageId)) fail(`sections.${section} references unknown package ${packageId}.`);
    }
  }

  return { developers, packages, sections };
}

function isGitHubUrlForRepo(parsed, repoParts) {
  const path = parsed.pathname.split("/").filter(Boolean);
  if (parsed.hostname === "github.com") {
    const [owner, repo] = path;
    return owner === repoParts.owner && repo?.replace(/\.git$/, "") === repoParts.repo;
  }
  if (parsed.hostname === "raw.githubusercontent.com") {
    const [owner, repo] = path;
    return owner === repoParts.owner && repo === repoParts.repo;
  }
  return false;
}

function isGitHubReleaseAssetUrlForRepo(parsed, repoParts) {
  const path = parsed.pathname.split("/").filter(Boolean);
  const [owner, repo, releases, download] = path;
  return parsed.hostname === "github.com"
    && owner === repoParts.owner
    && repo?.replace(/\.git$/, "") === repoParts.repo
    && releases === "releases"
    && download === "download";
}

function build() {
  const { developers, packages, sections } = validate();
  const index = {
    schema: "bakingrl.marketplace/1",
    generatedAt: new Date().toISOString(),
    sections: sections.sections,
    developers: developers.developers,
    packages
  };
  writeJson(indexPath, index);
  console.log(`Built ${indexPath}`);
}

function publicKeyRawFromSpki(publicKey) {
  const der = publicKey.export({ type: "spki", format: "der" });
  const header = Buffer.from("302a300506032b6570032100", "hex");
  if (der.length !== header.length + 32 || !der.subarray(0, header.length).equals(header)) {
    fail("Generated Ed25519 public key has an unsupported SPKI encoding.");
  }
  return der.subarray(header.length);
}

function keygen(keyPath = "bakingrl-marketplace-signing-key.json") {
  const target = resolve(process.cwd(), keyPath);
  if (existsSync(target)) fail(`Refusing to overwrite existing key file: ${target}`);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  writeJson(target, {
    algorithm: "ed25519",
    publicKey: publicKeyRawFromSpki(publicKey).toString("base64"),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" })
  });
  console.log(`Created signing key ${target}`);
}

function signIndex(args) {
  const keyIndex = args.indexOf("--key");
  const keyPath = keyIndex === -1 ? null : args[keyIndex + 1];
  if (!keyPath) fail("Usage: npm run sign -- --key <key-file>");
  if (!existsSync(indexPath)) build();
  const key = readJson(resolve(process.cwd(), keyPath));
  if (key.algorithm !== "ed25519" || typeof key.publicKey !== "string" || typeof key.privateKeyPem !== "string") {
    fail("Signing key must contain algorithm, publicKey, and privateKeyPem.");
  }
  const raw = readFileSync(indexPath);
  const signature = sign(null, raw, key.privateKeyPem).toString("base64");
  writeJson(signaturePath, {
    schema: "bakingrl.marketplace-signature/1",
    algorithm: "ed25519",
    publicKey: key.publicKey,
    signature,
    signedFile: "marketplace.json",
    sha256: createHash("sha256").update(raw).digest("hex")
  });
  console.log(`Signed ${indexPath}`);
}

const [command, ...args] = process.argv.slice(2);
if (command === "validate") {
  validate();
  console.log("Marketplace validation passed.");
} else if (command === "build") {
  build();
} else if (command === "sign") {
  signIndex(args);
} else if (command === "keygen") {
  keygen(args[0]);
} else {
  fail("Usage: node scripts/marketplace.mjs <validate|build|sign|keygen>");
}
