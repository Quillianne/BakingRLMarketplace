#!/usr/bin/env node
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify
} from "node:crypto";
import {
  existsSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync
} from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const scriptPath = fileURLToPath(import.meta.url);
export const marketplaceRoot = resolve(dirname(scriptPath), "..");

const publicDir = join(marketplaceRoot, "public");
const defaultIndexPath = join(publicDir, "marketplace.json");
const defaultSignaturePath = join(publicDir, "marketplace.sig");

export const MIN_SUPPORTED_RUNTIME_API = "2.3.0";
export const CLOCK_TOLERANCE_MS = 24 * 60 * 60 * 1000;
export const DEFAULT_CATALOGUE_VALIDITY_MS = 7 * 24 * 60 * 60 * 1000;

const schemaFiles = [
  "catalogue.schema.json",
  "developers.schema.json",
  "package.schema.json",
  "sections.schema.json",
  "signature.schema.json"
];
const statuses = new Set(["active", "yanked", "revoked"]);
const developerKinds = new Set(["individual", "organization"]);
const verifications = new Set(["unverified", "verified", "official"]);
const channels = new Set(["stable", "beta", "nightly"]);
const platforms = ["any", "darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "windows-x64"];
const platformSet = new Set(platforms);
const webviewKinds = new Set(["tool", "settings", "panel", "surface"]);
const listenTransports = new Set(["http", "https", "ws", "wss", "tcp"]);
const semverPattern = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
const packageIdPattern = /^[a-z0-9]+(?:[.-][a-z0-9]+)+$/;
const slugIdPattern = /^[a-z0-9]+(?:[._-][a-z0-9]+)*$/;
const runtimeIdPattern = /^[A-Za-z][A-Za-z0-9._-]*$/;

export class MarketplaceError extends Error {
  constructor(message) {
    super(message);
    this.name = "MarketplaceError";
  }
}

function fail(message) {
  throw new MarketplaceError(message);
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function assertObject(value, label, required, optional = []) {
  if (!isObject(value)) fail(`${label} must be an object.`);
  for (const key of required) {
    if (!hasOwn(value, key)) fail(`${label}.${key} is required.`);
  }
  const allowed = new Set([...required, ...optional]);
  const unknown = Object.keys(value).filter((key) => !allowed.has(key));
  if (unknown.length > 0) fail(`${label} contains unknown field ${unknown[0]}.`);
  return value;
}

function assertArray(value, label, minimum = 0) {
  if (!Array.isArray(value)) fail(`${label} must be an array.`);
  if (value.length < minimum) fail(`${label} must contain at least ${minimum} item(s).`);
  return value;
}

function assertUnique(values, label, key = (value) => canonicalJson(value)) {
  const seen = new Set();
  for (const value of values) {
    const identity = key(value);
    if (seen.has(identity)) fail(`${label} contains a duplicate entry: ${identity}.`);
    seen.add(identity);
  }
}

function requireString(value, label) {
  if (typeof value !== "string" || value.trim() === "") fail(`${label} must be a non-empty string.`);
  return value;
}

function requireBoolean(value, label) {
  if (typeof value !== "boolean") fail(`${label} must be a boolean.`);
  return value;
}

function requireEnum(value, allowed, label) {
  requireString(value, label);
  if (!allowed.has(value)) fail(`${label} has unsupported value ${value}.`);
  return value;
}

function requireSlugId(value, label) {
  requireString(value, label);
  if (!slugIdPattern.test(value)) fail(`${label} must be a lowercase identifier.`);
  return value;
}

function requireRuntimeId(value, label) {
  requireString(value, label);
  if (!runtimeIdPattern.test(value)) fail(`${label} must be a runtime identifier.`);
  return value;
}

function requirePackageId(value, label) {
  requireString(value, label);
  if (!packageIdPattern.test(value)) fail(`${label} must be a lowercase reverse-domain package id.`);
  return value;
}

function parseSemver(value, label) {
  requireString(value, label);
  const match = semverPattern.exec(value);
  if (!match) fail(`${label} must be a semantic version.`);
  return {
    major: Number(match[1]),
    minor: Number(match[2]),
    patch: Number(match[3]),
    prerelease: match[4] ?? null
  };
}

function requireRuntimeApi(value, label, status) {
  const parsed = parseSemver(value, label);
  if (status === "active" && (
    parsed.major !== 2
    || parsed.minor !== 3
    || parsed.prerelease !== null
  )) {
    fail(`${label} must target stable Runtime API 2.3.x; older runtimes may only remain yanked or revoked.`);
  }
  return parsed;
}

function requireTimestamp(value, label) {
  requireString(value, label);
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) fail(`${label} must be an ISO 8601 timestamp.`);
  return new Date(timestamp);
}

function requireSafeInteger(value, label, minimum = 0) {
  if (!Number.isSafeInteger(value) || value < minimum) {
    fail(`${label} must be a safe integer greater than or equal to ${minimum}.`);
  }
  return value;
}

function requireSha256(value, label) {
  requireString(value, label);
  if (!/^[a-f0-9]{64}$/.test(value)) fail(`${label} must be a lowercase SHA-256 digest.`);
  return value;
}

function decodeCanonicalBase64(value, byteLength, label) {
  requireString(value, label);
  const decoded = Buffer.from(value, "base64");
  if (decoded.length !== byteLength || decoded.toString("base64") !== value) {
    fail(`${label} must be canonical base64 for ${byteLength} bytes.`);
  }
  return decoded;
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
  if (parsed.username || parsed.password) fail(`${label} must not contain credentials.`);
  return parsed;
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue);
  if (!isObject(value)) return value;
  return Object.fromEntries(
    Object.keys(value)
      .sort()
      .map((key) => [key, stableValue(value[key])])
  );
}

export function canonicalJson(value) {
  return JSON.stringify(stableValue(value));
}

export function sha256Json(value) {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

function readJson(path, label = path) {
  let contents;
  try {
    contents = readFileSync(path, "utf8");
  } catch (error) {
    fail(`Unable to read ${label}: ${error.message}`);
  }
  try {
    return JSON.parse(contents);
  } catch (error) {
    fail(`Unable to parse JSON in ${label}: ${error.message}`);
  }
}

function writeJson(path, value, mode) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, mode === undefined ? undefined : { mode });
}

function validateRevocation(value, label) {
  assertObject(value, label, ["reason", "revokedAt"]);
  requireString(value.reason, `${label}.reason`);
  requireTimestamp(value.revokedAt, `${label}.revokedAt`);
}

function validateRevocable(value, label) {
  requireEnum(value.status, statuses, `${label}.status`);
  if (value.status === "revoked") {
    if (!hasOwn(value, "revocation")) fail(`${label}.revocation is required when status is revoked.`);
    validateRevocation(value.revocation, `${label}.revocation`);
  } else if (hasOwn(value, "revocation")) {
    fail(`${label}.revocation is only allowed when status is revoked.`);
  }
}

function githubRepoParts(repoUrl, label) {
  const parsed = requireHttpsUrl(repoUrl, label);
  if (parsed.hostname !== "github.com") fail(`${label} must use github.com.`);
  const path = parsed.pathname.split("/").filter(Boolean);
  if (path.length !== 2) fail(`${label} must use https://github.com/<owner>/<repo>.`);
  return {
    owner: path[0].toLowerCase(),
    repo: path[1].replace(/\.git$/, "").toLowerCase()
  };
}

function isGitHubUrlForRepo(parsed, repoParts) {
  const path = parsed.pathname.split("/").filter(Boolean);
  if (parsed.hostname === "github.com") {
    return path[0]?.toLowerCase() === repoParts.owner
      && path[1]?.replace(/\.git$/, "").toLowerCase() === repoParts.repo;
  }
  if (parsed.hostname === "raw.githubusercontent.com") {
    return path[0]?.toLowerCase() === repoParts.owner
      && path[1]?.toLowerCase() === repoParts.repo;
  }
  return false;
}

function isGitHubReleaseAssetUrlForRepo(parsed, repoParts) {
  const path = parsed.pathname.split("/").filter(Boolean);
  return parsed.hostname === "github.com"
    && path[0]?.toLowerCase() === repoParts.owner
    && path[1]?.replace(/\.git$/, "").toLowerCase() === repoParts.repo
    && path[2] === "releases"
    && path[3] === "download"
    && path.length >= 6;
}

function validateMedia(value, label, screenshot = false) {
  assertObject(value, label, ["url", "sha256"], screenshot ? ["caption"] : []);
  requireHttpsUrl(value.url, `${label}.url`);
  requireSha256(value.sha256, `${label}.sha256`);
  if (hasOwn(value, "caption")) requireString(value.caption, `${label}.caption`);
}

function validateListing(value, pkg, repoParts, label) {
  assertObject(value, label, ["sourceUrl", "snapshotSha256", "snapshot"]);
  const sourceUrl = requireHttpsUrl(value.sourceUrl, `${label}.sourceUrl`);
  if (!isGitHubUrlForRepo(sourceUrl, repoParts)) {
    fail(`${label}.sourceUrl must point to the package repository.`);
  }
  requireSha256(value.snapshotSha256, `${label}.snapshotSha256`);

  const snapshot = assertObject(value.snapshot, `${label}.snapshot`, [
    "schema",
    "packageId",
    "displayName",
    "shortDescription",
    "longDescription",
    "tags",
    "repo",
    "media",
    "links"
  ]);
  if (snapshot.schema !== "bakingrl.marketplace-listing/2") {
    fail(`${label}.snapshot.schema must be bakingrl.marketplace-listing/2.`);
  }
  requirePackageId(snapshot.packageId, `${label}.snapshot.packageId`);
  if (snapshot.packageId !== pkg.id) fail(`${label}.snapshot.packageId must match package ${pkg.id}.`);
  requireString(snapshot.displayName, `${label}.snapshot.displayName`);
  requireString(snapshot.shortDescription, `${label}.snapshot.shortDescription`);
  requireString(snapshot.longDescription, `${label}.snapshot.longDescription`);
  assertArray(snapshot.tags, `${label}.snapshot.tags`);
  assertUnique(snapshot.tags, `${label}.snapshot.tags`, (tag) => tag);
  for (const [index, tag] of snapshot.tags.entries()) {
    requireString(tag, `${label}.snapshot.tags[${index}]`);
    if (!/^[a-z0-9]+(?:-[a-z0-9]+)*$/.test(tag)) {
      fail(`${label}.snapshot.tags[${index}] must be a lowercase tag.`);
    }
  }
  const listingRepo = githubRepoParts(snapshot.repo, `${label}.snapshot.repo`);
  if (listingRepo.owner !== repoParts.owner || listingRepo.repo !== repoParts.repo) {
    fail(`${label}.snapshot.repo must match package.repo.`);
  }

  const media = assertObject(snapshot.media, `${label}.snapshot.media`, ["icon", "banner", "screenshots"]);
  for (const kind of ["icon", "banner"]) {
    if (media[kind] !== null) validateMedia(media[kind], `${label}.snapshot.media.${kind}`);
  }
  assertArray(media.screenshots, `${label}.snapshot.media.screenshots`);
  assertUnique(media.screenshots, `${label}.snapshot.media.screenshots`, (item) => item.url);
  media.screenshots.forEach((item, index) => {
    validateMedia(item, `${label}.snapshot.media.screenshots[${index}]`, true);
  });

  const links = assertObject(snapshot.links, `${label}.snapshot.links`, ["docs", "support"]);
  requireHttpsUrl(links.docs, `${label}.snapshot.links.docs`);
  requireHttpsUrl(links.support, `${label}.snapshot.links.support`);

  const actualHash = sha256Json(snapshot);
  if (actualHash !== value.snapshotSha256) {
    fail(`${label}.snapshotSha256 does not match the canonical listing snapshot (expected ${actualHash}).`);
  }
}

function validatePlatforms(value, label) {
  assertArray(value, label, 1);
  assertUnique(value, label, (item) => item);
  for (const [index, platform] of value.entries()) {
    requireEnum(platform, platformSet, `${label}[${index}]`);
  }
  if (value.includes("any") && value.length !== 1) fail(`${label} cannot combine any with a specific platform.`);
  const sorted = [...value].sort((a, b) => platforms.indexOf(a) - platforms.indexOf(b));
  if (canonicalJson(sorted) !== canonicalJson(value)) fail(`${label} must use canonical platform order.`);
  return value;
}

function validateRuntime(value, label, artifactPlatforms) {
  assertObject(value, label, ["node", "sidecars", "webviews"]);
  requireBoolean(value.node, `${label}.node`);

  assertArray(value.sidecars, `${label}.sidecars`);
  assertUnique(value.sidecars, `${label}.sidecars`, (sidecar) => sidecar.id);
  for (const [index, sidecar] of value.sidecars.entries()) {
    const sidecarLabel = `${label}.sidecars[${index}]`;
    assertObject(sidecar, sidecarLabel, ["id", "platforms"]);
    requireRuntimeId(sidecar.id, `${sidecarLabel}.id`);
    validatePlatforms(sidecar.platforms, `${sidecarLabel}.platforms`);
    if (!artifactPlatforms.includes("any")) {
      for (const platform of sidecar.platforms) {
        if (platform === "any" || !artifactPlatforms.includes(platform)) {
          fail(`${sidecarLabel}.platforms contains ${platform}, which has no package artifact.`);
        }
      }
    }
  }

  assertArray(value.webviews, `${label}.webviews`);
  assertUnique(value.webviews, `${label}.webviews`, (webview) => webview.id);
  for (const [index, webview] of value.webviews.entries()) {
    const webviewLabel = `${label}.webviews[${index}]`;
    assertObject(webview, webviewLabel, ["id", "kind"]);
    requireRuntimeId(webview.id, `${webviewLabel}.id`);
    requireEnum(webview.kind, webviewKinds, `${webviewLabel}.kind`);
  }
}

export function deriveNativeCapabilities(version) {
  const artifactPlatforms = [...new Set(version.artifacts.map((artifact) => artifact.platform))]
    .sort((a, b) => platforms.indexOf(a) - platforms.indexOf(b));
  const sidecars = version.runtime.sidecars
    .map((sidecar) => ({ id: sidecar.id, platforms: [...sidecar.platforms] }))
    .sort((a, b) => a.id.localeCompare(b.id));
  const surfaces = version.runtime.webviews
    .filter((webview) => webview.kind === "surface")
    .map((webview) => ({ id: webview.id, platforms: [...artifactPlatforms] }))
    .sort((a, b) => a.id.localeCompare(b.id));
  return {
    node: version.runtime.node ? { platforms: artifactPlatforms } : null,
    sidecars,
    surfaces
  };
}

function validateNativeCapabilities(value, version, label) {
  assertObject(value, label, ["node", "sidecars", "surfaces"]);
  if (value.node !== null) {
    assertObject(value.node, `${label}.node`, ["platforms"]);
    validatePlatforms(value.node.platforms, `${label}.node.platforms`);
  }
  for (const group of ["sidecars", "surfaces"]) {
    assertArray(value[group], `${label}.${group}`);
    assertUnique(value[group], `${label}.${group}`, (item) => item.id);
    for (const [index, item] of value[group].entries()) {
      const itemLabel = `${label}.${group}[${index}]`;
      assertObject(item, itemLabel, ["id", "platforms"]);
      requireRuntimeId(item.id, `${itemLabel}.id`);
      validatePlatforms(item.platforms, `${itemLabel}.platforms`);
    }
  }
  const derived = deriveNativeCapabilities(version);
  if (canonicalJson(value) !== canonicalJson(derived)) {
    fail(`${label} must be derived from runtime and artifact platforms.`);
  }
}

function validatePattern(value, label, storage = false) {
  requireString(value, label);
  const stars = [...value].filter((character) => character === "*").length;
  if (stars > 1 || (stars === 1 && !value.endsWith("*"))) {
    fail(`${label} may contain only one terminal wildcard.`);
  }
  if (value.includes("\\")) fail(`${label} must not contain backslashes.`);
  if (storage && value !== "*") {
    if (value.startsWith("/") || value.includes("://")) fail(`${label} must be a relative storage path.`);
    const withoutWildcard = value.endsWith("*") ? value.slice(0, -1) : value;
    const segments = withoutWildcard.split("/").filter(Boolean);
    if (segments.some((segment) => segment === "." || segment === "..")) {
      fail(`${label} must not contain dot path segments.`);
    }
  }
}

function validatePatternList(value, label, storage = false) {
  assertArray(value, label);
  assertUnique(value, label, (item) => item);
  value.forEach((item, index) => validatePattern(item, `${label}[${index}]`, storage));
}

function validatePorts(value, label) {
  if (value === "*") return;
  assertArray(value, label, 1);
  assertUnique(value, label, (port) => port);
  for (const [index, port] of value.entries()) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      fail(`${label}[${index}] must be a port between 1 and 65535.`);
    }
  }
  const sorted = [...value].sort((a, b) => a - b);
  if (canonicalJson(sorted) !== canonicalJson(value)) fail(`${label} must be sorted.`);
}

function validateHost(value, label) {
  requireString(value, label);
  if (value !== value.toLowerCase() || !/^[a-z0-9._:-]+$/.test(value)) {
    fail(`${label} must be a normalized lowercase host.`);
  }
}

function validatePathPrefix(value, label) {
  requireString(value, label);
  if (!value.startsWith("/") || value.includes("\\") || value.includes("?") || value.includes("#")) {
    fail(`${label} must be an absolute normalized URL path.`);
  }
  if (value.split("/").some((segment) => segment === "." || segment === "..")) {
    fail(`${label} must not contain dot path segments.`);
  }
}

function validateNetworkEndpoint(value, label, allowedSchemes) {
  assertObject(value, label, ["scheme", "host", "ports"], ["pathPrefixes"]);
  requireEnum(value.scheme, allowedSchemes, `${label}.scheme`);
  validateHost(value.host, `${label}.host`);
  validatePorts(value.ports, `${label}.ports`);
  if (hasOwn(value, "pathPrefixes")) {
    assertArray(value.pathPrefixes, `${label}.pathPrefixes`);
    assertUnique(value.pathPrefixes, `${label}.pathPrefixes`, (item) => item);
    value.pathPrefixes.forEach((prefix, index) => validatePathPrefix(prefix, `${label}.pathPrefixes[${index}]`));
  }
}

function validateListenEndpoint(value, label) {
  assertObject(value, label, ["transport", "host", "ports"]);
  requireEnum(value.transport, listenTransports, `${label}.transport`);
  validateHost(value.host, `${label}.host`);
  validatePorts(value.ports, `${label}.ports`);
}

function validatePermissions(value, label) {
  assertObject(value, label, ["bus", "registry", "network", "storage"]);

  assertObject(value.bus, `${label}.bus`, ["read", "publish"]);
  validatePatternList(value.bus.read, `${label}.bus.read`);
  validatePatternList(value.bus.publish, `${label}.bus.publish`);

  assertObject(value.registry, `${label}.registry`, ["read", "write"]);
  validatePatternList(value.registry.read, `${label}.registry.read`);
  validatePatternList(value.registry.write, `${label}.registry.write`);

  assertObject(value.storage, `${label}.storage`, ["read", "write"]);
  validatePatternList(value.storage.read, `${label}.storage.read`, true);
  validatePatternList(value.storage.write, `${label}.storage.write`, true);

  assertObject(value.network, `${label}.network`, ["http", "websocket", "listen"]);
  for (const group of ["http", "websocket", "listen"]) {
    assertArray(value.network[group], `${label}.network.${group}`);
    assertUnique(value.network[group], `${label}.network.${group}`);
  }
  value.network.http.forEach((endpoint, index) => {
    validateNetworkEndpoint(endpoint, `${label}.network.http[${index}]`, new Set(["http", "https"]));
  });
  value.network.websocket.forEach((endpoint, index) => {
    validateNetworkEndpoint(endpoint, `${label}.network.websocket[${index}]`, new Set(["ws", "wss"]));
  });
  value.network.listen.forEach((endpoint, index) => {
    validateListenEndpoint(endpoint, `${label}.network.listen[${index}]`);
  });
}

function validateArtifact(value, label, repoParts, developer) {
  assertObject(value, label, ["platform", "bundleUrl", "bundleSha256", "signingKeyId"]);
  requireEnum(value.platform, platformSet, `${label}.platform`);
  const bundleUrl = requireHttpsUrl(value.bundleUrl, `${label}.bundleUrl`);
  if (!isGitHubReleaseAssetUrlForRepo(bundleUrl, repoParts)) {
    fail(`${label}.bundleUrl must be a GitHub release asset from package.repo.`);
  }
  requireSha256(value.bundleSha256, `${label}.bundleSha256`);
  requireSlugId(value.signingKeyId, `${label}.signingKeyId`);
  const signingKey = developer.signingKeysById.get(value.signingKeyId);
  if (!signingKey) fail(`${label}.signingKeyId references an unknown developer key.`);
  return signingKey;
}

function validateDependency(value, label, packageId) {
  assertObject(value, label, ["packageId", "version", "optional"]);
  requirePackageId(value.packageId, `${label}.packageId`);
  if (value.packageId === packageId) fail(`${label}.packageId must not reference its own package.`);
  requireString(value.version, `${label}.version`);
  requireBoolean(value.optional, `${label}.optional`);
}

function validateVersion(value, label, pkg, repoParts, developer) {
  assertObject(value, label, [
    "version",
    "status",
    "channel",
    "runtimeApi",
    "runtime",
    "dependencies",
    "permissions",
    "nativeCapabilities",
    "artifacts",
    "reviewedAt"
  ], ["revocation", "minBakingrlVersion"]);
  parseSemver(value.version, `${label}.version`);
  validateRevocable(value, label);
  requireEnum(value.channel, channels, `${label}.channel`);
  requireRuntimeApi(value.runtimeApi, `${label}.runtimeApi`, value.status);
  if (hasOwn(value, "minBakingrlVersion")) {
    parseSemver(value.minBakingrlVersion, `${label}.minBakingrlVersion`);
  }

  assertArray(value.artifacts, `${label}.artifacts`, 1);
  assertUnique(value.artifacts, `${label}.artifacts`, (artifact) => artifact.platform);
  const artifactPlatforms = value.artifacts.map((artifact) => artifact.platform);
  validatePlatforms(artifactPlatforms, `${label}.artifactPlatforms`);
  const artifactKeys = value.artifacts.map((artifact, index) => (
    validateArtifact(artifact, `${label}.artifacts[${index}]`, repoParts, developer)
  ));
  if (value.status === "active" && artifactKeys.some((key) => key.status !== "active")) {
    fail(`${label} is active but uses a non-active signing key.`);
  }
  if (value.status !== "revoked" && artifactKeys.some((key) => key.status === "revoked")) {
    fail(`${label} must be revoked because one of its signing keys is revoked.`);
  }

  validateRuntime(value.runtime, `${label}.runtime`, artifactPlatforms);
  assertArray(value.dependencies, `${label}.dependencies`);
  assertUnique(value.dependencies, `${label}.dependencies`, (dependency) => dependency.packageId);
  value.dependencies.forEach((dependency, index) => {
    validateDependency(dependency, `${label}.dependencies[${index}]`, pkg.id);
  });
  validatePermissions(value.permissions, `${label}.permissions`);
  validateNativeCapabilities(value.nativeCapabilities, value, `${label}.nativeCapabilities`);
  requireTimestamp(value.reviewedAt, `${label}.reviewedAt`);
}

function validateDeveloperDocument(document) {
  assertObject(document, "developers.json", ["schema", "developers"]);
  if (document.schema !== "bakingrl.marketplace-developers/2") {
    fail("developers.json.schema must be bakingrl.marketplace-developers/2.");
  }
  assertArray(document.developers, "developers.json.developers");
  assertUnique(document.developers, "developers.json.developers", (developer) => developer.id);

  const developersById = new Map();
  const publicKeys = new Set();
  for (const [index, developer] of document.developers.entries()) {
    const label = `developers.json.developers[${index}]`;
    assertObject(developer, label, ["id", "name", "kind", "verification", "signingKeys"]);
    requireSlugId(developer.id, `${label}.id`);
    requireString(developer.name, `${label}.name`);
    requireEnum(developer.kind, developerKinds, `${label}.kind`);
    requireEnum(developer.verification, verifications, `${label}.verification`);
    assertArray(developer.signingKeys, `${label}.signingKeys`, 1);
    assertUnique(developer.signingKeys, `${label}.signingKeys`, (key) => key.id);
    const signingKeysById = new Map();
    for (const [keyIndex, key] of developer.signingKeys.entries()) {
      const keyLabel = `${label}.signingKeys[${keyIndex}]`;
      assertObject(key, keyLabel, ["id", "algorithm", "publicKey", "status"], ["revocation"]);
      requireSlugId(key.id, `${keyLabel}.id`);
      if (key.algorithm !== "ed25519") fail(`${keyLabel}.algorithm must be ed25519.`);
      decodeCanonicalBase64(key.publicKey, 32, `${keyLabel}.publicKey`);
      if (publicKeys.has(key.publicKey)) fail(`${keyLabel}.publicKey is already registered under another key id.`);
      publicKeys.add(key.publicKey);
      validateRevocable(key, keyLabel);
      signingKeysById.set(key.id, key);
    }
    developersById.set(developer.id, { ...developer, signingKeysById });
  }
  return developersById;
}

function validatePackageDocuments(packages, developersById, fileNames = []) {
  assertArray(packages, "packages", 1);
  assertUnique(packages, "packages", (pkg) => pkg.id);
  const packagesById = new Map();

  for (const [index, pkg] of packages.entries()) {
    const label = `packages[${index}]`;
    assertObject(pkg, label, ["schema", "id", "developerId", "status", "repo", "listing", "versions"], ["revocation"]);
    if (pkg.schema !== "bakingrl.marketplace-package/2") {
      fail(`${label}.schema must be bakingrl.marketplace-package/2.`);
    }
    requirePackageId(pkg.id, `${label}.id`);
    if (fileNames[index] && fileNames[index] !== `${pkg.id}.json`) {
      fail(`${fileNames[index]} must be named ${pkg.id}.json.`);
    }
    requireSlugId(pkg.developerId, `${label}.developerId`);
    const developer = developersById.get(pkg.developerId);
    if (!developer) fail(`${label}.developerId references unknown developer ${pkg.developerId}.`);
    validateRevocable(pkg, label);
    const repoParts = githubRepoParts(pkg.repo, `${label}.repo`);
    validateListing(pkg.listing, pkg, repoParts, `${label}.listing`);
    assertArray(pkg.versions, `${label}.versions`, 1);
    assertUnique(pkg.versions, `${label}.versions`, (version) => version.version);
    pkg.versions.forEach((version, versionIndex) => {
      validateVersion(version, `${label}.versions[${versionIndex}]`, pkg, repoParts, developer);
    });
    if (pkg.status === "yanked" && pkg.versions.some((version) => version.status === "active")) {
      fail(`${label} is yanked and cannot contain active versions.`);
    }
    if (pkg.status === "revoked" && pkg.versions.some((version) => version.status !== "revoked")) {
      fail(`${label} is revoked and all of its versions must be revoked.`);
    }
    packagesById.set(pkg.id, pkg);
  }

  for (const pkg of packages) {
    for (const version of pkg.versions) {
      for (const dependency of version.dependencies) {
        const target = packagesById.get(dependency.packageId);
        if (!target) {
          fail(`Package ${pkg.id}@${version.version} references unknown dependency ${dependency.packageId}.`);
        }
        if (version.status === "active" && !dependency.optional) {
          const installable = target.status === "active" && target.versions.some((candidate) => candidate.status === "active");
          if (!installable) {
            fail(`Package ${pkg.id}@${version.version} requires unavailable dependency ${dependency.packageId}.`);
          }
        }
      }
    }
  }

  return packagesById;
}

function validateSectionsDocument(document, packagesById) {
  assertObject(document, "sections.json", ["schema", "sections"]);
  if (document.schema !== "bakingrl.marketplace-sections/2") {
    fail("sections.json.schema must be bakingrl.marketplace-sections/2.");
  }
  assertObject(document.sections, "sections.json.sections", ["recommended", "new", "firstRun"]);
  for (const name of ["recommended", "new", "firstRun"]) {
    const values = assertArray(document.sections[name], `sections.json.sections.${name}`);
    assertUnique(values, `sections.json.sections.${name}`, (item) => item);
    for (const [index, packageId] of values.entries()) {
      requirePackageId(packageId, `sections.json.sections.${name}[${index}]`);
      const pkg = packagesById.get(packageId);
      if (!pkg) fail(`sections.json.sections.${name} references unknown package ${packageId}.`);
      if (pkg.status === "revoked") fail(`sections.json.sections.${name} references revoked package ${packageId}.`);
      if (name === "firstRun") {
        const installable = pkg.status === "active" && pkg.versions.some((version) => (
          version.status === "active" && version.channel === "stable"
        ));
        if (!installable) fail(`sections.json.sections.firstRun references non-installable package ${packageId}.`);
      }
    }
  }
}

function scanStrictObjectSchemas(value, path) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => scanStrictObjectSchemas(item, `${path}[${index}]`));
    return;
  }
  if (!isObject(value)) return;
  if (value.type === "object" && hasOwn(value, "properties") && value.additionalProperties !== false) {
    fail(`${path} defines an object without additionalProperties: false.`);
  }
  for (const [key, child] of Object.entries(value)) scanStrictObjectSchemas(child, `${path}.${key}`);
}

function validateSchemaFiles(rootDir) {
  for (const file of schemaFiles) {
    const path = join(rootDir, "schemas", file);
    const schema = readJson(path, `schemas/${file}`);
    if (schema.$schema !== "https://json-schema.org/draft/2020-12/schema") {
      fail(`schemas/${file} must use JSON Schema draft 2020-12.`);
    }
    if (schema.type !== "object" || schema.additionalProperties !== false) {
      fail(`schemas/${file} must be a strict root object schema.`);
    }
    scanStrictObjectSchemas(schema, `schemas/${file}`);
  }
}

function loadPackages(rootDir) {
  const packageDir = join(rootDir, "packages");
  const files = readdirSync(packageDir)
    .filter((file) => file.endsWith(".json"))
    .sort();
  return {
    files,
    packages: files.map((file) => readJson(join(packageDir, file), `packages/${file}`))
  };
}

export function validateMarketplaceSources({ rootDir = marketplaceRoot } = {}) {
  validateSchemaFiles(rootDir);
  const developers = readJson(join(rootDir, "developers.json"), "developers.json");
  const sections = readJson(join(rootDir, "sections.json"), "sections.json");
  const { files, packages } = loadPackages(rootDir);
  const developersById = validateDeveloperDocument(developers);
  const packagesById = validatePackageDocuments(packages, developersById, files);
  validateSectionsDocument(sections, packagesById);
  return { developers, packages, sections };
}

export function validateCatalogue(catalogue) {
  assertObject(catalogue, "catalogue", [
    "schema",
    "sequence",
    "generatedAt",
    "expiresAt",
    "sections",
    "developers",
    "packages"
  ]);
  if (catalogue.schema !== "bakingrl.marketplace/2") {
    fail("catalogue.schema must be bakingrl.marketplace/2.");
  }
  requireSafeInteger(catalogue.sequence, "catalogue.sequence", 1);
  const generatedAt = requireTimestamp(catalogue.generatedAt, "catalogue.generatedAt");
  const expiresAt = requireTimestamp(catalogue.expiresAt, "catalogue.expiresAt");
  if (expiresAt <= generatedAt) fail("catalogue.expiresAt must be later than catalogue.generatedAt.");

  const developers = {
    schema: "bakingrl.marketplace-developers/2",
    developers: catalogue.developers
  };
  const sections = {
    schema: "bakingrl.marketplace-sections/2",
    sections: catalogue.sections
  };
  const developersById = validateDeveloperDocument(developers);
  const packagesById = validatePackageDocuments(catalogue.packages, developersById);
  validateSectionsDocument(sections, packagesById);
  return catalogue;
}

function normalizeBuildTimestamp(value, fallback, label) {
  const date = value === undefined ? fallback : requireTimestamp(value, label);
  return date.toISOString();
}

export function buildMarketplace({
  rootDir = marketplaceRoot,
  outputDir = join(rootDir, "public"),
  sequence,
  generatedAt,
  expiresAt,
  now = new Date()
} = {}) {
  const source = validateMarketplaceSources({ rootDir });
  const generatedAtValue = normalizeBuildTimestamp(generatedAt, new Date(now), "generatedAt");
  const generatedDate = new Date(generatedAtValue);
  const expiresAtValue = normalizeBuildTimestamp(
    expiresAt,
    new Date(generatedDate.getTime() + DEFAULT_CATALOGUE_VALIDITY_MS),
    "expiresAt"
  );
  const sequenceValue = sequence === undefined ? generatedDate.getTime() : Number(sequence);
  requireSafeInteger(sequenceValue, "sequence", 1);

  const catalogue = {
    schema: "bakingrl.marketplace/2",
    sequence: sequenceValue,
    generatedAt: generatedAtValue,
    expiresAt: expiresAtValue,
    sections: source.sections.sections,
    developers: source.developers.developers,
    packages: source.packages
  };
  validateCatalogue(catalogue);

  const indexPath = join(outputDir, "marketplace.json");
  if (existsSync(indexPath)) {
    const previous = readJson(indexPath, indexPath);
    if (previous.schema === "bakingrl.marketplace/2") {
      if (previous.sequence > catalogue.sequence) {
        fail(`Refusing to decrease catalogue sequence from ${previous.sequence} to ${catalogue.sequence}.`);
      }
      if (previous.sequence === catalogue.sequence && canonicalJson(previous) !== canonicalJson(catalogue)) {
        fail(`Refusing to reuse catalogue sequence ${catalogue.sequence} for different contents.`);
      }
    }
  }
  writeJson(indexPath, catalogue);
  rmSync(join(outputDir, "marketplace.sig"), { force: true });
  return { catalogue, indexPath };
}

function rawPublicKeyFromKeyObject(publicKey) {
  const der = publicKey.export({ type: "spki", format: "der" });
  const header = Buffer.from("302a300506032b6570032100", "hex");
  if (der.length !== header.length + 32 || !der.subarray(0, header.length).equals(header)) {
    fail("Ed25519 public key has an unsupported SPKI encoding.");
  }
  return der.subarray(header.length);
}

function publicKeyFromRaw(raw) {
  const header = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({
    key: Buffer.concat([header, raw]),
    type: "spki",
    format: "der"
  });
}

function validateRootKey(value, label, requirePrivate = false) {
  assertObject(value, label, ["schema", "keyId", "algorithm", "publicKey"], ["privateKeyPem"]);
  const allowedSchemas = new Set([
    "bakingrl.marketplace-signing-key/1",
    "bakingrl.marketplace-verification-key/1"
  ]);
  requireEnum(value.schema, allowedSchemas, `${label}.schema`);
  requireSlugId(value.keyId, `${label}.keyId`);
  if (value.algorithm !== "ed25519") fail(`${label}.algorithm must be ed25519.`);
  decodeCanonicalBase64(value.publicKey, 32, `${label}.publicKey`);
  if (requirePrivate && !hasOwn(value, "privateKeyPem")) fail(`${label}.privateKeyPem is required for signing.`);
  if (hasOwn(value, "privateKeyPem")) requireString(value.privateKeyPem, `${label}.privateKeyPem`);
  return value;
}

export function generateSigningKey({ targetPath, keyId } = {}) {
  if (!targetPath) fail("targetPath is required.");
  requireSlugId(keyId, "keyId");
  if (existsSync(targetPath)) fail(`Refusing to overwrite existing key file: ${targetPath}`);
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const document = {
    schema: "bakingrl.marketplace-signing-key/1",
    keyId,
    algorithm: "ed25519",
    publicKey: rawPublicKeyFromKeyObject(publicKey).toString("base64"),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" })
  };
  writeJson(targetPath, document, 0o600);
  return document;
}

function validateSignatureDocument(value) {
  assertObject(value, "signature", [
    "schema",
    "algorithm",
    "keyId",
    "signedFile",
    "sha256",
    "signature"
  ]);
  if (value.schema !== "bakingrl.marketplace-signature/2") {
    fail("signature.schema must be bakingrl.marketplace-signature/2.");
  }
  if (value.algorithm !== "ed25519") fail("signature.algorithm must be ed25519.");
  requireSlugId(value.keyId, "signature.keyId");
  if (value.signedFile !== "marketplace.json") fail("signature.signedFile must be marketplace.json.");
  requireSha256(value.sha256, "signature.sha256");
  decodeCanonicalBase64(value.signature, 64, "signature.signature");
  return value;
}

export function signMarketplace({
  indexPath = defaultIndexPath,
  signaturePath = defaultSignaturePath,
  keyPath
} = {}) {
  if (!keyPath) fail("keyPath is required.");
  if (!existsSync(indexPath)) fail(`Catalogue does not exist: ${indexPath}`);
  const raw = readFileSync(indexPath);
  let catalogue;
  try {
    catalogue = JSON.parse(raw.toString("utf8"));
  } catch (error) {
    fail(`Unable to parse catalogue before signing: ${error.message}`);
  }
  validateCatalogue(catalogue);

  const key = validateRootKey(readJson(keyPath, keyPath), "signing key", true);
  let privateKey;
  try {
    privateKey = createPrivateKey(key.privateKeyPem);
  } catch (error) {
    fail(`Unable to parse signing key privateKeyPem: ${error.message}`);
  }
  const derivedPublic = rawPublicKeyFromKeyObject(createPublicKey(privateKey)).toString("base64");
  if (derivedPublic !== key.publicKey) fail("Signing key publicKey does not match privateKeyPem.");

  const signature = {
    schema: "bakingrl.marketplace-signature/2",
    algorithm: "ed25519",
    keyId: key.keyId,
    signedFile: "marketplace.json",
    sha256: createHash("sha256").update(raw).digest("hex"),
    signature: sign(null, raw, privateKey).toString("base64")
  };
  validateSignatureDocument(signature);
  writeJson(signaturePath, signature);
  return { signature, signaturePath };
}

export function verifyMarketplace({
  indexPath = defaultIndexPath,
  signaturePath = defaultSignaturePath,
  keyPath,
  minSequence = 0,
  now = new Date(),
  allowExpired = false
} = {}) {
  if (!keyPath) fail("keyPath is required.");
  requireSafeInteger(Number(minSequence), "minSequence", 0);
  const raw = readFileSync(indexPath);
  let catalogue;
  try {
    catalogue = JSON.parse(raw.toString("utf8"));
  } catch (error) {
    fail(`Unable to parse catalogue: ${error.message}`);
  }
  validateCatalogue(catalogue);
  const signature = validateSignatureDocument(readJson(signaturePath, signaturePath));
  const key = validateRootKey(readJson(keyPath, keyPath), "verification key");
  if (signature.keyId !== key.keyId) {
    fail(`Signature keyId ${signature.keyId} does not match trusted key ${key.keyId}.`);
  }

  const digest = createHash("sha256").update(raw).digest("hex");
  if (digest !== signature.sha256) fail("Catalogue SHA-256 does not match the signature envelope.");
  const publicKey = publicKeyFromRaw(decodeCanonicalBase64(key.publicKey, 32, "verification key.publicKey"));
  const signatureBytes = decodeCanonicalBase64(signature.signature, 64, "signature.signature");
  if (!verify(null, raw, publicKey, signatureBytes)) fail("Catalogue Ed25519 signature is invalid.");

  const minimum = Number(minSequence);
  if (catalogue.sequence < minimum) {
    fail(`Catalogue sequence ${catalogue.sequence} is below required sequence ${minimum}.`);
  }
  const nowMs = new Date(now).getTime();
  if (!Number.isFinite(nowMs)) fail("now must be a valid date.");
  const generatedAt = Date.parse(catalogue.generatedAt);
  const expiresAt = Date.parse(catalogue.expiresAt);
  if (generatedAt > nowMs + CLOCK_TOLERANCE_MS) {
    fail("Catalogue generatedAt is too far in the future.");
  }
  if (!allowExpired && expiresAt < nowMs - CLOCK_TOLERANCE_MS) {
    fail("Catalogue is expired beyond the 24-hour clock tolerance.");
  }
  return { catalogue, signature };
}

function parseOptions(args, valueOptions, flagOptions = []) {
  const values = new Set(valueOptions);
  const flags = new Set(flagOptions);
  const parsed = {};
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (!argument.startsWith("--")) fail(`Unexpected argument ${argument}.`);
    const name = argument.slice(2);
    if (hasOwn(parsed, name)) fail(`Option --${name} was provided more than once.`);
    if (flags.has(name)) {
      parsed[name] = true;
      continue;
    }
    if (!values.has(name)) fail(`Unknown option --${name}.`);
    const value = args[index + 1];
    if (value === undefined || value.startsWith("--")) fail(`Option --${name} requires a value.`);
    parsed[name] = value;
    index += 1;
  }
  return parsed;
}

function cli() {
  const [command, ...args] = process.argv.slice(2);
  if (command === "validate") {
    if (args.length > 0) fail("validate does not accept options.");
    validateMarketplaceSources();
    console.log("Marketplace validation passed.");
    return;
  }
  if (command === "build") {
    const options = parseOptions(args, ["sequence", "generated-at", "expires-at"]);
    const result = buildMarketplace({
      sequence: options.sequence ?? process.env.BAKINGRL_MARKETPLACE_SEQUENCE,
      generatedAt: options["generated-at"] ?? process.env.BAKINGRL_MARKETPLACE_GENERATED_AT,
      expiresAt: options["expires-at"] ?? process.env.BAKINGRL_MARKETPLACE_EXPIRES_AT
    });
    console.log(`Built ${result.indexPath} at sequence ${result.catalogue.sequence}.`);
    return;
  }
  if (command === "sign") {
    const options = parseOptions(args, ["key"]);
    if (!options.key) fail("Usage: marketplace.mjs sign --key <key-file>");
    const result = signMarketplace({ keyPath: resolve(process.cwd(), options.key) });
    console.log(`Signed ${defaultIndexPath} with key ${result.signature.keyId}.`);
    return;
  }
  if (command === "verify") {
    const options = parseOptions(args, ["key", "min-sequence", "now"], ["allow-expired"]);
    if (!options.key) fail("Usage: marketplace.mjs verify --key <trusted-key-file>");
    const result = verifyMarketplace({
      keyPath: resolve(process.cwd(), options.key),
      minSequence: options["min-sequence"] ?? 0,
      now: options.now ? new Date(options.now) : new Date(),
      allowExpired: options["allow-expired"] === true
    });
    console.log(`Verified ${defaultIndexPath} at sequence ${result.catalogue.sequence}.`);
    return;
  }
  if (command === "keygen") {
    const options = parseOptions(args, ["key-id", "out"]);
    if (!options["key-id"]) fail("Usage: marketplace.mjs keygen --key-id <id> [--out <key-file>]");
    const targetPath = resolve(
      process.cwd(),
      options.out ?? "bakingrl-marketplace-signing-key.json"
    );
    generateSigningKey({ targetPath, keyId: options["key-id"] });
    console.log(`Created signing key ${targetPath}.`);
    return;
  }
  fail("Usage: marketplace.mjs <validate|build|sign|verify|keygen>");
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    cli();
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  }
}
