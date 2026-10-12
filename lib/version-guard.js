// lib/version-guard.js
// Dependency version guard: detects unauthorized major dependency bumps in package.json (#95).

import fs from "node:fs";
import path from "node:path";

const DEPENDENCY_SECTIONS = [
  "dependencies",
  "devDependencies",
  "peerDependencies",
  "optionalDependencies",
];

const SEMVER_REGEX = /^(?:[\^~>=<v\s]*?)(\d+)(?:\.(\d+))?(?:\.(\d+))?/;

/**
 * Parses semver string into numeric major, minor, and patch components (#95).
 *
 * @param {string} ver
 * @returns {{ major: number, minor: number, patch: number } | null}
 */
export function parseSemver(ver) {
  if (typeof ver !== "string" || !ver.trim()) return null;
  const match = SEMVER_REGEX.exec(ver.trim());
  if (!match) return null;

  return {
    major: parseInt(match[1], 10),
    minor: match[2] !== undefined ? parseInt(match[2], 10) : 0,
    patch: match[3] !== undefined ? parseInt(match[3], 10) : 0,
  };
}

/**
 * Determines whether a version transition represents a major version bump (#95).
 *
 * @param {string} oldVer
 * @param {string} newVer
 * @returns {boolean}
 */
export function isMajorBump(oldVer, newVer) {
  const oldParsed = parseSemver(oldVer);
  const newParsed = parseSemver(newVer);
  if (!oldParsed || !newParsed) return false;

  return newParsed.major > oldParsed.major;
}

/**
 * Compares two dependency maps and returns detected major bumps (#95).
 *
 * @param {Record<string, string>} [oldDeps]
 * @param {Record<string, string>} [newDeps]
 * @param {string} [section="dependencies"]
 * @returns {Array<{ pkg: string, from: string, to: string, section: string }>}
 */
export function compareDependencySection(oldDeps = {}, newDeps = {}, section = "dependencies") {
  if (!oldDeps || !newDeps) return [];
  const bumps = [];

  for (const [pkg, newVer] of Object.entries(newDeps)) {
    const oldVer = oldDeps[pkg];
    if (typeof oldVer === "string" && typeof newVer === "string") {
      if (isMajorBump(oldVer, newVer)) {
        bumps.push({
          pkg,
          from: oldVer,
          to: newVer,
          section,
        });
      }
    }
  }

  return bumps;
}

/**
 * Inspects a mutation between two package.json objects for major dependency bumps (#95).
 *
 * @param {any} oldPkg
 * @param {any} newPkg
 * @returns {{ hasMajorBump: boolean, bumps: Array<{ pkg: string, from: string, to: string, section: string }> }}
 */
export function inspectPackageJsonDiff(oldPkg, newPkg) {
  if (!oldPkg || typeof oldPkg !== "object" || !newPkg || typeof newPkg !== "object") {
    return { hasMajorBump: false, bumps: [] };
  }

  const allBumps = [];

  for (const section of DEPENDENCY_SECTIONS) {
    const oldSec = oldPkg[section] || {};
    const newSec = newPkg[section] || {};
    const sectionBumps = compareDependencySection(oldSec, newSec, section);
    allBumps.push(...sectionBumps);
  }

  return {
    hasMajorBump: allBumps.length > 0,
    bumps: allBumps,
  };
}

/**
 * Guard enforcing human confirmation on major dependency version updates (#95).
 */
export class VersionGuard {
  /**
   * @param {{ workspaceDir?: string }} [options]
   */
  constructor(options = {}) {
    this.workspaceDir = options.workspaceDir || "";
  }

  /**
   * Inspects a file write operation to detect major dependency bumps in package.json (#95).
   *
   * @param {string} targetPath - Path of file being written
   * @param {string | object} newContent - Incoming content or parsed JSON
   * @returns {{ majorBump: boolean, bumps: Array<any>, detail?: string }}
   */
  inspectWrite(targetPath, newContent) {
    if (typeof targetPath !== "string") {
      return { majorBump: false, bumps: [] };
    }

    const basename = path.basename(targetPath);
    if (basename !== "package.json") {
      return { majorBump: false, bumps: [] };
    }

    let parsedNew;
    if (typeof newContent === "string") {
      try {
        parsedNew = JSON.parse(newContent);
      } catch {
        return { majorBump: false, bumps: [] };
      }
    } else if (newContent && typeof newContent === "object") {
      parsedNew = newContent;
    } else {
      return { majorBump: false, bumps: [] };
    }

    // Attempt reading existing package.json
    let existingPkg = null;
    const resolvedPath = path.isAbsolute(targetPath)
      ? targetPath
      : path.resolve(this.workspaceDir || process.cwd(), targetPath);

    try {
      if (fs.existsSync(resolvedPath)) {
        const raw = fs.readFileSync(resolvedPath, "utf-8");
        existingPkg = JSON.parse(raw);
      }
    } catch {
      // ignore read/parse error on existing file
    }

    if (!existingPkg) {
      return { majorBump: false, bumps: [] };
    }

    const diff = inspectPackageJsonDiff(existingPkg, parsedNew);
    if (diff.hasMajorBump) {
      const descriptions = diff.bumps.map((b) => `${b.pkg} (${b.from} -> ${b.to})`).join(", ");
      return {
        majorBump: true,
        bumps: diff.bumps,
        detail: `Major dependency version bump detected: ${descriptions}`,
      };
    }

    return { majorBump: false, bumps: [] };
  }
}
