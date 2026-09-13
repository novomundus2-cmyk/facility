import { execFileSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const rootUrl = "postgres://facility:facility@127.0.0.1:1/seed_env_test";
let fixtureRoot: string;
let fixturePackage: string;

beforeAll(async () => {
  fixtureRoot = await mkdtemp(join(tmpdir(), "facility-seed-env-"));
  fixturePackage = join(fixtureRoot, "packages/db");
  await mkdir(join(fixturePackage, "src"), { recursive: true });
  await copyFile(join(packageRoot, "src/seed.ts"), join(fixturePackage, "src/seed.ts"));
  await symlink(join(packageRoot, "node_modules"), join(fixturePackage, "node_modules"));
  await writeFile(join(fixturePackage, "package.json"), '{"type":"module"}\n');
  await writeFile(join(fixtureRoot, ".env"), `DATABASE_URL=${rootUrl}\n`);
});

afterAll(async () => {
  if (fixtureRoot) await rm(fixtureRoot, { recursive: true, force: true });
});

function loadSeedDatabaseUrl(explicitUrl?: string): string {
  const env = { ...process.env };
  if (explicitUrl) env.DATABASE_URL = explicitUrl;
  else delete env.DATABASE_URL;
  return execFileSync(
    process.execPath,
    [
      "--import",
      "tsx",
      "--input-type=module",
      "-e",
      "await import('./src/seed.ts'); process.stdout.write(process.env.DATABASE_URL ?? 'missing');",
    ],
    { cwd: fixturePackage, encoding: "utf8", env },
  );
}

describe("seed environment", () => {
  it("loads the repository .env when invoked from the package directory", () => {
    expect(loadSeedDatabaseUrl()).toBe(rootUrl);
  });

  it("keeps an explicitly exported database URL", () => {
    const explicitUrl = "postgres://facility:facility@127.0.0.1:1/explicit";
    expect(loadSeedDatabaseUrl(explicitUrl)).toBe(explicitUrl);
  });
});
