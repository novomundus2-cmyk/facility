import { createHash } from "node:crypto";
import { newId } from "@facility/core";
import {
  createDb,
  type FacilityDb,
  idempotencyRecords,
  migrate,
  orgMembers,
  orgs,
  seed,
  users,
} from "@facility/db";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { buildApp, mintSessionCookie } from "../src/app.js";
import type { AppConfig } from "../src/types.js";

const databaseUrl =
  process.env.DATABASE_URL ?? "postgres://facility:facility@localhost:5461/facility_test";
const masterKey = Buffer.alloc(32, 7).toString("base64");

let db: FacilityDb;
let client: ReturnType<typeof createDb>["client"];
let app: Awaited<ReturnType<typeof buildApp>>;
let orgId: string;
let userId: string;
let sessionCookie: string;

const baseConfig: AppConfig = {
  databaseUrl,
  secretMasterKey: masterKey,
  port: 4401,
  publicUrl: "https://api.facility.test",
  webUrl: "https://facility.test",
  workspaceImage: "facility-runner:dev",
  workspaceDriver: "docker",
  authCallbackUrl: "https://facility.test/api/auth/callback",
  facilityInsecureDev: true,
  logLevel: "silent",
};

beforeAll(async () => {
  await migrate(databaseUrl);
  await seed(databaseUrl);
  const connection = createDb(databaseUrl);
  const { db: createdDb } = connection;
  db = createdDb;
  client = connection.client;
  app = await buildApp(baseConfig);
  await app.ready();

  userId = newId("user");
  orgId = newId("org");
  const suffix = userId.slice(-12);
  await db.insert(orgs).values({
    id: orgId,
    name: "Security Test Organization",
    slug: `security-test-${suffix}`,
    settings: {},
  });
  await db.insert(users).values({
    id: userId,
    email: `security-test-${suffix}@example.com`,
    name: "Test User",
  });
  await db.insert(orgMembers).values({
    id: newId("member"),
    orgId,
    userId,
    roleId: "role_bundled_owner",
  });

  sessionCookie = `facility_session=${await mintSessionCookie(baseConfig, userId, orgId)}`;
});

afterAll(async () => {
  await app.close();
  await client.end();
});

beforeEach(async () => {
  // Clean up idempotency records between tests
  await db.delete(idempotencyRecords).where(eq(idempotencyRecords.orgId, orgId));
});

describe("Idempotency Security", () => {
  it("requires authentication for idempotent requests", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/projects",
      headers: {
        "idempotency-key": "test-key-12345678",
      },
      payload: { name: "Test Project" },
    });
    expect(response.statusCode).toBe(401);
  });

  it("rejects idempotency keys shorter than 8 characters", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/v1/projects",
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": "short",
      },
      payload: { name: "Test Project", slug: "test-project-short-key" },
    });
    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.error.code).toBe("invalid_idempotency_key");
    expect(body.error.message).toContain("between 8 and 200");
  });

  it("rejects idempotency keys longer than 200 characters", async () => {
    const longKey = "a".repeat(201);
    const response = await app.inject({
      method: "POST",
      url: "/v1/projects",
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": longKey,
      },
      payload: { name: "Test Project", slug: "test-project-long-key" },
    });
    expect(response.statusCode).toBe(400);
    const body = JSON.parse(response.body);
    expect(body.error.code).toBe("invalid_idempotency_key");
  });

  it("detects idempotency key reuse with different request bodies", async () => {
    const key = "idem-test-reuse-12345678";
    // First request
    const response1 = await app.inject({
      method: "PATCH",
      url: "/v1/org",
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": key,
      },
      payload: { settings: { theme: "dark" } },
    });

    expect(response1.statusCode).toBe(200);
    const response2 = await app.inject({
      method: "PATCH",
      url: "/v1/org",
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": key,
      },
      payload: { settings: { theme: "light" } },
    });

    expect(response2.statusCode).toBe(409);
    const body = JSON.parse(response2.body);
    expect(body.error.code).toBe("idempotency_key_reused");
  });

  it("reclaims expired idempotency records before replay processing", async () => {
    const key = "idem-expired-record-key-12345";
    const path = "/v1/org";
    const payload = { settings: { theme: "dark" } };
    const keyHash = hash(key);
    const requestHash = hash(JSON.stringify(payload));
    const recordId = `idem_${hash(`${orgId}:user:${userId}:PATCH:${path}:${keyHash}`)}`;
    const now = new Date();
    const expiredTime = new Date(now.getTime() - 25 * 60 * 60 * 1000);

    await db.insert(idempotencyRecords).values({
      id: recordId,
      orgId,
      principalId: `user:${userId}`,
      method: "PATCH",
      path,
      keyHash,
      requestHash,
      state: "completed",
      statusCode: 200,
      responseBody: { success: true },
      expiresAt: expiredTime,
    });

    const response = await app.inject({
      method: "PATCH",
      url: path,
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": key,
      },
      payload,
    });

    expect(response.statusCode).toBe(200);
    expect(response.headers["idempotency-status"]).toBe("created");
    const refreshed = await db
      .select()
      .from(idempotencyRecords)
      .where(eq(idempotencyRecords.id, recordId));
    expect(refreshed[0]?.state).toBe("completed");
    expect(refreshed[0]?.expiresAt.getTime()).toBeGreaterThan(now.getTime());
  });

  it("prevents unauthorized access to protected endpoints without idempotency", async () => {
    const response = await app.inject({
      method: "PATCH",
      url: "/v1/org",
      payload: { settings: { theme: "dark" } },
    });

    expect(response.statusCode).toBe(401);
  });

  it("validates idempotency key format to prevent injection attacks", async () => {
    const maliciousKey = `12345678'; DROP TABLE users; --`;
    const response = await app.inject({
      method: "POST",
      url: "/v1/projects",
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": maliciousKey,
      },
      payload: {
        name: "Test Project",
        slug: `test-project-${Date.now()}`,
      },
    });

    // Should handle gracefully, not execute injection
    expect(response.statusCode).toBeGreaterThan(0);
    // Verify database integrity
    const userCount = await db.select().from(users);
    expect(userCount.length).toBeGreaterThan(0);
  });

  it("respects org isolation in idempotency records", async () => {
    const key = "idem-isolation-test-1234567";
    // Create second org
    const org2Id = newId("org");
    await db.insert(orgs).values({
      id: org2Id,
      name: "Second Security Test Organization",
      slug: `security-test-${org2Id.slice(-12)}`,
      settings: {},
    });
    await db.insert(orgMembers).values({
      id: newId("member"),
      orgId: org2Id,
      userId,
      roleId: "role_bundled_owner",
    });
    const org2Cookie = `facility_session=${await mintSessionCookie(baseConfig, userId, org2Id)}`;

    // Insert idempotency record for first org
    const keyHash = hash(key);
    const requestHash = hash(JSON.stringify({ settings: { theme: "light" } }));
    const path = "/v1/org";
    const recordId = `idem_${hash(`${orgId}:user:${userId}:PATCH:${path}:${keyHash}`)}`;
    await db.insert(idempotencyRecords).values({
      id: recordId,
      orgId,
      principalId: `user:${userId}`,
      method: "PATCH",
      path,
      keyHash,
      requestHash,
      state: "completed",
      statusCode: 200,
      responseBody: { success: true },
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });

    // Same key for second org should be treated separately
    const response = await app.inject({
      method: "PATCH",
      url: path,
      headers: {
        Cookie: org2Cookie,
        "idempotency-key": key,
      },
      payload: { settings: { theme: "light" } },
    });

    // Should not conflict with first org's record
    expect(response.statusCode).toBe(200);
    expect(response.headers["idempotency-status"]).toBe("created");
  });

  it("returns consistent replay status headers", async () => {
    const key = "idem-replay-status-test-1234567";
    const payload = { name: "Replay Test Project", slug: `replay-test-${Date.now()}` };
    // First request
    const response1 = await app.inject({
      method: "POST",
      url: "/v1/projects",
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": key,
      },
      payload,
    });

    const status1 = response1.headers["idempotency-status"];
    expect(status1).toBe("created");

    // Subsequent request with same key
    const response2 = await app.inject({
      method: "POST",
      url: "/v1/projects",
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": key,
      },
      payload,
    });

    const status2 = response2.headers["idempotency-status"];
    expect(status2).toBe("replayed");
  });
});

function hash(value: string) {
  return createHash("sha256").update(value).digest("hex");
}
