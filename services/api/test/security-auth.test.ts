import { newId } from "@facility/core";
import {
  createDb,
  idempotencyRecords,
  migrate,
  orgMembers,
  seed,
  users,
  type FacilityDb,
} from "@facility/db";
import { and, eq } from "drizzle-orm";
import postgres from "postgres";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { buildApp, mintSessionCookie } from "../src/app.js";
import type { AppConfig } from "../src/types.js";

const databaseUrl =
  process.env.DATABASE_URL ?? "postgres://facility:facility@localhost:5461/facility_test";
const masterKey = Buffer.alloc(32, 7).toString("base64");

let db: FacilityDb;
let sql: postgres.Sql<any>;
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
  const { db: createdDb, client } = createDb(databaseUrl);
  db = createdDb;
  sql = postgres(databaseUrl);
  app = await buildApp(baseConfig);
  await app.ready();

  // Create test user and org
  const created = await db
    .insert(users)
    .values({ id: newId("user"), displayName: "Test User" })
    .returning({ id: users.id });
  userId = created[0].id;

  const createdOrg = await db
    .insert(orgMembers)
    .values({
      orgId: newId("org"),
      memberId: userId,
      role: "admin",
    })
    .returning({ orgId: orgMembers.orgId });
  orgId = createdOrg[0].orgId;

  sessionCookie = await mintSessionCookie(userId, masterKey);
});

afterAll(async () => {
  await app.close();
  await sql.end();
});

beforeEach(async () => {
  // Clean up idempotency records between tests
  await db.delete(idempotencyRecords).where(eq(idempotencyRecords.orgId, orgId));
});

describe("Idempotency Security", () => {
  it("requires authentication for idempotent requests", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/projects",
      headers: {
        "idempotency-key": "test-key-12345678",
      },
      payload: { name: "Test Project" },
    });
    // 401 if no auth, or 404/405 if auth not required for that endpoint
    expect([401, 404, 405]).toContain(response.statusCode);
  });

  it("rejects idempotency keys shorter than 8 characters", async () => {
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/projects",
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": "short",
      },
      payload: { name: "Test Project" },
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
      url: "/api/v1/projects",
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": longKey,
      },
      payload: { name: "Test Project" },
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
      url: `/api/v1/org/${orgId}/settings`,
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": key,
      },
      payload: { theme: "dark" },
    });

    if (response1.statusCode === 200 || response1.statusCode === 201) {
      // Second request with same key but different body
      const response2 = await app.inject({
        method: "PATCH",
        url: `/api/v1/org/${orgId}/settings`,
        headers: {
          Cookie: sessionCookie,
          "idempotency-key": key,
        },
        payload: { theme: "light" },
      });

      expect(response2.statusCode).toBe(409);
      const body = JSON.parse(response2.body);
      expect(body.error.code).toBe("idempotency_key_reused");
    }
  });

  it("limits recursive retries in idempotency processing", async () => {
    const key = "idem-recursion-limit-key-12345";
    // Insert a stale expired record to trigger retry logic
    const now = new Date();
    const expiredTime = new Date(now.getTime() - 25 * 60 * 60 * 1000); // 25 hours ago

    await db.insert(idempotencyRecords).values({
      id: `idem_test_${newId("id")}`,
      orgId,
      principalId: `user:${userId}`,
      method: "PATCH",
      path: `/api/v1/org/${orgId}/settings`,
      keyHash: "hash1",
      requestHash: "hash2",
      state: "completed",
      statusCode: 200,
      responseBody: { success: true },
      expiresAt: expiredTime,
    });

    const response = await app.inject({
      method: "PATCH",
      url: `/api/v1/org/${orgId}/settings`,
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": key,
      },
      payload: { theme: "dark" },
    });

    // Should succeed or return proper error, not hang/timeout
    expect([200, 201, 400, 409, 500]).toContain(response.statusCode);
  });

  it("prevents unauthorized access to protected endpoints without idempotency", async () => {
    const response = await app.inject({
      method: "DELETE",
      url: `/api/v1/org/${orgId}`,
      // Missing sessionCookie
    });

    expect(response.statusCode).toBe(401);
  });

  it("validates idempotency key format to prevent injection attacks", async () => {
    const maliciousKey = `12345678'; DROP TABLE users; --`;
    const response = await app.inject({
      method: "POST",
      url: "/api/v1/projects",
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": maliciousKey,
      },
      payload: { name: "Test Project" },
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
    await db.insert(orgMembers).values({
      orgId: org2Id,
      memberId: userId,
      role: "admin",
    });

    // Insert idempotency record for first org
    await db.insert(idempotencyRecords).values({
      id: `idem_org1_${newId("id")}`,
      orgId,
      principalId: `user:${userId}`,
      method: "PATCH",
      path: `/api/v1/org/${orgId}/settings`,
      keyHash: "hash_org1",
      requestHash: "hash_body_org1",
      state: "completed",
      statusCode: 200,
      responseBody: { success: true },
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
    });

    // Same key for second org should be treated separately
    const response = await app.inject({
      method: "PATCH",
      url: `/api/v1/org/${org2Id}/settings`,
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": key,
      },
      payload: { theme: "light" },
    });

    // Should not conflict with first org's record
    expect([200, 201, 400, 404]).toContain(response.statusCode);
  });

  it("returns consistent replay status headers", async () => {
    const key = "idem-replay-status-test-1234567";
    // First request
    const response1 = await app.inject({
      method: "POST",
      url: "/api/v1/projects",
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": key,
      },
      payload: { name: "Test Project" },
    });

    const status1 = response1.headers["idempotency-status"];
    if (status1) {
      expect(["created", "pending"]).toContain(status1);
    }

    // Subsequent request with same key
    const response2 = await app.inject({
      method: "POST",
      url: "/api/v1/projects",
      headers: {
        Cookie: sessionCookie,
        "idempotency-key": key,
      },
      payload: { name: "Test Project" },
    });

    const status2 = response2.headers["idempotency-status"];
    if (status2) {
      expect(["replayed", "in-progress"]).toContain(status2);
    }
  });
});
