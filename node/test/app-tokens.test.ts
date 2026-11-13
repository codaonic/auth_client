import { SignJWT } from "jose";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

import { AuthServiceClient, IntrospectionError, TokenExchangeError } from "../src/app-client";
import { TokenValidationError } from "../src/validator";
import { createKeypair, ISSUER, type TestKeypair } from "./helpers";
import { startJwksServer, type JwksServer } from "./jwks-server";

const EVENT = "http://schemas.openid.net/event/backchannel-logout";

let keypair: TestKeypair;
let jwks: JwksServer;

beforeAll(async () => {
  keypair = await createKeypair();
  jwks = await startJwksServer(keypair.jwks);
});
afterAll(() => jwks.server.close());

function sign(claims: Record<string, unknown>, typ?: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ aud: "my-app", ...claims })
    .setProtectedHeader({ alg: "RS256", kid: keypair.kid, ...(typ ? { typ } : {}) })
    .setIssuer(`${ISSUER}/`)
    .setIssuedAt(now)
    .setExpirationTime(now + 300)
    .sign(keypair.privateKey);
}

function client(fetchImpl?: typeof fetch) {
  return new AuthServiceClient(ISSUER, "my-app", { clientSecret: "s3cret", jwksUrl: jwks.url, fetch: fetchImpl });
}

function reply(status: number, body: unknown, seen: Request[] = []): typeof fetch {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    seen.push(new Request(String(input), init));
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  }) as typeof fetch;
}

describe("tokens issued to the app", () => {
  it("verifies an ID token and its nonce", async () => {
    const token = await sign({ sub: "u1", azp: "my-app", at_hash: "x", nonce: "n1", email: "a@b.c" }, "JWT");
    expect((await client().verifyIdToken(token, "n1")).email).toBe("a@b.c");
    await expect(client().verifyIdToken(token, "other")).rejects.toBeInstanceOf(TokenValidationError);
  });

  it("refuses access and logout tokens as ID tokens", async () => {
    await expect(client().verifyIdToken(await sign({ sub: "u1" }, "at+jwt"))).rejects.toBeInstanceOf(TokenValidationError);
    await expect(client().verifyIdToken(await sign({ sub: "u1", events: { [EVENT]: {} } }, "logout+jwt"))).rejects.toBeInstanceOf(
      TokenValidationError,
    );
  });

  it("verifies a back-channel logout token", async () => {
    const token = await sign({ sub: "u1", sid: "s1", events: { [EVENT]: {} } }, "logout+jwt");
    expect((await client().verifyLogoutToken(token)).sid).toBe("s1");
    await expect(client().verifyLogoutToken(await sign({ sub: "u1" }, "logout+jwt"))).rejects.toBeInstanceOf(TokenValidationError);
  });
});

describe("refresh and introspect", () => {
  it("refreshes", async () => {
    const seen: Request[] = [];
    const body = await client(reply(200, { access_token: "at", refresh_token: "rt2" }, seen)).refresh("rt1");
    expect(body.refresh_token).toBe("rt2");
    const form = new URLSearchParams(await seen[0].text());
    expect(form.get("grant_type")).toBe("refresh_token");
    expect(form.get("client_secret")).toBe("s3cret");
  });

  it("reports a refused refresh", async () => {
    await expect(client(reply(400, { detail: "invalid_grant" })).refresh("rt1")).rejects.toMatchObject({
      error: "invalid_grant",
    });
    await expect(client(reply(400, { detail: "invalid_grant" })).refresh("rt1")).rejects.toBeInstanceOf(TokenExchangeError);
  });

  it("introspects with basic auth", async () => {
    const seen: Request[] = [];
    expect(await client(reply(200, { active: false }, seen)).introspect("t")).toEqual({ active: false });
    expect(seen[0].url).toBe(`${ISSUER}/introspect`);
    expect(seen[0].headers.get("authorization")).toMatch(/^Basic /);
    await expect(client(reply(401, { detail: "invalid_client" })).introspect("t")).rejects.toBeInstanceOf(IntrospectionError);
  });

  it("puts the ID token hint in the logout URL", () => {
    expect(client().logoutUrl({ idTokenHint: "idt" })).toContain("id_token_hint=idt");
  });
});
