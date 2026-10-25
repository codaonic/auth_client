import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { TokenValidationError, TokenValidator } from "../src/validator";
import { createKeypair, ISSUER, makeToken, RESOURCE_ID, type TestKeypair } from "./helpers";
import { startJwksServer, type JwksServer } from "./jwks-server";

describe("TokenValidator", () => {
  let keypair: TestKeypair;
  let jwks: JwksServer;

  beforeEach(async () => {
    keypair = await createKeypair();
    jwks = await startJwksServer(keypair.jwks);
  });

  afterEach(() => {
    jwks.server.close();
  });

  it("returns claims for a valid token", async () => {
    const validator = new TokenValidator(ISSUER, RESOURCE_ID, { jwksUrl: jwks.url });
    const token = await makeToken(keypair, { sub: "user-123" });

    const claims = await validator.validate(token);

    expect(claims.sub).toBe("user-123");
    expect(claims.aud).toBe(RESOURCE_ID);
  });

  it("rejects wrong audience", async () => {
    const validator = new TokenValidator(ISSUER, RESOURCE_ID, { jwksUrl: jwks.url });
    const token = await makeToken(keypair, { aud: "https://other.example.com" });

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);
  });

  it("rejects wrong issuer", async () => {
    const validator = new TokenValidator(ISSUER, RESOURCE_ID, { jwksUrl: jwks.url });
    const token = await makeToken(keypair, { iss: "https://not-the-real-as.example.com" });

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);
  });

  it("rejects an expired token", async () => {
    const validator = new TokenValidator(ISSUER, RESOURCE_ID, { jwksUrl: jwks.url });
    const token = await makeToken(keypair, { ttlSeconds: -60 });

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);
  });

  it("rejects an unknown kid", async () => {
    const emptyJwks = await startJwksServer({ keys: [] });
    const validator = new TokenValidator(ISSUER, RESOURCE_ID, { jwksUrl: emptyJwks.url });
    const token = await makeToken(keypair);

    await expect(validator.validate(token)).rejects.toThrow(TokenValidationError);

    emptyJwks.server.close();
  });

  it("checks scope membership", async () => {
    const validator = new TokenValidator(ISSUER, RESOURCE_ID, { jwksUrl: jwks.url });
    const token = await makeToken(keypair, { scope: "profile email" });

    const claims = await validator.validate(token);

    expect(TokenValidator.hasScope(claims, "profile")).toBe(true);
    expect(TokenValidator.hasScope(claims, "admin")).toBe(false);
  });

  it("caches the JWKS across calls", async () => {
    const validator = new TokenValidator(ISSUER, RESOURCE_ID, { jwksUrl: jwks.url });
    const token = await makeToken(keypair);

    await validator.validate(token);
    await validator.validate(token);

    expect(jwks.callCount()).toBe(1);
  });

  it("accepts only listed clients when allowedClientIds is set", async () => {
    const validator = new TokenValidator(ISSUER, RESOURCE_ID, { jwksUrl: jwks.url, allowedClientIds: ["my-app"] });

    const claims = await validator.validate(await makeToken(keypair, { clientId: "my-app" }));
    expect(claims.client_id).toBe("my-app");
    await expect(validator.validate(await makeToken(keypair, { clientId: "someone-else" }))).rejects.toThrow(
      TokenValidationError,
    );
  });

  it("accepts any client when allowedClientIds is not set", async () => {
    const validator = new TokenValidator(ISSUER, RESOURCE_ID, { jwksUrl: jwks.url });
    const claims = await validator.validate(await makeToken(keypair, { clientId: "anything" }));
    expect(claims.client_id).toBe("anything");
  });

  it("does not refetch the JWKS for every unknown kid", async () => {
    const validator = new TokenValidator(ISSUER, RESOURCE_ID, { jwksUrl: jwks.url });
    await validator.validate(await makeToken(keypair));
    const madeUp = { ...keypair, kid: "made-up" };

    for (let i = 0; i < 5; i++) {
      await expect(validator.validate(await makeToken(madeUp))).rejects.toThrow(TokenValidationError);
    }
    expect(jwks.callCount()).toBe(1);
  });
});
