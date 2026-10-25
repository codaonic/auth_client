import { exportJWK, generateKeyPair, SignJWT, type KeyLike } from "jose";

export const ISSUER = "https://auth.example.com";
export const RESOURCE_ID = "https://api.example.com";

export interface TestKeypair {
  privateKey: KeyLike;
  kid: string;
  jwks: { keys: Record<string, unknown>[] };
}

export async function createKeypair(): Promise<TestKeypair> {
  const { publicKey, privateKey } = await generateKeyPair("RS256");
  const kid = "test-key-1";
  const jwk = await exportJWK(publicKey);
  jwk.kid = kid;
  jwk.use = "sig";
  jwk.alg = "RS256";
  return { privateKey: privateKey as KeyLike, kid, jwks: { keys: [jwk] } };
}

export interface MakeTokenOptions {
  aud?: string;
  iss?: string;
  scope?: string;
  sub?: string;
  ttlSeconds?: number;
  clientId?: string;
}

export async function makeToken(keypair: TestKeypair, opts: MakeTokenOptions = {}): Promise<string> {
  const {
    aud = RESOURCE_ID,
    iss = ISSUER,
    scope = "profile email",
    sub = "user-123",
    ttlSeconds = 600,
    clientId = "my-app",
  } = opts;

  return new SignJWT({ scope, client_id: clientId })
    .setProtectedHeader({ alg: "RS256", kid: keypair.kid })
    .setSubject(sub)
    .setIssuer(iss)
    .setAudience(aud)
    .setIssuedAt()
    .setExpirationTime(Math.floor(Date.now() / 1000) + ttlSeconds)
    .sign(keypair.privateKey);
}
