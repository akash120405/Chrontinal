import { cookies } from "next/headers";
import crypto from "crypto";

const AUTH_COOKIE = "clif_session";
const TOKEN_MAX_AGE = 60 * 60 * 24; // 24 hours in seconds

// Missing or weak configuration disables login rather than enabling known defaults.
function getCredentials() {
  const username = process.env.CLIF_AUTH_USER?.trim();
  const password = process.env.CLIF_AUTH_PASS;
  const secret = process.env.CLIF_AUTH_SECRET;
  if (!username || !password || password.length < 12 || !secret || Buffer.byteLength(secret) < 32) {
    return null;
  }
  return { username, password, secret };
}

export function isAuthConfigured(): boolean {
  return getCredentials() !== null;
}

/** Create a signed session token */
export function createSessionToken(): string {
  const config = getCredentials();
  if (!config) throw new Error("Authentication is not configured");
  const now = Math.floor(Date.now() / 1000);
  const payload = JSON.stringify({
    v: 1,
    iat: now,
    exp: now + TOKEN_MAX_AGE,
  });
  const b64 = Buffer.from(payload).toString("base64url");
  const sig = crypto
    .createHmac("sha256", config.secret)
    .update(b64)
    .digest("base64url");
  return `${b64}.${sig}`;
}

/** Verify a session token is valid and not expired */
export function verifySessionToken(token: string): boolean {
  const config = getCredentials();
  if (!config || !/^[A-Za-z0-9_-]{1,512}\.[A-Za-z0-9_-]{43}$/.test(token)) return false;
  const parts = token.split(".");
  const [b64, sig] = parts;

  const expectedSig = crypto.createHmac("sha256", config.secret).update(b64).digest();
  const actualSig = Buffer.from(sig, "base64url");
  if (actualSig.length !== expectedSig.length || !crypto.timingSafeEqual(actualSig, expectedSig)) return false;

  try {
    const payload = JSON.parse(Buffer.from(b64, "base64url").toString("utf8"));
    const now = Math.floor(Date.now() / 1000);
    return payload.v === 1 &&
      Number.isInteger(payload.iat) &&
      Number.isInteger(payload.exp) &&
      payload.iat <= now + 60 &&
      payload.exp > now &&
      payload.exp <= payload.iat + TOKEN_MAX_AGE;
  } catch {
    return false;
  }
}

/** Validate login credentials */
export function validateCredentials(
  username: string,
  password: string,
): boolean {
  const creds = getCredentials();
  if (!creds) return false;
  const digest = (value: string) => crypto.createHash("sha256").update(value).digest();
  const userMatch = crypto.timingSafeEqual(
    digest(username),
    digest(creds.username),
  );
  const passMatch = crypto.timingSafeEqual(
    digest(password),
    digest(creds.password),
  );
  return userMatch && passMatch;
}

/** Check if current request is authenticated (server component) */
export async function isAuthenticated(): Promise<boolean> {
  const cookieStore = await cookies();
  const token = cookieStore.get(AUTH_COOKIE)?.value;
  if (!token) return false;
  return verifySessionToken(token);
}

export { AUTH_COOKIE, TOKEN_MAX_AGE };
