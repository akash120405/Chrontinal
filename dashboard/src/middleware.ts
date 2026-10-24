import { NextRequest, NextResponse } from "next/server";

const AUTH_COOKIE = "clif_session";
const TOKEN_MAX_AGE = 60 * 60 * 24;

// Public landing, sign-in, and an unauthenticated deployment health probe.
const PUBLIC_PATHS = new Set(["/", "/login", "/api/auth", "/api/health"]);

function isPublicPath(pathname: string): boolean {
  return PUBLIC_PATHS.has(pathname);
}

function decodeBase64Url(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const decoded = atob(base64.padEnd(Math.ceil(base64.length / 4) * 4, "="));
  return Uint8Array.from(decoded, (char) => char.charCodeAt(0)).buffer as ArrayBuffer;
}

async function verifyTokenEdge(token: string): Promise<boolean> {
  const secret = process.env.CLIF_AUTH_SECRET;
  const password = process.env.CLIF_AUTH_PASS;
  const username = process.env.CLIF_AUTH_USER?.trim();
  if (!secret || new TextEncoder().encode(secret).length < 32 ||
      !password || password.length < 12 || !username ||
      !/^[A-Za-z0-9_-]{1,512}\.[A-Za-z0-9_-]{43}$/.test(token)) return false;

  try {
    const [encoded, signature] = token.split(".");
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      decodeBase64Url(signature),
      new TextEncoder().encode(encoded),
    );
    if (!valid) return false;

    const payload = JSON.parse(new TextDecoder().decode(decodeBase64Url(encoded)));
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

export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Allow public paths (login page, auth API, static assets)
  if (
    isPublicPath(pathname) ||
    pathname.startsWith("/_next") ||
    pathname.startsWith("/favicon") ||
    pathname.endsWith(".ico") ||
    pathname.endsWith(".svg") ||
    pathname.endsWith(".png") ||
    pathname.endsWith(".jpg")
  ) {
    return NextResponse.next();
  }

  const token = request.cookies.get(AUTH_COOKIE)?.value;

  if (!token || !(await verifyTokenEdge(token))) {
    if (pathname.startsWith("/api/")) {
      return NextResponse.json(
        { error: "Authentication required" },
        { status: 401, headers: { "Cache-Control": "no-store" } },
      );
    }
    const loginUrl = new URL("/login", request.url);
    return NextResponse.redirect(loginUrl);
  }

  return NextResponse.next();
}

export const config = {
  matcher: [
    // Match all paths except Next.js internals and static files
    "/((?!_next/static|_next/image|favicon.ico).*)",
  ],
};
