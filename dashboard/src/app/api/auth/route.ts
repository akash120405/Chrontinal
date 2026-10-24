import { NextRequest, NextResponse } from "next/server";
import {
  validateCredentials,
  createSessionToken,
  isAuthConfigured,
  AUTH_COOKIE,
  TOKEN_MAX_AGE,
} from "@/lib/auth";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";

export async function POST(req: NextRequest) {
  if (!isAuthConfigured()) {
    return NextResponse.json(
      { error: "Authentication is not configured on this server" },
      { status: 503 },
    );
  }
  const limited = checkRateLimit(
    getClientId(req),
    { maxTokens: 5, refillRate: 1 / 60 },
    "/api/auth",
  );
  if (limited) return limited;

  try {
    const body = await req.json();
    const { username, password } = body;

    if (
      !username ||
      !password ||
      typeof username !== "string" ||
      typeof password !== "string"
    ) {
      return NextResponse.json(
        { error: "Username and password are required" },
        { status: 400 },
      );
    }

    // Rate-limit basic protection: reject very long inputs
    if (username.length > 128 || password.length > 128) {
      return NextResponse.json(
        { error: "Invalid credentials" },
        { status: 401 },
      );
    }

    if (!validateCredentials(username, password)) {
      return NextResponse.json(
        { error: "Invalid credentials" },
        { status: 401 },
      );
    }

    const token = createSessionToken();
    const res = NextResponse.json({ ok: true });
    res.cookies.set(AUTH_COOKIE, token, {
      httpOnly: true,
      secure: process.env.CLIF_HTTPS === "true" || req.nextUrl.protocol === "https:",
      sameSite: "lax",
      path: "/",
      maxAge: TOKEN_MAX_AGE,
    });
    return res;
  } catch {
    return NextResponse.json({ error: "Bad request" }, { status: 400 });
  }
}

export async function DELETE(req: NextRequest) {
  const res = NextResponse.json({ ok: true });
  res.cookies.set(AUTH_COOKIE, "", {
    httpOnly: true,
    secure: process.env.CLIF_HTTPS === "true" || req.nextUrl.protocol === "https:",
    sameSite: "lax",
    path: "/",
    maxAge: 0,
  });
  return res;
}
