import { NextResponse } from "next/server";

export const dynamic = "force-dynamic";

/** Lightweight public probe for the dashboard container and HTTPS proxy. */
export function GET() {
  return NextResponse.json(
    { status: "ok" },
    { headers: { "Cache-Control": "no-store" } },
  );
}
