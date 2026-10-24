import { NextRequest, NextResponse } from "next/server";
import { isAuthenticated } from "@/lib/auth";
import { checkRateLimit, getClientId } from "@/lib/rate-limit";

const GROQ_ENDPOINT = "https://api.groq.com/openai/v1/chat/completions";
const DEFAULT_MODEL = "openai/gpt-oss-20b";
const MAX_MESSAGE_LENGTH = 4000;
const MAX_HISTORY_LENGTH = 12;
const MAX_BODY_LENGTH = 32_000;

type ChatTurn = { role: "user" | "assistant"; content: string };

function parseHistory(value: unknown): ChatTurn[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_HISTORY_LENGTH) return null;

  const history: ChatTurn[] = [];
  let totalLength = 0;
  for (const turn of value) {
    if (!turn || typeof turn !== "object" ||
        (turn.role !== "user" && turn.role !== "assistant") ||
        typeof turn.content !== "string") return null;
    const content = turn.content.trim();
    totalLength += content.length;
    if (!content || content.length > MAX_MESSAGE_LENGTH || totalLength > 12_000) return null;
    history.push({ role: turn.role, content });
  }
  return history;
}

/** POST /api/ai/chat — authenticated, server-side Groq chat completion. */
export async function POST(req: NextRequest) {
  if (!(await isAuthenticated())) {
    return NextResponse.json({ error: "Authentication required" }, { status: 401 });
  }
  const limited = checkRateLimit(
    getClientId(req),
    { maxTokens: 6, refillRate: 1 / 15 },
    "/api/ai/chat",
  );
  if (limited) return limited;

  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey) {
    return NextResponse.json(
      { error: "AI chat is not configured on this server" },
      { status: 503 },
    );
  }

  const declaredLength = Number(req.headers.get("content-length") || 0);
  if (declaredLength > MAX_BODY_LENGTH) {
    return NextResponse.json({ error: "Message is too large" }, { status: 413 });
  }

  let message: string;
  let history: ChatTurn[];
  try {
    const raw = await req.text();
    if (raw.length > MAX_BODY_LENGTH) {
      return NextResponse.json({ error: "Message is too large" }, { status: 413 });
    }
    const body = JSON.parse(raw);
    const candidate = body?.message ?? body?.prompt;
    message = typeof candidate === "string" ? candidate.trim() : "";
    const parsedHistory = parseHistory(body?.history);
    if (!message || message.length > MAX_MESSAGE_LENGTH || parsedHistory === null) {
      return NextResponse.json({ error: "Invalid chat message or history" }, { status: 400 });
    }
    history = parsedHistory;
  } catch {
    return NextResponse.json({ error: "Invalid JSON request" }, { status: 400 });
  }

  const model = process.env.GROQ_MODEL || DEFAULT_MODEL;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 25_000);
  try {
    const upstream = await fetch(GROQ_ENDPOINT, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages: [
          {
            role: "system",
            content: "You are Chrontinal's security operations assistant. Give concise, practical security analysis. You do not have direct access to live events, ClickHouse, the AI pipeline, or external tools in this chat. Never claim to have checked live telemetry. Ask for relevant event details when needed.",
          },
          ...history,
          { role: "user", content: message },
        ],
        temperature: 0.3,
        max_completion_tokens: 1024,
        stream: false,
      }),
      cache: "no-store",
      signal: controller.signal,
    });

    if (!upstream.ok) {
      const status = upstream.status === 429 ? 429 : 502;
      return NextResponse.json(
        { error: status === 429 ? "AI chat is busy. Please retry shortly." : "AI provider request failed." },
        { status },
      );
    }

    const data = await upstream.json();
    const response = data?.choices?.[0]?.message?.content;
    if (typeof response !== "string" || !response.trim()) {
      return NextResponse.json({ error: "AI provider returned an empty response" }, { status: 502 });
    }
    return NextResponse.json(
      {
        response: response.trim(),
        model: typeof data.model === "string" ? data.model : model,
        tokensUsed: data.usage?.total_tokens,
        available: true,
      },
      { headers: { "Cache-Control": "no-store" } },
    );
  } catch (error) {
    const timedOut = error instanceof Error && error.name === "AbortError";
    return NextResponse.json(
      { error: timedOut ? "AI provider timed out." : "AI chat is temporarily unavailable." },
      { status: timedOut ? 504 : 502 },
    );
  } finally {
    clearTimeout(timeout);
  }
}
