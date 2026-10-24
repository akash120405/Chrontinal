"use client";

import { useState, useRef, useEffect, useCallback, FormEvent } from "react";
import {
  Send,
  Bot,
  User,
  Loader2,
  Trash2,
  Sparkles,
  MessageSquare,
  X,
  Minus,
} from "lucide-react";
import { cn } from "@/lib/utils";

interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: Date;
}

const CHAT_DISCLOSURE =
  "Prompts and recent chat history are sent to Groq. This chat does not automatically access live SOC events or pipeline status.";

export function ChatWidget() {
  const [open, setOpen] = useState(false);
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "welcome",
      role: "system",
      content: CHAT_DISCLOSURE,
      timestamp: new Date(),
    },
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  const scrollToBottom = useCallback(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, []);

  useEffect(() => {
    scrollToBottom();
  }, [messages, scrollToBottom]);

  useEffect(() => {
    if (open) inputRef.current?.focus();
  }, [open]);

  const handleSubmit = async (e?: FormEvent) => {
    e?.preventDefault();
    const trimmed = input.trim();
    if (!trimmed || isLoading) return;
    const history = messages
      .filter((msg) => msg.role === "user" || msg.role === "assistant")
      .slice(-12)
      .map((msg) => ({ role: msg.role, content: msg.content }));
    while (history.reduce((length, turn) => length + turn.content.length, 0) > 12_000) {
      history.shift();
    }

    const userMsg: ChatMessage = {
      id: crypto.randomUUID(),
      role: "user",
      content: trimmed,
      timestamp: new Date(),
    };
    setMessages((prev) => [...prev, userMsg]);
    setInput("");
    setIsLoading(true);

    try {
      const res = await fetch("/api/ai/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: trimmed, history }),
      });

      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Chat API error: ${res.status}`);

      setMessages((prev) => [
        ...prev,
        {
          id: crypto.randomUUID(),
          role: "assistant",
          content: data.response || data.message || "I couldn't process that request.",
          timestamp: new Date(),
        },
      ]);
    } catch (error) {
      setMessages((prev) => [
        ...prev,
        {
          id: crypto.randomUUID(),
          role: "assistant",
          content: error instanceof Error ? error.message : "Chat is temporarily unavailable. Please try again.",
          timestamp: new Date(),
        },
      ]);
    } finally {
      setIsLoading(false);
      inputRef.current?.focus();
    }
  };

  const clearChat = () => {
    setMessages([
      {
        id: "welcome",
        role: "system",
        content: CHAT_DISCLOSURE,
        timestamp: new Date(),
      },
    ]);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSubmit();
    }
  };

  return (
    <>
      {/* Floating button */}
      {!open && (
        <button
          onClick={() => setOpen(true)}
          className="fixed bottom-6 right-6 z-50 flex h-14 w-14 items-center justify-center rounded-full bg-primary text-primary-foreground shadow-2xl shadow-primary/30 hover:bg-primary/90 transition-all hover:scale-105"
          aria-label="Open chat"
        >
          <MessageSquare className="h-6 w-6" />
        </button>
      )}

      {/* Chat panel */}
      {open && (
        <div className="fixed bottom-6 right-6 z-50 flex w-[400px] flex-col rounded-2xl border border-border bg-white shadow-2xl overflow-hidden" style={{ height: 520 }}>
          {/* Header */}
          <div className="flex items-center justify-between px-5 py-3 border-b border-border bg-white">
            <div className="flex items-center gap-3">
              <div className="flex h-8 w-8 items-center justify-center rounded-xl bg-primary/10">
                <Bot className="h-4 w-4 text-primary" />
              </div>
              <div>
                <h3 className="text-sm font-extrabold text-foreground">Chrontinal AI</h3>
                <p className="text-[10px] text-muted-foreground font-bold">Groq powered chat</p>
              </div>
            </div>
            <div className="flex items-center gap-1">
              <button onClick={clearChat} className="p-1.5 rounded-lg text-muted-foreground hover:bg-muted/30 transition-colors" title="Clear chat">
                <Trash2 className="h-3.5 w-3.5" />
              </button>
              <button onClick={() => setOpen(false)} className="p-1.5 rounded-lg text-muted-foreground hover:bg-muted/30 transition-colors" title="Minimize">
                <Minus className="h-3.5 w-3.5" />
              </button>
              <button onClick={() => setOpen(false)} className="p-1.5 rounded-lg text-muted-foreground hover:bg-muted/30 transition-colors" title="Close">
                <X className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto px-4 py-3 space-y-3" ref={scrollRef}>
            {messages.map((msg) => (
              <div
                key={msg.id}
                className={cn("flex gap-2.5", msg.role === "user" && "justify-end")}
              >
                {msg.role !== "user" && (
                  <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10 mt-0.5">
                    {msg.role === "system" ? (
                      <Sparkles className="h-3 w-3 text-primary" />
                    ) : (
                      <Bot className="h-3 w-3 text-primary" />
                    )}
                  </div>
                )}
                <div
                  className={cn(
                    "max-w-[80%] rounded-2xl px-3.5 py-2.5",
                    msg.role === "user"
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted/30 border border-border"
                  )}
                >
                  <p className="text-xs leading-relaxed whitespace-pre-wrap">{msg.content}</p>
                  <span className="block text-[9px] mt-1 opacity-50">
                    {msg.timestamp.toLocaleTimeString()}
                  </span>
                </div>
                {msg.role === "user" && (
                  <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-muted mt-0.5">
                    <User className="h-3 w-3 text-muted-foreground" />
                  </div>
                )}
              </div>
            ))}
            {isLoading && (
              <div className="flex gap-2.5">
                <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10">
                  <Bot className="h-3 w-3 text-primary" />
                </div>
                <div className="rounded-2xl border border-border bg-muted/30 px-3.5 py-2.5">
                  <Loader2 className="h-3.5 w-3.5 animate-spin text-muted-foreground" />
                </div>
              </div>
            )}
          </div>

          {/* Input */}
          <div className="border-t border-border bg-white px-4 py-3">
            <form onSubmit={handleSubmit} className="flex items-end gap-2">
              <textarea
                ref={inputRef}
                value={input}
                maxLength={4000}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                placeholder="Ask Chrontinal AI..."
                className="flex-1 resize-none rounded-xl border border-border bg-muted/20 px-3 py-2 text-xs placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/30"
                rows={1}
                style={{ minHeight: 36, maxHeight: 80 }}
                disabled={isLoading}
              />
              <button
                type="submit"
                disabled={!input.trim() || isLoading}
                className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-primary text-primary-foreground disabled:opacity-40 hover:bg-primary/90 transition-colors"
              >
                {isLoading ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Send className="h-3.5 w-3.5" />
                )}
              </button>
            </form>
            <p className="mt-2 text-[10px] leading-snug text-muted-foreground">
              Prompt and recent history go to Groq. Live SOC data is not included automatically.
            </p>
          </div>
        </div>
      )}
    </>
  );
}
