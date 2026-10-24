"use client";

import { usePathname } from "next/navigation";
import { ThemeProvider, DynamicToaster } from "@/components/theme-provider";
import { Sidebar } from "@/components/sidebar";
import { TopBar } from "@/components/top-bar";
import { ErrorBoundary } from "@/components/error-boundary";
import { ChatWidget } from "@/components/chat-widget";

export function AppFrame({
  children,
  hasSession,
}: {
  children: React.ReactNode;
  hasSession: boolean;
}) {
  const pathname = usePathname();

  // The marketing site and login screen have their own full-page layouts.
  if (!hasSession || pathname === "/" || pathname === "/login") {
    return <>{children}</>;
  }

  return (
    <ThemeProvider
      attribute="class"
      defaultTheme="light"
      enableSystem={false}
      disableTransitionOnChange
    >
      <div className="clif-shell" id="clif-shell">
        <TopBar />
        <Sidebar />
        <main className="clif-main overflow-y-auto">
          <ErrorBoundary>
            <div className="page-enter p-4 lg:p-6">{children}</div>
          </ErrorBoundary>
        </main>
      </div>
      <ChatWidget />
      <DynamicToaster />
    </ThemeProvider>
  );
}
