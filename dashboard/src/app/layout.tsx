import type { Metadata } from "next";
import "./globals.css";
import { AppFrame } from "@/components/app-frame";
import { cookies } from "next/headers";

export const metadata: Metadata = {
  title: "Chrontinal NEXUS — Security Operations",
  description: "Enterprise AI-powered Security Operations Center",
};

export default async function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const cookieStore = await cookies();
  const hasSession = cookieStore.has("clif_session");

  return (
    <html lang="en" suppressHydrationWarning>
      <body className="font-sans">
        <AppFrame hasSession={hasSession}>{children}</AppFrame>
      </body>
    </html>
  );
}
