export const metadata = {
  title: "Sign In — Chrontinal NEXUS",
  description: "Sign in to Chrontinal NEXUS Security Operations Center",
};

export default function LoginLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  // Render children directly — the login page provides its own html/body
  return children;
}
