import { ClerkProvider } from "@clerk/nextjs";
import type { Metadata } from "next";
import { IBM_Plex_Mono, Sora } from "next/font/google";
import "./globals.css";

const sora = Sora({
  variable: "--font-sora",
  subsets: ["latin"],
});

const plexMono = IBM_Plex_Mono({
  variable: "--font-plex-mono",
  subsets: ["latin"],
  weight: ["400", "500", "600", "700"],
});

export const metadata: Metadata = {
  title: "BoxAI",
  description:
    "BoxAI seals OpenClaw-based agents inside a controllable boundary with scan setup, security modules, remediation, and report views.",
  icons: {
    icon: [{ url: "/next.png?v=2", type: "image/png" }],
    shortcut: ["/next.png?v=2"],
    apple: [{ url: "/next.png?v=2", type: "image/png" }],
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${sora.variable} ${plexMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col">
        <ClerkProvider afterSignOutUrl="/">{children}</ClerkProvider>
      </body>
    </html>
  );
}
