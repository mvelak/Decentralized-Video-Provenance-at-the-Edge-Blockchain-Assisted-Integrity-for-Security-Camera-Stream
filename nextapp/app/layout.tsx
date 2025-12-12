import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Veritas",
  description: "Record a video, hash it, pin to IPFS, and register provenance on-chain.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">
        {children}
      </body>
    </html>
  );
}
