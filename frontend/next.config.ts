import path from "path";
import type { NextConfig } from "next";

const forwardedOrigins = Array.from(
	new Set(
		[
			process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN
				? `*.${process.env.GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}`
				: null,
			"*.app.github.dev",
			"*.githubpreview.dev",
			"localhost",
			"127.0.0.1",
		].filter((value): value is string => Boolean(value)),
	),
);

const nextConfig: NextConfig = {
	allowedDevOrigins: forwardedOrigins,
	async redirects() {
		return [
			{
				source: "/favicon.ico",
				destination: "/next.png?v=2",
				permanent: false,
			},
		];
	},
	async headers() {
		const clerkHosts = "https://*.clerk.accounts.dev https://clerk.com";
		const backendOrigins =
			"https://au-611fda3e66c34377b1540e37489404d2.ecs.ap-south-1.on.aws";

		const cspDirectives = [
			`default-src 'self' ${clerkHosts}`,
			`script-src 'self' 'unsafe-eval' 'unsafe-inline' 'wasm-unsafe-eval' ${clerkHosts} https://challenges.cloudflare.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com`,
			"worker-src 'self' blob:",
			`connect-src 'self' http://localhost:* http://127.0.0.1:* ws://localhost:* ws://127.0.0.1:* ${backendOrigins} ${clerkHosts} https://clerk-telemetry.com https://challenges.cloudflare.com https://*.supabase.co https://api.groq.com https://huggingface.co https://*.huggingface.co https://cdn-lfs.huggingface.co https://raw.githubusercontent.com https://*.xenova.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com`,
			"img-src 'self' data: blob: https://img.clerk.com https://images.unsplash.com",
			"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com",
			"font-src 'self' data: https://cdn.jsdelivr.net",
			"object-src 'none'",
			`frame-src 'self' https://challenges.cloudflare.com ${clerkHosts}`,
			"frame-ancestors 'none'",
			"base-uri 'self'",
			"form-action 'self'",
		].join("; ");

		return [
			{
				source: "/:path*",
				headers: [
					{
						key: "Content-Security-Policy",
						value: cspDirectives,
					},
					{
						key: "X-Frame-Options",
						value: "DENY",
					},
					{
						key: "X-Content-Type-Options",
						value: "nosniff",
					},
					{
						key: "Referrer-Policy",
						value: "strict-origin-when-cross-origin",
					},
					{
						key: "Permissions-Policy",
						value: "camera=(), microphone=(), geolocation=()",
					},
				],
			},
		];
	},
	experimental: {
		serverActions: {
			allowedOrigins: forwardedOrigins,
		},
	},
	turbopack: {
		root: path.resolve(__dirname),
	},
	devIndicators: false,
};

export default nextConfig;
