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
