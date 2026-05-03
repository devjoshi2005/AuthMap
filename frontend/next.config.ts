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
	experimental: {
		serverActions: {
			allowedOrigins: forwardedOrigins,
		},
	},
	turbopack: {
		root: path.resolve(__dirname),
	},
};

export default nextConfig;
