import type { NextConfig } from "next";

// Every page is a client component that talks to the API, so there's nothing to prerender.
const nextConfig: NextConfig = {
  // The dev badge sits on top of the tables, and tomorrow's demo runs on the dev server.
  devIndicators: false,
  turbopack: {
    rules: {
      "*.css": {
        loaders: ["@tailwindcss/turbopack"],
        as: "*.css",
      },
    },
  },
};

export default nextConfig;
