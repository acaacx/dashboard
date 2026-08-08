import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    // Node by default: most of the suite exercises parsing, normalization and
    // services, which have no DOM. Component tests opt in per file with a
    // `@vitest-environment jsdom` docblock.
    environment: "node",
    globals: true,
    setupFiles: ["./tests/setup.ts"],
    include: ["tests/**/*.test.ts", "tests/**/*.test.tsx"],
  },
  resolve: {
    alias: {
      "@": new URL("./src", import.meta.url).pathname,
      // `server-only` throws unless it resolves under React's `react-server`
      // condition, which Vitest does not set. Point it at the no-op entry the
      // package itself ships for that condition, so a composition root or a
      // guard can be unit-tested directly rather than only through a mock.
      "server-only": new URL(
        "./node_modules/server-only/empty.js",
        import.meta.url,
      ).pathname,
    },
  },
});
