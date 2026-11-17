import { defineConfig } from "vite";

// The build is inlined into one HTML file by scripts/inline.mjs, so nothing may be split out.
export default defineConfig({
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    assetsInlineLimit: 100_000_000,
    cssCodeSplit: false,
    modulePreload: false,
    sourcemap: false,
    target: "es2020",
    rollupOptions: { output: { inlineDynamicImports: true } },
  },
});
