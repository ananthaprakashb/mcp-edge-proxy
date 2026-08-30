import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const SOCIAL_PREVIEW_VERSION = "20260830";

export default defineConfig({
  plugins: [
    react(),
    {
      name: "contextgateway-social-preview-version",
      transformIndexHtml(html) {
        return html.replaceAll(
          "/contextgateway-social.jpg",
          `/contextgateway-social-${SOCIAL_PREVIEW_VERSION}.jpg`,
        );
      },
    },
  ],
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
