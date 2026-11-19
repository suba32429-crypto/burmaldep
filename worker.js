export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Keep the preview isolated from production account and balance data.
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
      return new Response(
        JSON.stringify({ error: "API is intentionally disabled in this isolated preview." }),
        {
          status: 503,
          headers: {
            "content-type": "application/json; charset=utf-8",
            "cache-control": "no-store"
          }
        }
      );
    }

    return env.ASSETS.fetch(request);
  }
};
