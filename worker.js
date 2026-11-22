const SUPABASE_FUNCTION = "https://qgsugmiaryvqixsypfgw.supabase.co/functions/v1/burmaldep-api";
const API_ROUTES = new Set([
  "register", "login", "me", "player-profile", "presence", "feed",
  "optimized-mode", "inventory", "balance", "activity-view", "activity",
  "password", "username", "avatar", "delete-account", "leaderboard"
]);

function json(data, status = 200, origin = "*") {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": origin,
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "access-control-allow-headers": "authorization, content-type",
      "vary": "Origin"
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) {
      const origin = request.headers.get("Origin") || "*";

      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: {
            "access-control-allow-origin": origin,
            "access-control-allow-methods": "GET, POST, OPTIONS",
            "access-control-allow-headers": "authorization, content-type",
            "access-control-max-age": "86400",
            "vary": "Origin"
          }
        });
      }

      if (url.pathname === "/api" || url.pathname === "/api/") {
        return json({ service: "Burmaldep API", status: "maintenance", message: "Burmaldep временно на технических работах." }, 503, origin);
      }

      // Temporary maintenance mode: block account and game API calls without touching stored data.
      return json({ error: "Burmaldep временно на технических работах. Данные аккаунтов сохранены.", maintenance: true }, 503, origin);

      const route = url.pathname.slice("/api/".length).replace(/\/+$/, "");
      if (!API_ROUTES.has(route)) {
        return json({ error: "Маршрут не найден" }, 404, origin);
      }
      if (request.method !== "GET" && request.method !== "POST") {
        return json({ error: "Метод не поддерживается" }, 405, origin);
      }

      const headers = new Headers(request.headers);
      const authorization = headers.get("authorization") || "";
      if (/^Bearer\s+/i.test(authorization)) {
        headers.set("x-burmaldep-token", authorization.replace(/^Bearer\s+/i, ""));
      }
      headers.delete("authorization");
      headers.delete("host");
      headers.delete("content-length");
      headers.set("accept", "application/json");

      const target = SUPABASE_FUNCTION + "/" + route + url.search;
      const init = { method: request.method, headers };
      if (request.method !== "GET" && request.method !== "HEAD") {
        init.body = request.body;
      }

      try {
        const upstream = await fetch(new Request(target, init));
        const responseHeaders = new Headers(upstream.headers);
        responseHeaders.set("cache-control", "no-store");
        responseHeaders.set("access-control-allow-origin", origin);
        responseHeaders.set("access-control-allow-methods", "GET, POST, OPTIONS");
        responseHeaders.set("access-control-allow-headers", "authorization, content-type");
        responseHeaders.set("vary", "Origin");
        return new Response(upstream.body, {
          status: upstream.status,
          statusText: upstream.statusText,
          headers: responseHeaders
        });
      } catch (error) {
        console.error("Burmaldep Supabase proxy:", error);
        return json({ error: "Не удалось связаться с сервером базы данных." }, 502, origin);
      }
    }

    return env.ASSETS.fetch(request);
  }
};
