// Cloudflare Pages Function: /api/* aur /admin/* ko Railway backend tak forward karta hai.
const BACKEND = "https://anshapipanel2backend-production.up.railway.app";

export async function onRequest({ request }) {
  const url = new URL(request.url);
  const target = new URL(url.pathname + url.search, BACKEND);

  const headers = new Headers(request.headers);
  // Asli visitor ka IP Cloudflare batata hai. Client ka bheja hua X-Forwarded-For
  // overwrite kar dete hain, taaki koi IP fake na kar sake.
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) headers.set("X-Forwarded-For", ip);
  else headers.delete("X-Forwarded-For");
  headers.delete("X-Real-IP");
  headers.set("X-Forwarded-Host", url.host);

  const hasBody = !["GET", "HEAD"].includes(request.method);
  return fetch(
    new Request(target, {
      method: request.method,
      headers,
      body: hasBody ? request.body : null,
      redirect: "manual",
    })
  );
}
