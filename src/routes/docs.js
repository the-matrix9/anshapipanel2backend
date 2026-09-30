import { Router } from "express";
import { db } from "../db/index.js";
import { requireAuth } from "../middleware/auth.js";
import { HttpError, intParam } from "../middleware/errors.js";

const router = Router();
router.use(requireAuth);
router.param("id", intParam("API id"));

// Every entry below mirrors a response the proxy engine (routes/proxy.js)
// really produces — nothing invented.
function errorResponses(api) {
  return [
    { status: 400, when: "A required parameter is missing", body: { status: false, error: "Missing required parameter(s): <name>", credit: "@shreeapi" } },
    { status: 401, when: "An API key was sent but is not valid", body: { status: false, error: "Invalid API key", credit: "@shreeapi" } },
    { status: 403, when: "The key is revoked, expired, not permitted for this API, or the IP is blocked", body: { status: false, error: "API key is revoked", credit: "@shreeapi" } },
    { status: 405, when: `The wrong HTTP method was used (this API expects ${api.method})`, body: { status: false, error: `Method not allowed. Expected ${api.method}`, credit: "@shreeapi" } },
    { status: 429, when: "A rate limit was exceeded", body: { status: false, error: "Rate limit exceeded", retry_after: 30, credit: "@shreeapi" } },
    { status: 502, when: "The upstream service failed, timed out or is unreachable", body: { status: false, error: "Upstream request failed after retries", credit: "@shreeapi" } },
    { status: 503, when: "The API is disabled", body: { status: false, error: "This API is currently disabled", credit: "@shreeapi" } },
  ];
}

router.get("/:id", (req, res) => {
  const api = db.prepare("SELECT * FROM apis WHERE id = ?").get(req.params.id);
  if (!api) throw new HttpError(404, "API not found", "NOT_FOUND");
  const params = db.prepare("SELECT * FROM api_parameters WHERE api_id = ?").all(api.id);
  const baseUrl = (process.env.PUBLIC_BASE_URL || "http://localhost:4000").replace(/\/+$/, "");
  const publicUrl = `${baseUrl}/api/${api.slug}`;

  const queryParams = params.filter((p) => p.location === "query");
  const bodyParams = params.filter((p) => p.location === "body");
  const exampleQuery = queryParams.map((p) => `${p.public_name}=${p.default_value || "VALUE"}`).join("&");
  const withoutKeyUrl = exampleQuery ? `${publicUrl}?${exampleQuery}` : publicUrl;
  const withKeyUrl = exampleQuery ? `${publicUrl}?key=YOUR_KEY&${exampleQuery}` : `${publicUrl}?key=YOUR_KEY`;
  const exampleUrl = withoutKeyUrl;

  const hasBody = bodyParams.length > 0 && ["POST", "PUT", "DELETE"].includes(api.method);
  const bodyObj = Object.fromEntries(bodyParams.map((p) => [p.public_name, p.default_value || "VALUE"]));
  const bodyJson = JSON.stringify(bodyObj);

  const curl = hasBody
    ? `curl -X ${api.method} "${withoutKeyUrl}" \\\n  -H "Content-Type: application/json" \\\n  -d '${bodyJson}'`
    : `curl -X ${api.method} "${withoutKeyUrl}"`;
  const curlWithKey = hasBody
    ? `curl -X ${api.method} "${withKeyUrl}" \\\n  -H "Content-Type: application/json" \\\n  -d '${bodyJson}'`
    : `curl -X ${api.method} "${withKeyUrl}"`;

  const js = `fetch("${exampleUrl}", {
  method: "${api.method}",
  headers: {${hasBody ? '\n    "Content-Type": "application/json",' : ""}
    "Authorization": "Bearer YOUR_KEY"  // optional
  }${hasBody ? `,\n  body: JSON.stringify(${bodyJson})` : ""}
}).then((r) => r.json()).then(console.log);`;

  const python = `import requests

resp = requests.request(
    "${api.method}",
    "${exampleUrl}",
    headers={"Authorization": "Bearer YOUR_KEY"},  # optional${hasBody ? `\n    json=${bodyJson},` : ""}
)
print(resp.json())`;

  const php = `<?php
$ch = curl_init("${exampleUrl}");
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, "${api.method}");
curl_setopt($ch, CURLOPT_HTTPHEADER, [${hasBody ? '"Content-Type: application/json", ' : ""}"Authorization: Bearer YOUR_KEY"]);${hasBody ? `\ncurl_setopt($ch, CURLOPT_POSTFIELDS, '${bodyJson}');` : ""}
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$response = curl_exec($ch);
curl_close($ch);
echo $response;`;

  res.json({
    status: true,
    data: {
      name: api.name,
      description: api.description,
      api_status: api.status,
      method: api.method,
      slug: api.slug,
      base_url: baseUrl,
      endpoint: `${api.method} /api/${api.slug}`,
      full_url: publicUrl,
      parameters: params.map((p) => ({
        name: p.public_name,
        location: p.location,
        required: !!p.required,
        default: p.default_value,
      })),
      // Accurate to the proxy engine: a key is validated only when one is sent.
      authentication: {
        required: false,
        description:
          "API keys are optional for this endpoint. If you send one it must be valid — its limits and permissions then apply, and the request is attributed to that key in the logs.",
        methods: [
          { label: "Authorization header", example: "Authorization: Bearer YOUR_KEY" },
          { label: "Query parameter", example: "?key=YOUR_KEY" },
        ],
      },
      example_request: exampleUrl,
      example_body: hasBody ? bodyObj : null,
      usage_examples: [
        { label: "With API key", url: withKeyUrl },
        { label: "Without API key", url: withoutKeyUrl },
      ],
      response_wrapper_enabled: !!api.response_wrapper_enabled,
      example_response: api.response_wrapper_enabled
        ? { status: true, data: {}, credit: "@shreeapi" }
        : null,
      response_note: api.response_wrapper_enabled
        ? "Successful responses are wrapped: the upstream payload is returned inside `data`."
        : "Successful responses are passed through exactly as the upstream service returns them.",
      error_responses: errorResponses(api),
      snippets: { curl, curl_with_key: curlWithKey, javascript: js, python, php },
    },
  });
});

export default router;
