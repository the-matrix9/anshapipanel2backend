// Centralised error handling. Route code can `throw new HttpError(404, ...)`
// (or let anything else throw) and the client always gets the same JSON
// shape: { status:false, error, code?, request_id? } with the right status.

export class HttpError extends Error {
  constructor(status, message, code) {
    super(message);
    this.status = status;
    this.code = code;
    this.expose = true;
  }
}

/** Express 4 doesn't catch rejected promises from async handlers — this does. */
export const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/** Validates numeric :id params once, instead of every handler doing it (or not). */
export function intParam(name = "id") {
  return (req, res, next, value) => {
    if (!/^\d{1,12}$/.test(String(value))) {
      return res.status(400).json({ status: false, error: `Invalid ${name}`, code: "INVALID_ID" });
    }
    next();
  };
}

export function notFoundHandler(req, res) {
  res.status(404).json({ status: false, error: "Not found", code: "NOT_FOUND", credit: "@shreeapi" });
}

export function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);

  let status = Number(err.status || err.statusCode) || 500;
  let message = err.expose ? err.message : null;
  let code = err.code && typeof err.code === "string" && /^[A-Z_]+$/.test(err.code) ? err.code : undefined;

  if (err.type === "entity.parse.failed") {
    status = 400;
    message = "Request body is not valid JSON";
    code = "INVALID_JSON";
  } else if (err.type === "entity.too.large") {
    status = 413;
    message = "Request body is too large";
    code = "BODY_TOO_LARGE";
  } else if (err.message === "Not allowed by CORS") {
    status = 403;
    message = "Origin not allowed by CORS policy";
    code = "CORS_FORBIDDEN";
  } else if (/UNIQUE constraint failed/i.test(err.message || "")) {
    status = 409;
    message = "That value is already in use";
    code = "CONFLICT";
  }

  if (status >= 500) {
    console.error(`[error] ${req.method} ${req.originalUrl} (${req.requestId || "-"}):`, err);
    message = "Internal server error";
  } else if (!message) {
    message = status === 404 ? "Not found" : "Request failed";
  }

  // Let the request logger record WHY (e.g. "Request body is not valid JSON")
  // rather than a bare status code.
  if (req.apiLog && !req.apiLog.error) req.apiLog.error = message;

  res.status(status).json({
    status: false,
    error: message,
    ...(code ? { code } : {}),
    ...(req.requestId ? { request_id: req.requestId } : {}),
    credit: "@shreeapi",
  });
}
