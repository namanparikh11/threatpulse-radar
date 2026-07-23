/**
 * V6.2 — portable HTTP route: /health
 *
 * Liveness probe. Returns 200 as long as the server
 * is up. Does NOT touch the storage adapter; the
 * check is purely process-level.
 */

export function handleHealth() {
  return new Response(JSON.stringify({ status: 'ok' }), {
    status: 200,
    headers: {
      'Content-Type': 'application/json; charset=utf-8',
      'Cache-Control': 'no-store',
    },
  });
}
