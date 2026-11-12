import { createHash } from 'node:crypto';
import { BlobPreconditionFailedError, get, put } from '@vercel/blob';

const maxBytes = 4_000_000;
const noCache = { 'Cache-Control': 'private, no-store', 'X-Content-Type-Options': 'nosniff' };
const response = (status, body = null, headers = {}) =>
  new Response(body, { status, headers: { ...noCache, ...headers } });
// The hosting layer can weaken the HTTP ETag on streamed responses. Keep the
// original Blob version in a dedicated header for compare-and-swap updates.
const revision = value => (value || '').replace(/^W\//, '');
const validTag = value => /^"[\x21\x23-\x7e]{1,128}"$/.test(value ?? '');

export default {
  async fetch(request) {
    if (!['GET', 'PUT'].includes(request.method)) return response(405, null, { Allow: 'GET, PUT' });
    if (request.headers.get('sec-fetch-site') === 'cross-site') return response(403);

    const access = /^Bearer ([a-f0-9]{64})$/.exec(request.headers.get('authorization') ?? '');
    if (!access) return response(401);
    const id = createHash('sha256').update(access[1]).digest('hex');
    const path = `hybrid42-sync/${id}.bin`;

    try {
      if (request.method === 'GET') {
        const prior = request.headers.get('if-none-match');
        const blob = await get(path, {
          access: 'private',
          useCache: false,
          ifNoneMatch: validTag(prior) ? prior : undefined,
        });
        if (!blob) return response(404);
        return response(blob.statusCode, blob.stream, {
          'X-Hybrid42-Revision': revision(blob.blob.etag),
          'Content-Type': 'application/octet-stream',
        });
      }

      const create = request.headers.get('if-none-match') === '*';
      const expected = request.headers.get('if-match');
      if (create ? expected !== null : !validTag(expected)) return response(428);
      if (request.headers.get('content-type') !== 'application/octet-stream') return response(415);
      if (Number(request.headers.get('content-length')) > maxBytes) return response(413);
      const bytes = new Uint8Array(await request.arrayBuffer());
      if (bytes.length > maxBytes) return response(413);
      if (bytes.length < 30 || bytes[0] > 1) return response(400);

      try {
        const blob = await put(path, bytes, {
          access: 'private',
          addRandomSuffix: false,
          allowOverwrite: !create,
          ifMatch: create ? undefined : expected,
          contentType: 'application/octet-stream',
        });
        return response(create ? 201 : 204, null, { 'X-Hybrid42-Revision': revision(blob.etag) });
      } catch (error) {
        if (error instanceof BlobPreconditionFailedError) return response(409);
        if (create) {
          // A second device may have created the same record during this request.
          const existing = await get(path, { access: 'private', useCache: false });
          if (existing) {
            await existing.stream?.cancel();
            return response(409);
          }
        }
        throw error;
      }
    } catch {
      return response(503);
    }
  },
};
