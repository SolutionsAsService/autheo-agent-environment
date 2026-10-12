// Reference JavaScript signer for agent-signed Autheo documents (request, outcome). Node >= 20.
// The private key never leaves the agent runtime; only the public key is enrolled via /v1/identities.
import { createHash, createPublicKey, randomUUID, sign } from 'node:crypto';

const b64json = (value) => Buffer.from(JSON.stringify(value), 'utf8').toString('base64url');

// "sha256:" + base64url(sha256(SPKI DER)) - the v1 agent kid (same as Paperclip's agent keyId).
export function keyFingerprint(keyObject) {
  const der = createPublicKey(keyObject).export({ type: 'spki', format: 'der' });
  return 'sha256:' + createHash('sha256').update(der).digest('base64url');
}

export function signDocument({ kind, privateKey, agentId, environment, body, ttlSeconds = 60, now }) {
  const iat = now ?? Math.floor(Date.now() / 1000);
  const header = { alg: 'EdDSA', kid: keyFingerprint(privateKey), typ: `autheo-${kind}+jwt` };
  const claims = { iss: agentId, sub: agentId, aud: environment, iat, nbf: iat, exp: iat + ttlSeconds,
    jti: randomUUID(), body };
  const input = `${b64json(header)}.${b64json(claims)}`;
  return `${input}.${sign(null, Buffer.from(input, 'ascii'), privateKey).toString('base64url')}`;
}

// body must match schemas/request.v1.schema.json exactly (unknown fields are rejected).
export const signRequest = (options) => signDocument({ ...options, kind: 'request' });
export const signOutcome = (options) => signDocument({ ...options, kind: 'outcome' });

// CLI for tests: echo '{"privateKeyPem":..., "agentId":..., "environment":..., "body":{...}}' | node autheo-sign.mjs
if (import.meta.url === `file://${process.argv[1]}`) {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));
  const { createPrivateKey } = await import('node:crypto');
  process.stdout.write(signDocument({ kind: input.kind ?? 'request', privateKey: createPrivateKey(input.privateKeyPem),
    agentId: input.agentId, environment: input.environment, body: input.body }));
}
