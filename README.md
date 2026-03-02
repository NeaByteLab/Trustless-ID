<div align="center">

# Trustless ID

Anonymous ID: request, decode, verify time-bound. No server, no storage.

[![Node](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org) [![Deno](https://img.shields.io/badge/deno-compatible-ffcb00?logo=deno&logoColor=000000)](https://deno.com) [![Bun](https://img.shields.io/badge/bun-compatible-f9f1e1?logo=bun&logoColor=000000)](https://bun.sh) [![Browser](https://img.shields.io/badge/browser-compatible-4285F4?logo=googlechrome&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)

[![Module type: ESM](https://img.shields.io/badge/module%20type-esm-brightgreen)](https://github.com/NeaByteLab/Trustless-ID) [![npm version](https://img.shields.io/npm/v/@neabyte/trustless-id.svg)](https://www.npmjs.org/package/@neabyte/trustless-id) [![JSR](https://jsr.io/badges/@neabyte/trustless-id)](https://jsr.io/@neabyte/trustless-id) [![CI](https://github.com/NeaByteLab/Trustless-ID/actions/workflows/ci.yaml/badge.svg)](https://github.com/NeaByteLab/Trustless-ID/actions/workflows/ci.yaml) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

## Features

- **Trustless** — No server or DB; key from a shared identifier (`connectorId`) both sides agree on.
- **Connector-bound** — Same `connectorId` = same pair; others can’t `decode` or `verify`.
- **Request, decode, verify** — `request` → `decode` to `codeId` → `verify` with user input (number or digits).
- **Time-bound** — Payloads expire automatically and predictably in 1–60 seconds (configurable).
- **Session ID** — `hashId` can be one-time per session (default) or stable per user for repeated identity proof.

## Installation

> [!NOTE]
> **Prerequisites:** For **Deno** install from [deno.com](https://deno.com/). For **npm** use Node.js (e.g. [nodejs.org](https://nodejs.org/)).

**npm:**

```bash
npm install @neabyte/trustless-id
```

**Deno (JSR):**

```bash
deno add jsr:@neabyte/trustless-id
```

## Quick Start

Use a **connector ID** (`connectorId`) (e.g. service URL or app identifier) on both sides. Generate a one-time `hashId` via `generate(connectorId)`, create an instance via `create(connectorId)`, build a `requestId` via `request(hashId, expireTime?)`, then **client** decodes to a numeric code (`codeId`) to show the user; **verifier** checks the user-entered code with `verify(requestId, secret)`.

```typescript
import trustless from '@neabyte/trustless-id'

// Connector ID (same on both sides)
const connectorId = 'trustless://auth/example.com:0.1.0?service=none'

// One-time hashId per session
const hashId = trustless.generate(connectorId)

// Instance for connector (same on client and verifier)
const instance = trustless.create(connectorId)

// Build payload; send requestId to verifier (QR / link / form)
const requestId = instance.request(hashId, 10)

// Client decodes to get code (show to user so they can type it at verifier)
const codeId = instance.decode(hashId, requestId)
if (codeId !== null) {
  console.log('Code:', codeId)
  // Verifier side: check user-entered secret
  console.log('Verify:', instance.verify(requestId, codeId))
}
```

## TOTP vs Trustless-ID

| Aspect               | **TOTP**                                                                                                | **Trustless-ID**                                                                                                                                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Secret**           | A shared secret is generated and stored by both the server and the user (e.g. in an authenticator app). | No stored secret. Only a connector ID (`connectorId`) (e.g. service URL or app identifier) is agreed on; the key is derived from it when needed.                                                                                        |
| **Code derivation**  | Code is computed from the shared secret and the current time window (e.g. 30s) using HMAC-SHA1.         | Code is derived from the session’s `hashId` and the encoded `requestId` using a FNV-1a–style mix; time is embedded in the request payload.                                                                                              |
| **Server / backend** | A server (or backend) must store the secret per user and validate the code on each login.               | No server or database. Client uses same `connectorId` to derive key, decode to code; verifier uses same `connectorId` to verify the user-entered code locally.                                                                          |
| **Typical use**      | Two-factor authentication (2FA): prove that the user possesses the shared secret at login time.         | One-time pairing or repeated identity: same connector; client uses `request` → `decode` → code, verifier uses `verify`. Use a new `hashId` per session (anonymous) or one stable `hashId` per user (repeated proof, no server storage). |

## Documentation

- **[USAGE.md](USAGE.md)** — Full API, flow, and type reference; how to use the library end-to-end and every method.
- **[USECASE.md](USECASE.md)** — Use cases to clarify flow and architecture (actors, channels, secure vs leak conditions).

## Build & Test

From the repo root (requires [Deno](https://deno.com/)).

**Check** — format, lint, and typecheck source:

```bash
deno task check
```

**Unit tests** — format/lint tests and run all tests:

```bash
deno task test
```

Tests live under `tests/` (Trustless flow, Cipher, Security, Expiration, EdgeCases).

## License

This project is licensed under the MIT license. See the [LICENSE](LICENSE) file for details.
