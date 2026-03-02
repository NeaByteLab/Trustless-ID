<div align="center">

# Trustless ID

Anonymous ID: request, decode, verify time-bound. No server, no storage.

[![Node](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org) [![Deno](https://img.shields.io/badge/deno-compatible-ffcb00?logo=deno&logoColor=000000)](https://deno.com) [![Bun](https://img.shields.io/badge/bun-compatible-f9f1e1?logo=bun&logoColor=000000)](https://bun.sh) [![Browser](https://img.shields.io/badge/browser-compatible-4285F4?logo=googlechrome&logoColor=white)](https://developer.mozilla.org/en-US/docs/Web/JavaScript)

[![Module type: ESM](https://img.shields.io/badge/module%20type-esm-brightgreen)](https://github.com/NeaByteLab/Trustless-ID) [![npm version](https://img.shields.io/npm/v/@neabyte/trustless-id.svg)](https://www.npmjs.org/package/@neabyte/trustless-id) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

## Features

- **Trustless** — No server or DB; key from a shared identifier both sides agree on.
- **Connector-bound** — Same identifier = same pair; others can’t decode or verify.
- **Request, decode, verify** — Encode → decode to code → verify with user input (number or digits).
- **Time-bound** — Payloads expire in 1–60 seconds (configurable).
- **One-time session ID** — Unique per session (timestamp + nonce).

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

Use a **connector ID** (e.g. service URL or app identifier) on both sides. Generate a one-time **hashId**, create an **instance**, build a **requestId**, then decode to a numeric code or verify with a user secret.

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

// Verifier decodes to get code
const codeId = instance.decode(hashId, requestId)
if (codeId !== null) {
  console.log('Code:', codeId)
  // Check user secret
  console.log('Verify:', instance.verify(requestId, codeId))
}
```

## TOTP vs Trustless-ID

| Aspect               | **TOTP**                                                                                                | **Trustless-ID**                                                                                                                                                        |
| -------------------- | ------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Secret**           | A shared secret is generated and stored by both the server and the user (e.g. in an authenticator app). | No stored secret. Only a connector ID (e.g. service URL or app identifier) is agreed on; the key is derived from it when needed.                                        |
| **Code derivation**  | Code is computed from the shared secret and the current time window (e.g. 30s) using HMAC-SHA1.         | Code is derived from the session’s hashId and the encoded requestId using a FNV-1a–style mix; time is embedded in the request payload.                                  |
| **Server / backend** | A server (or backend) must store the secret per user and validate the code on each login.               | No server or database. Both sides use the same connector ID to derive the same key and verify the code locally.                                                         |
| **Typical use**      | Two-factor authentication (2FA): prove that the user possesses the shared secret at login time.         | One-time pairing or handshake: both sides agree on a connector; one creates a request, the other decodes and verifies the user-entered code within a short time window. |

## Documentation

The full API, flow, and type reference are in **[USAGE.md](USAGE.md)**.

That document describes how to use the library end-to-end and lists every method and type.

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
