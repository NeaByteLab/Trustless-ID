# Usage

API, flow, options — `request`, `decode`, `verify` time-bound IDs.

## Table of Contents

- [Quick Start](#quick-start)
- [Flow Overview](#flow-overview)
- [Methods Overview](#methods-overview)
- [ConnectorId and HashId](#connectorid-and-hashid)
- [Request and Expiry](#request-and-expiry)
- [Decode and Verify](#decode-and-verify)
- [API Reference](#api-reference)
- [Option Types](#option-types)
- [Reference](#reference)

## Quick Start

**Flow:** `connectorId` → `hashId` → instance (via `create`) → `request` → `decode` → `verify`.

```typescript
import trustless from '@neabyte/trustless-id'

// Connector ID (same on both sides)
const connectorId = 'trustless://auth/example.com:0.1.0?service=none'

// One-time hashId per session
const hashId = trustless.generate(connectorId)

// Instance for connector (same on client and verifier)
const instance = trustless.create(connectorId)

// Request with 10s expiry window; send requestId to verifier (QR / link / form)
const requestId = instance.request(hashId, 10)

// Client: decode to code and show to user
const codeId = instance.decode(hashId, requestId)
if (codeId !== null) {
  // Verifier: check user-entered secret
  const ok = instance.verify(requestId, codeId)
}
```

## Flow Overview

1. **Connector** — Both client and verifier use the same `connectorId` (e.g. service URL).
2. **Hash** — Client calls `trustless.generate(connectorId)` once per session; returns a 197-char hex `hashId` (unique per call). This is the session identifier.
3. **Instance** — Both sides call `trustless.create(connectorId)` to get an instance (for `request`, `decode`, `verify`) bound to that connector.
4. **Request** — Client calls `instance.request(hashId, expireTime?)` to get `requestId`. Send `requestId` to the verifier (e.g. QR, link, form).
5. **Decode** — **Client** calls `instance.decode(hashId, requestId)` to get numeric `codeId`, or `null` if invalid/expired. Client shows the code to the user so they can type it at the verifier. The verifier does not call `decode`.
6. **Verify** — User enters the code at the verifier. **Verifier** calls `instance.verify(requestId, secret)` only; returns `true` when not expired and code matches.

## Methods Overview

| Method                                                                       | Type     | Returns          | Description                                           |
| :--------------------------------------------------------------------------- | :------- | :--------------- | :---------------------------------------------------- |
| [`trustless.create(connectorId)`](#trustlesscreateconnectorid)               | static   | instance         | Factory: new instance bound to connector.             |
| [`trustless.generate(connectorId)`](#trustlessgenerateconnectorid)           | static   | `HashId`         | One-time 197-char hex hash.                           |
| [`instance.request(hashId, expireTime?)`](#instancerequesthashid-expiretime) | instance | `RequestId`      | Encoded payload string or `''` if `hashId` invalid.   |
| [`instance.decode(hashId, requestId)`](#instancedecodehashid-requestid)      | instance | `CodeId \| null` | **Client:** numeric code when valid (show to user).   |
| [`instance.verify(requestId, secret)`](#instanceverifyrequestid-secret)      | instance | `boolean`        | **Verifier:** true when not expired and code matches. |

## ConnectorId and HashId

- **ConnectorId** — Any non-secret string that identifies the connector (e.g. `trustless://auth/example.com:0.1.0?service=none`). Trimmed before hashing. Same value on both sides yields the same encryption key.
- **HashId** — 197 lowercase hex chars from `trustless.generate(connectorId)`. Includes timestamp and random nonce; different on every call. Used by the **client** when calling `decode(hashId, requestId)` to obtain the code to show the user. The verifier does not need `hashId`; it only receives `requestId` and the user-entered code and calls `verify(requestId, secret)`.

  ```typescript
  const hashId = trustless.generate(connectorId)
  // hashId.length === 197, /^[0-9a-f]{197}$/.test(hashId) === true
  ```

## Request and Expiry

- **request(hashId, expireTime?)** — Validates `hashId` (197 hex chars), then encodes `hashId` + current time slot + window. Returns fixed-length `RequestId` or `''` if `hashId` invalid.
- **expireTime** — Window in seconds (1–60). Default 10. Clamped via `Cipher.clampWindow`. Same `hashId` and same window in the same time slot yields the same `requestId` and same `codeId`.

  ```typescript
  const requestId = instance.request(hashId, 10)
  const requestIdLong = instance.request(hashId, 60)
  // requestId length: 6 (slot) + 2 (window) + 197 (hashId) = 205
  ```

## Decode and Verify

- **decode(hashId, requestId)** — Decodes with instance key; checks expiry; ensures payload `hashId` matches argument; returns derived numeric code or `null`. Code is in range `0`–`1e10`.
- **verify(requestId, secret)** — Decodes, checks expiry, derives expected code, compares to `secret`. `secret` can be number or string (digits only); returns `true` when match and not expired.

  ```typescript
  const codeId = instance.decode(hashId, requestId)
  if (codeId !== null) {
    instance.verify(requestId, codeId) === true
    instance.verify(requestId, String(codeId)) === true
  }
  ```

## API Reference

### trustless.create(connectorId)

Create an instance bound to the given connector. The instance key is a hash of the trimmed `connectorId`.

- `connectorId` `<ConnectorId>`: Caller identifier (string, trimmed).
- Returns: New instance (use for `request`, `decode`, `verify`).

### trustless.generate(connectorId)

Generate a one-time 197-char hex hash. Uses `connectorId` + timestamp + random nonce. Call once per session; each call returns a different value.

- `connectorId` `<ConnectorId>`: Same identifier as used for `create`.
- Returns: `<HashId>` 197 lowercase hex characters.

### instance.request(hashId, expireTime?)

Build the encoded request payload for the given hash and optional expiry window.

- `hashId` `<HashId>`: 197-char hex from `generate`.
- `expireTime` `<ExpireTime | undefined>`: Window in seconds (1–60). Default 10.
- Returns: `<RequestId>` Encoded string of length 205, or `''` if `hashId` invalid.

### instance.decode(hashId, requestId)

**Client only.** Decode request payload and return the numeric code when hash matches and not expired. Use the returned code to show the user so they can enter it at the verifier.

- `hashId` `<HashId>`: Expected hash for this session.
- `requestId` `<RequestId>`: Encoded payload from `request`.
- Returns: `<CodeId | null>` Integer in 0–1e10, or null when invalid/expired/wrong hash.

### instance.verify(requestId, secret)

**Verifier only.** Check that the user-provided secret matches the derived code and the payload is not expired.

- `requestId` `<RequestId>`: Encoded payload (received from client, e.g. via QR).
- `secret` `<VerifySecret>`: Number or string of digits (user-entered code).
- Returns: `<boolean>` True when not expired and code matches.

## Option Types

Types are exported for TypeScript: `import type { CodeId, ConnectorId, DecodedPayload, ExpireTime, HashId, RequestId, VerifySecret } from '@neabyte/trustless-id'`.

- **ConnectorId:** `<string>` — Caller identifier.
- **HashId:** `<string>` — 197-char hex from `generate`.
- **RequestId:** `<string>` — Encoded payload from `request`.
- **CodeId:** `<number>` — Numeric code from `decode` (0–1e10).
- **ExpireTime:** `<number>` — Window in seconds (1–60).
- **VerifySecret:** `<string | number>` — Value for `verify`.
- **DecodedPayload:** `{ hashId: HashId, slot: number, window: number }` — Internal decoded parts (slot base-36, window in seconds).

## Reference

- [README](README.md) — Installation and quick start.
- Tests under `tests/` — Trustless flow, Cipher, Security, Expiration, EdgeCases.
