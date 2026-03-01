import { assertEquals, assertMatch } from '@std/assert'
import Cipher from '@app/Cipher.ts'

const hashHexLen = 197
const rawLen = 6 + 2 + hashHexLen

Deno.test('Cipher - clampWindow floors and clamps value in range', () => {
  assertEquals(Cipher.clampWindow(1), 1)
  assertEquals(Cipher.clampWindow(10), 10)
  assertEquals(Cipher.clampWindow(30.9), 30)
})

Deno.test('Cipher - clampWindow Infinity returns max', () => {
  assertEquals(Cipher.clampWindow(Infinity), 60)
})

Deno.test('Cipher - clampWindow returns max when expireTime above max', () => {
  assertEquals(Cipher.clampWindow(60), 60)
  assertEquals(Cipher.clampWindow(61), 60)
  assertEquals(Cipher.clampWindow(100), 60)
})

Deno.test('Cipher - clampWindow returns min when expireTime below min', () => {
  assertEquals(Cipher.clampWindow(0), 1)
  assertEquals(Cipher.clampWindow(-1), 1)
  assertEquals(Cipher.clampWindow(0.5), 1)
})

Deno.test('Cipher - decodePayload returns null for invalid base64url chars in requestId', () => {
  const key = Cipher.generateHash('key')
  const invalid = '!!!!!!' + '01' + 'a'.repeat(hashHexLen)
  assertEquals(invalid.length, rawLen)
  const decoded = Cipher.decodePayload(invalid, key)
  assertEquals(decoded, null)
})

Deno.test('Cipher - decodePayload returns null for requestId length 204', () => {
  const key = Cipher.generateHash('key')
  assertEquals(Cipher.decodePayload('x'.repeat(204), key), null)
})

Deno.test('Cipher - decodePayload returns null for requestId length 206', () => {
  const key = Cipher.generateHash('key')
  assertEquals(Cipher.decodePayload('x'.repeat(206), key), null)
})

Deno.test('Cipher - decodePayload returns null for wrong length', () => {
  const key = Cipher.generateHash('key')
  assertEquals(Cipher.decodePayload('short', key), null)
  assertEquals(Cipher.decodePayload('x'.repeat(rawLen + 1), key), null)
})

Deno.test('Cipher - decodePayload returns null when decoded window out of range', () => {
  const rawPayload = '000000' + '61' + 'a'.repeat(hashHexLen)
  assertEquals(rawPayload.length, rawLen)
  assertEquals(Cipher.decodePayload(rawPayload, ''), null)
})

Deno.test(
  'Cipher - decodePayload returns null when hashId segment not 197 hex with empty key',
  () => {
    const rawPayload = '000000' + '10' + 'g'.repeat(hashHexLen)
    assertEquals(rawPayload.length, rawLen)
    assertEquals(Cipher.decodePayload(rawPayload, ''), null)
  }
)

Deno.test('Cipher - decodePayload returns null when slot parses as NaN', () => {
  const rawPayload = '------' + '10' + 'a'.repeat(hashHexLen)
  assertEquals(rawPayload.length, rawLen)
  assertEquals(Cipher.decodePayload(rawPayload, ''), null)
})

Deno.test('Cipher - decodePayload returns null when windowString parses as NaN', () => {
  const rawPayload = '000000' + 'ab' + 'a'.repeat(hashHexLen)
  assertEquals(rawPayload.length, rawLen)
  assertEquals(Cipher.decodePayload(rawPayload, ''), null)
})

Deno.test('Cipher - decodePayload round-trip with empty key', () => {
  const hashId = Cipher.generateHash('id')
  const timeSlot = Math.floor(Date.now() / 10) % 0xffffff
  const windowSeconds = 10
  const requestId = Cipher.encodePayload(hashId, timeSlot, windowSeconds, '')
  assertEquals(requestId.length, rawLen)
  const decoded = Cipher.decodePayload(requestId, '')
  assertEquals(decoded !== null, true)
  if (decoded) {
    assertEquals(decoded.hashId, hashId)
    assertEquals(decoded.slot, timeSlot)
    assertEquals(decoded.window, windowSeconds)
  }
})

Deno.test('Cipher - decodePayload round-trip with same key', () => {
  const key = Cipher.generateHash('connector')
  const hashId = Cipher.generateHash('id' + Date.now())
  const timeSlot = Math.floor(Date.now() / 10) % 0xffffff
  const windowSeconds = 10
  const requestId = Cipher.encodePayload(hashId, timeSlot, windowSeconds, key)
  const decoded = Cipher.decodePayload(requestId, key)
  assertEquals(decoded !== null, true)
  if (decoded) {
    assertEquals(decoded.hashId, hashId)
    assertEquals(decoded.slot, timeSlot)
    assertEquals(decoded.window, windowSeconds)
  }
})

Deno.test('Cipher - decodePayload with wrong key does not reveal original hashId', () => {
  const keyA = Cipher.generateHash('connector-a')
  const keyB = Cipher.generateHash('connector-b')
  const hashId = Cipher.generateHash('id')
  const timeSlot = Math.floor(Date.now() / 10) % 0xffffff
  const requestId = Cipher.encodePayload(hashId, timeSlot, 10, keyA)
  const decodedWithB = Cipher.decodePayload(requestId, keyB)
  if (decodedWithB === null) {
    return
  }
  assertEquals(decodedWithB.hashId === hashId, false)
})

Deno.test('Cipher - deriveSecret differs for different hashId', () => {
  const key = Cipher.generateHash('k')
  const requestId = Cipher.encodePayload(
    Cipher.generateHash('h1'),
    Math.floor(Date.now() / 10),
    10,
    key
  )
  const code1 = Cipher.deriveSecret(Cipher.generateHash('h1'), requestId)
  const code2 = Cipher.deriveSecret(Cipher.generateHash('h2'), requestId)
  assertEquals(code1 !== code2, true)
})

Deno.test('Cipher - deriveSecret differs for different requestId', () => {
  const hashId = Cipher.generateHash('h')
  const key = Cipher.generateHash('k')
  const req1 = Cipher.encodePayload(hashId, 100, 10, key)
  const req2 = Cipher.encodePayload(hashId, 101, 10, key)
  assertEquals(Cipher.deriveSecret(hashId, req1) !== Cipher.deriveSecret(hashId, req2), true)
})

Deno.test('Cipher - deriveSecret is deterministic for same hashId and requestId', () => {
  const hashId = Cipher.generateHash('h')
  const key = Cipher.generateHash('k')
  const requestId = Cipher.encodePayload(hashId, Math.floor(Date.now() / 10), 10, key)
  const a = Cipher.deriveSecret(hashId, requestId)
  const b = Cipher.deriveSecret(hashId, requestId)
  assertEquals(a, b)
})

Deno.test('Cipher - deriveSecret returns non-negative number', () => {
  const hashId = Cipher.generateHash('h')
  const key = Cipher.generateHash('k')
  const requestId = Cipher.encodePayload(hashId, Math.floor(Date.now() / 10), 10, key)
  const code = Cipher.deriveSecret(hashId, requestId)
  assertEquals(Number.isInteger(code), true)
  assertEquals(code >= 0, true)
})

Deno.test('Cipher - deriveSecret returns value in range 0 to 1e10', () => {
  const hashId = Cipher.generateHash('h')
  const key = Cipher.generateHash('k')
  const requestId = Cipher.encodePayload(hashId, Math.floor(Date.now() / 10), 10, key)
  const code = Cipher.deriveSecret(hashId, requestId)
  assertEquals(code >= 0, true)
  assertEquals(code <= 1e10, true)
})

Deno.test('Cipher - deriveSecret with empty hashId returns integer in range', () => {
  const key = Cipher.generateHash('k')
  const requestId = Cipher.encodePayload(
    Cipher.generateHash('h'),
    Math.floor(Date.now() / 10),
    10,
    key
  )
  const code = Cipher.deriveSecret('', requestId)
  assertEquals(Number.isInteger(code), true)
  assertEquals(code >= 0 && code <= 1e10, true)
})

Deno.test('Cipher - deriveSecret with empty requestId returns integer in range', () => {
  const hashId = Cipher.generateHash('h')
  const code = Cipher.deriveSecret(hashId, '')
  assertEquals(Number.isInteger(code), true)
  assertEquals(code >= 0 && code <= 1e10, true)
})

Deno.test('Cipher - encodePayload returns length rawLen when key present', () => {
  const key = Cipher.generateHash('connector')
  const hashId = Cipher.generateHash('id' + Date.now())
  const timeSlot = Math.floor(Date.now() / 10) % 0xffffff
  const requestId = Cipher.encodePayload(hashId, timeSlot, 10, key)
  assertEquals(requestId.length, rawLen)
})

Deno.test('Cipher - encodePayload returns length rawLen when timeSlot >= 36^6', () => {
  const key = Cipher.generateHash('connector')
  const hashId = Cipher.generateHash('id')
  const timeSlot = 36 ** 6
  const requestId = Cipher.encodePayload(hashId, timeSlot, 10, key)
  assertEquals(requestId.length, rawLen)
  const decoded = Cipher.decodePayload(requestId, key)
  assertEquals(decoded !== null, true)
})

Deno.test(
  'Cipher - encodePayload returns payload length not rawLen when hashId length not 197',
  () => {
    const key = Cipher.generateHash('k')
    const shortHashId = 'a'.repeat(196)
    const result = Cipher.encodePayload(shortHashId, 1, 10, key)
    assertEquals(result.length !== rawLen, true)
    assertEquals(result.length, 6 + 2 + 196)
  }
)

Deno.test('Cipher - generateHash differs for different input', () => {
  const a = Cipher.generateHash('a')
  const b = Cipher.generateHash('b')
  assertEquals(a !== b, true)
})

Deno.test('Cipher - generateHash is deterministic for same input', () => {
  const a = Cipher.generateHash('same')
  const b = Cipher.generateHash('same')
  assertEquals(a, b)
})

Deno.test('Cipher - generateHash returns 197 hex chars', () => {
  const hash = Cipher.generateHash('input')
  assertEquals(hash.length, hashHexLen)
  assertMatch(hash, /^[0-9a-f]{197}$/)
})

Deno.test('Cipher - generateHash trims input', () => {
  const a = Cipher.generateHash('  x  ')
  const b = Cipher.generateHash('x')
  assertEquals(a, b)
})

Deno.test('Cipher - generateHash with unicode input returns 197 hex', () => {
  const hash = Cipher.generateHash('café日本語')
  assertEquals(hash.length, hashHexLen)
  assertMatch(hash, /^[0-9a-f]{197}$/)
})

Deno.test('Cipher - generateHash with very long input returns 197 hex', () => {
  const hash = Cipher.generateHash('a'.repeat(1_000_000))
  assertEquals(hash.length, hashHexLen)
  assertMatch(hash, /^[0-9a-f]{197}$/)
})

Deno.test('Cipher - hashHexLen is 197', () => {
  assertEquals(Cipher.hashHexLen, 197)
})

Deno.test('Cipher - isExpired with malformed requestId returns true', () => {
  const key = Cipher.generateHash('k')
  assertEquals(Cipher.isExpired('x'.repeat(rawLen), key), true)
  assertEquals(Cipher.isExpired('short', key), true)
})
