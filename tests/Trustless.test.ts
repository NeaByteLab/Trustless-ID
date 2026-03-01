import { assert, assertEquals } from '@std/assert'
import Trustless from '@app/index.ts'

const hashHexLen = 197

function makeConnectorId(domain: string): string {
  return `trustless://auth/${encodeURIComponent(domain)}:0.1.0?service=none`
}

Deno.test('Trustless - create returns instance', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  assert(instance !== null)
  assert(typeof instance.request === 'function')
  assert(typeof instance.decode === 'function')
  assert(typeof instance.verify === 'function')
})

Deno.test('Trustless - decode returns integer CodeId when successful', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  assertEquals(typeof codeId, 'number')
  assertEquals(Number.isInteger(codeId), true)
})

Deno.test('Trustless - empty connectorId create and getHash produce valid flow', () => {
  const instance = Trustless.create('')
  const hashId = Trustless.getHash('')
  assertEquals(hashId.length, hashHexLen)
  assertEquals(/^[0-9a-f]{197}$/.test(hashId), true)
  const requestId = instance.request(hashId, 10)
  assertEquals(requestId.length, 6 + 2 + hashHexLen)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  assertEquals(instance.verify(requestId, codeId!), true)
})

Deno.test('Trustless - full flow decode returns code and verify succeeds', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  const verified = instance.verify(requestId, codeId!)
  assertEquals(verified, true)
})

Deno.test('Trustless - getHash different connectorIds returns different hashId', () => {
  const hashA = Trustless.getHash(makeConnectorId('a.com'))
  const hashB = Trustless.getHash(makeConnectorId('b.com'))
  assertEquals(hashA !== hashB, true)
})

Deno.test('Trustless - getHash produces different hashes on each call', () => {
  const connectorId = makeConnectorId('example.com')
  const a = Trustless.getHash(connectorId)
  const b = Trustless.getHash(connectorId)
  assertEquals(a !== b, true)
})

Deno.test('Trustless - getHash returns 197-char hex', () => {
  const connectorId = makeConnectorId('example.com')
  const hashId = Trustless.getHash(connectorId)
  assertEquals(hashId.length, hashHexLen)
  assertEquals(/^[0-9a-f]{197}$/.test(hashId), true)
})

Deno.test('Trustless - invariant verify true when code from decode and not expired', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  assertEquals(instance.verify(requestId, codeId!), true)
})

Deno.test('Trustless - request returns fixed-length requestId', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  assertEquals(requestId.length, 6 + 2 + hashHexLen)
})

Deno.test('Trustless - request uses default expireTime when omitted', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId)
  assert(requestId.length > 0)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
})

Deno.test(
  'Trustless - request with expireTime 60 produces valid requestId and decode succeeds',
  () => {
    const connectorId = makeConnectorId('example.com')
    const instance = Trustless.create(connectorId)
    const hashId = Trustless.getHash(connectorId)
    const requestId = instance.request(hashId, 60)
    assertEquals(requestId.length, 6 + 2 + hashHexLen)
    const codeId = instance.decode(hashId, requestId)
    assert(codeId !== null)
  }
)

Deno.test('Trustless - request with explicit undefined expireTime uses default window', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, undefined)
  assertEquals(requestId.length, 6 + 2 + hashHexLen)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
})

Deno.test('Trustless - requestId contains only output alphabet characters', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  const outputAlphabet = /^[0-9a-zA-Z_-]{205}$/
  assertEquals(outputAlphabet.test(requestId), true)
})

Deno.test(
  'Trustless - same connectorId same hashId same window yields same code in same slot',
  () => {
    const connectorId = makeConnectorId('example.com')
    const instance = Trustless.create(connectorId)
    const hashId = Trustless.getHash(connectorId)
    const requestId1 = instance.request(hashId, 60)
    const requestId2 = instance.request(hashId, 60)
    const code1 = instance.decode(hashId, requestId1)
    const code2 = instance.decode(hashId, requestId2)
    assert(code1 !== null && code2 !== null)
    assertEquals(code1, code2)
    assertEquals(requestId1, requestId2)
  }
)

Deno.test('Trustless - two instances with same connectorId can decode each other request', () => {
  const connectorId = makeConnectorId('example.com')
  const instance1 = Trustless.create(connectorId)
  const instance2 = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance1.request(hashId, 10)
  const codeFrom2 = instance2.decode(hashId, requestId)
  assert(codeFrom2 !== null)
  assertEquals(instance2.verify(requestId, codeFrom2!), true)
})

Deno.test('Trustless - verify with number secret succeeds when code matches', () => {
  const connectorId = makeConnectorId('test.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  assertEquals(instance.verify(requestId, codeId!), true)
})

Deno.test('Trustless - verify with string digits succeeds when code matches', () => {
  const connectorId = makeConnectorId('test.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  assertEquals(instance.verify(requestId, String(codeId!)), true)
})
