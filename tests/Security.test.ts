import { assert, assertEquals } from '@std/assert'
import Trustless from '@app/index.ts'
import Cipher from '@app/Cipher.ts'

const hashHexLen = 197
const rawLen = 6 + 2 + hashHexLen

function makeConnectorId(domain: string): string {
  return `trustless://auth/${encodeURIComponent(domain)}:0.1.0?service=none`
}

Deno.test('Security - connectorId very long create and request succeed', () => {
  const longConnectorId = 'x'.repeat(50_000)
  const instance = Trustless.create(longConnectorId)
  const hashId = Trustless.getHash(longConnectorId)
  const requestId = instance.request(hashId, 10)
  assertEquals(requestId.length, rawLen)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  assertEquals(instance.verify(requestId, codeId!), true)
})

Deno.test('Security - decode returns CodeId in range 0 to 1e10', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  assertEquals(codeId! >= 0, true)
  assertEquals(codeId! <= 1e10, true)
})

Deno.test('Security - decode with wrong hashId returns null', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashIdReal = Trustless.getHash(connectorId)
  const hashIdFake = Trustless.getHash('other-connector')
  const requestId = instance.request(hashIdReal, 10)
  const codeId = instance.decode(hashIdFake, requestId)
  assertEquals(codeId, null)
})

Deno.test('Security - different connectorId yields different encryption key', () => {
  const keyA = Cipher.generateHash(String(makeConnectorId('a')).trim())
  const keyB = Cipher.generateHash(String(makeConnectorId('b')).trim())
  assertEquals(keyA !== keyB, true)
})

Deno.test(
  'Security - hashId from connector A with requestId from connector B decode returns null',
  () => {
    const connectorA = makeConnectorId('domain-a.com')
    const connectorB = makeConnectorId('domain-b.com')
    const instanceA = Trustless.create(connectorA)
    const instanceB = Trustless.create(connectorB)
    const hashIdA = Trustless.getHash(connectorA)
    const hashIdB = Trustless.getHash(connectorB)
    const requestIdB = instanceB.request(hashIdB, 10)
    const codeFromAWithBRequest = instanceA.decode(hashIdA, requestIdB)
    assertEquals(codeFromAWithBRequest, null)
    const codeFromB = instanceB.decode(hashIdB, requestIdB)
    assert(codeFromB !== null)
  }
)

Deno.test('Security - random string as requestId decode returns null', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const randomRequestId = 'a'.repeat(rawLen)
  const codeId = instance.decode(hashId, randomRequestId)
  assertEquals(codeId, null)
})

Deno.test('Security - random string as requestId verify returns false', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  assertEquals(instance.verify('x'.repeat(rawLen), 12345), false)
})

Deno.test('Security - replay of old requestId after window decode returns null', async () => {
  const connectorId = makeConnectorId('replay.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 1)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  await new Promise((r) => setTimeout(r, 2100))
  const codeAfter = instance.decode(hashId, requestId)
  assertEquals(codeAfter, null)
})

Deno.test('Security - replay of old requestId after window verify returns false', async () => {
  const connectorId = makeConnectorId('replay-verify.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 1)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  await new Promise((r) => setTimeout(r, 2100))
  assertEquals(instance.verify(requestId, codeId!), false)
})

Deno.test('Security - requestId from connector A cannot be decoded by connector B', () => {
  const connectorA = makeConnectorId('domain-a.com')
  const connectorB = makeConnectorId('domain-b.com')
  const instanceA = Trustless.create(connectorA)
  const instanceB = Trustless.create(connectorB)
  const hashId = Trustless.getHash(connectorA)
  const requestId = instanceA.request(hashId, 10)
  const codeFromB = instanceB.decode(hashId, requestId)
  assertEquals(codeFromB, null)
})

Deno.test('Security - requestId length 204 decode returns null', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  assertEquals(instance.decode(hashId, 'x'.repeat(204)), null)
})

Deno.test('Security - requestId length 204 verify returns false', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  assertEquals(instance.verify('x'.repeat(204), 12345), false)
})

Deno.test('Security - requestId length 206 decode returns null', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  assertEquals(instance.decode(hashId, 'x'.repeat(206)), null)
})

Deno.test('Security - requestId length 0 verify returns false', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  assertEquals(instance.verify('', 12345), false)
})

Deno.test(
  'Security - requestId valid length but invalid internal format decode returns null',
  () => {
    const connectorId = makeConnectorId('example.com')
    const instance = Trustless.create(connectorId)
    const hashId = Trustless.getHash(connectorId)
    const malformed = '!!!!!!' + '01' + 'z'.repeat(hashHexLen)
    assertEquals(malformed.length, rawLen)
    assertEquals(instance.decode(hashId, malformed), null)
  }
)

Deno.test(
  'Security - requestId valid length but invalid internal format verify returns false',
  () => {
    const connectorId = makeConnectorId('example.com')
    const instance = Trustless.create(connectorId)
    const malformed = '!!!!!!' + '01' + 'z'.repeat(hashHexLen)
    assertEquals(instance.verify(malformed, 12345), false)
  }
)

Deno.test('Security - reusing requestId with correct hashId and code still verifies', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  assertEquals(instance.verify(requestId, codeId!), true)
  assertEquals(instance.verify(requestId, codeId!), true)
})

Deno.test('Security - tampered requestId decode returns null', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  const tampered = requestId.slice(0, 10) + 'X' + requestId.slice(11)
  const codeId = instance.decode(hashId, tampered)
  assertEquals(codeId, null)
})

Deno.test('Security - tampered requestId verify returns false', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  const tampered = requestId.slice(0, 50) + 'Y' + requestId.slice(51)
  assertEquals(instance.verify(tampered, codeId!), false)
})

Deno.test('Security - two different hashIds same connector decode only with own requestId', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId1 = Trustless.getHash(connectorId)
  const hashId2 = Trustless.getHash(connectorId)
  assert(hashId1 !== hashId2)
  const requestId1 = instance.request(hashId1, 10)
  const requestId2 = instance.request(hashId2, 10)
  assert(instance.decode(hashId1, requestId1) !== null)
  assert(instance.decode(hashId2, requestId2) !== null)
  assertEquals(instance.decode(hashId1, requestId2), null)
  assertEquals(instance.decode(hashId2, requestId1), null)
})

Deno.test(
  'Security - verify with requestId from connector A fails when verified by connector B',
  () => {
    const connectorA = makeConnectorId('domain-a.com')
    const connectorB = makeConnectorId('domain-b.com')
    const instanceA = Trustless.create(connectorA)
    const instanceB = Trustless.create(connectorB)
    const hashId = Trustless.getHash(connectorA)
    const requestId = instanceA.request(hashId, 10)
    const codeId = instanceA.decode(hashId, requestId)
    assert(codeId !== null)
    const verifiedByB = instanceB.verify(requestId, codeId!)
    assertEquals(verifiedByB, false)
  }
)

Deno.test('Security - verify with wrong secret returns false', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  assertEquals(instance.verify(requestId, codeId! + 1), false)
  assertEquals(instance.verify(requestId, 0), false)
})

Deno.test('Security - verify with large wrong secret returns false', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  const requestId = instance.request(hashId, 10)
  assertEquals(instance.verify(requestId, 9999999999), false)
})

Deno.test('Security - wrong length requestId decode returns null', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.getHash(connectorId)
  assertEquals(instance.decode(hashId, ''), null)
  assertEquals(instance.decode(hashId, 'short'), null)
  assertEquals(instance.decode(hashId, 'x'.repeat(rawLen - 1)), null)
  assertEquals(instance.decode(hashId, 'x'.repeat(rawLen + 1)), null)
})
