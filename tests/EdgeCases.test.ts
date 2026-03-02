import { assert, assertEquals } from '@std/assert'
import Trustless from '@app/index.ts'
import Cipher from '@app/Cipher.ts'

function makeConnectorId(domain: string): string {
  return `trustless://auth/${encodeURIComponent(domain)}:0.1.0?service=none`
}

Deno.test('EdgeCases - clampWindow Infinity returns 60', () => {
  assertEquals(Cipher.clampWindow(Infinity), 60)
})

Deno.test('EdgeCases - clampWindow with NaN returns NaN', () => {
  assertEquals(Number.isNaN(Cipher.clampWindow(NaN)), true)
})

Deno.test('EdgeCases - connectorId with whitespace is trimmed', () => {
  const connectorId = makeConnectorId('example.com')
  const withSpaces = '  ' + connectorId + '  '
  const instance = Trustless.create(withSpaces)
  const hashId = Trustless.generate(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode(hashId, requestId)
  assertEquals(codeId !== null, true)
  assertEquals(instance.verify(requestId, codeId!), true)
})

Deno.test('EdgeCases - decode with empty hashId string still validates by hashId match', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.generate(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode('', requestId)
  assertEquals(codeId, null)
})

Deno.test('EdgeCases - generateHash empty string after trim', () => {
  const hash = Cipher.generateHash('   ')
  assertEquals(hash.length, 197)
  assertEquals(/^[0-9a-f]{197}$/.test(hash), true)
})

Deno.test('EdgeCases - isExpired with invalid requestId returns true', () => {
  const key = Cipher.generateHash('k')
  assertEquals(Cipher.isExpired('x'.repeat(205), key), true)
  assertEquals(Cipher.isExpired('', key), true)
})

Deno.test('EdgeCases - request clamps expireTime to valid range', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.generate(connectorId)
  const requestIdZero = instance.request(hashId, 0)
  const requestIdHuge = instance.request(hashId, 999)
  assert(requestIdZero.length > 0)
  assert(requestIdHuge.length > 0)
  const codeZero = instance.decode(hashId, requestIdZero)
  const codeHuge = instance.decode(hashId, requestIdHuge)
  assertEquals(codeZero !== null, true)
  assertEquals(codeHuge !== null, true)
})

Deno.test('EdgeCases - request with hashId non-hex returns empty string', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  assertEquals(instance.request('g'.repeat(197), 10), '')
  assertEquals(instance.request('A'.repeat(197), 10), '')
})

Deno.test('EdgeCases - request with invalid hashId length returns empty string', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  assertEquals(instance.request('a'.repeat(196), 10), '')
  assertEquals(instance.request('a'.repeat(198), 10), '')
  assertEquals(instance.request('', 10), '')
})

Deno.test(
  'EdgeCases - request with NaN expireTime uses default window and produces valid requestId',
  () => {
    const connectorId = makeConnectorId('example.com')
    const instance = Trustless.create(connectorId)
    const hashId = Trustless.generate(connectorId)
    const requestId = instance.request(hashId, Number.NaN)
    assertEquals(requestId.length, 205)
    const codeId = instance.decode(hashId, requestId)
    assert(codeId !== null)
    assertEquals(instance.verify(requestId, codeId!), true)
  }
)

Deno.test(
  'EdgeCases - request with negative expireTime is clamped and produces valid requestId',
  () => {
    const connectorId = makeConnectorId('example.com')
    const instance = Trustless.create(connectorId)
    const hashId = Trustless.generate(connectorId)
    const requestId = instance.request(hashId, -5)
    assertEquals(requestId.length, 205)
    const codeId = instance.decode(hashId, requestId)
    assert(codeId !== null)
  }
)

Deno.test('EdgeCases - verify NaN secret returns false', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.generate(connectorId)
  const requestId = instance.request(hashId, 10)
  assertEquals(instance.verify(requestId, Number.NaN), false)
})

Deno.test('EdgeCases - verify with string leading zeros strips and validates', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.generate(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  const withLeadingZeros = '00' + String(codeId)
  assertEquals(instance.verify(requestId, withLeadingZeros), true)
})

Deno.test('EdgeCases - verify with string non-numeric secret returns false', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.generate(connectorId)
  const requestId = instance.request(hashId, 10)
  assertEquals(instance.verify(requestId, 'no-digits'), false)
  assertEquals(instance.verify(requestId, ''), false)
})

Deno.test('EdgeCases - verify with string secret strips non-digits and validates', () => {
  const connectorId = makeConnectorId('example.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.generate(connectorId)
  const requestId = instance.request(hashId, 10)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  const codeStr = String(codeId)
  assertEquals(instance.verify(requestId, codeStr), true)
  assertEquals(instance.verify(requestId, '  ' + codeStr + '  '), true)
  assertEquals(instance.verify(requestId, 'abc' + codeStr + 'def'), true)
})
