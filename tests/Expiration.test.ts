import { assert, assertEquals } from '@std/assert'
import Trustless from '@app/index.ts'
import Cipher from '@app/Cipher.ts'

function makeConnectorId(domain: string): string {
  return `trustless://auth/${encodeURIComponent(domain)}:0.1.0?service=none`
}

Deno.test('Expiration - after window passes decode returns null', async () => {
  const connectorId = makeConnectorId('expire-test.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.generate(connectorId)
  const requestId = instance.request(hashId, 1)
  const codeBefore = instance.decode(hashId, requestId)
  assertEquals(codeBefore !== null, true)
  await new Promise((r) => setTimeout(r, 2100))
  const codeAfter = instance.decode(hashId, requestId)
  assertEquals(codeAfter, null)
})

Deno.test('Expiration - after window passes verify returns false', async () => {
  const connectorId = makeConnectorId('expire-verify.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.generate(connectorId)
  const requestId = instance.request(hashId, 1)
  const codeId = instance.decode(hashId, requestId)
  assert(codeId !== null)
  await new Promise((r) => setTimeout(r, 2100))
  assertEquals(instance.verify(requestId, codeId!), false)
})

Deno.test('Expiration - decode when hashId matches but slot expired returns null', () => {
  const connectorId = makeConnectorId('past-slot.com')
  const key = Cipher.generateHash(String(connectorId).trim())
  const hashId = Trustless.generate(connectorId)
  const pastSlot = 0
  const requestId = Cipher.encodePayload(hashId, pastSlot, 60, key)
  const instance = Trustless.create(connectorId)
  const codeId = instance.decode(hashId, requestId)
  assertEquals(codeId, null)
})

Deno.test('Expiration - isExpired true for past slot', () => {
  const key = Cipher.generateHash('k')
  const hashId = Cipher.generateHash('h')
  const pastSlot = 0
  const windowSeconds = 60
  const requestId = Cipher.encodePayload(hashId, pastSlot, windowSeconds, key)
  assertEquals(Cipher.isExpired(requestId, key), true)
})

Deno.test('Expiration - request with expireTime 1 uses 1s window', () => {
  const connectorId = makeConnectorId('window1.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.generate(connectorId)
  const requestId = instance.request(hashId, 1)
  const codeId = instance.decode(hashId, requestId)
  assertEquals(codeId !== null, true)
})

Deno.test(
  'Expiration - request with expireTime 60 produces requestId valid in same 60s window',
  () => {
    const connectorId = makeConnectorId('window60.com')
    const instance = Trustless.create(connectorId)
    const hashId = Trustless.generate(connectorId)
    const requestId = instance.request(hashId, 60)
    const codeId = instance.decode(hashId, requestId)
    assert(codeId !== null)
    assertEquals(instance.verify(requestId, codeId!), true)
  }
)

Deno.test('Expiration - within same window decode and verify succeed', async () => {
  const connectorId = makeConnectorId('within-window.com')
  const instance = Trustless.create(connectorId)
  const hashId = Trustless.generate(connectorId)
  const requestId = instance.request(hashId, 10)
  await new Promise((r) => setTimeout(r, 500))
  const codeId = instance.decode(hashId, requestId)
  assertEquals(codeId !== null, true)
  assertEquals(instance.verify(requestId, codeId!), true)
})
