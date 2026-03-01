import Cipher from '@app/Cipher.ts'
import type * as Types from '@app/Types.ts'

/**
 * Trustless ID instance for request and verify.
 * @description Binds connectorId to encryption key and hash flow.
 */
export default class Trustless {
  /** Hash of trimmed connectorId for XOR and decode. */
  private readonly encryptionKey: string

  /**
   * Create instance with connector-bound key.
   * @description Hashes trimmed connectorId to set encryption key.
   * @param connectorId - Caller identifier (trimmed)
   */
  constructor(connectorId: Types.ConnectorId) {
    this.encryptionKey = Cipher.generateHash(String(connectorId).trim())
  }

  /**
   * Create Trustless instance for connector.
   * @description Factory that returns new Trustless with hashed key.
   * @param connectorId - Caller identifier
   * @returns New Trustless instance
   */
  static create(connectorId: Types.ConnectorId): Trustless {
    return new Trustless(connectorId)
  }

  /**
   * Generate one-time 197-char hex hash.
   * @description Hashes connectorId plus timestamp and random nonce.
   * @param connectorId - Caller identifier
   * @returns 197-char hex HashId
   */
  static getHash(connectorId: Types.ConnectorId): Types.HashId {
    const nonce = String(Date.now()) + String(Math.random())
    return Cipher.generateHash(String(connectorId).trim() + nonce)
  }

  /**
   * Decode requestId to code when hashId matches.
   * @description Decodes requestId; returns code when hash matches, not expired.
   * @param hashId - Expected 197-char hex hash
   * @param requestId - Encoded payload from request
   * @returns Code or null when invalid or expired
   */
  decode(hashId: Types.HashId, requestId: Types.RequestId): Types.CodeId | null {
    const decodedPayload = Cipher.decodePayload(requestId, this.encryptionKey)
    if (!decodedPayload) {
      return null
    }
    if (Cipher.isExpired(requestId, this.encryptionKey)) {
      return null
    }
    if (decodedPayload.hashId !== hashId) {
      return null
    }
    return Cipher.deriveSecret(hashId, requestId)
  }

  /**
   * Build requestId for hashId and optional window.
   * @description Validates hashId then encodes with current slot and window.
   * @param hashId - 197-char hex from getHash
   * @param expireTime - Optional window seconds (default 10)
   * @returns RequestId string or empty when hashId invalid
   */
  request(hashId: Types.HashId, expireTime?: Types.ExpireTime): Types.RequestId {
    const hashIdStr = String(hashId)
    if (hashIdStr.length !== Cipher.hashHexLen || !/^[0-9a-f]{197}$/.test(hashIdStr)) {
      return ''
    }
    const effective = expireTime ?? 10
    const windowSeconds = Number.isFinite(effective) ? Cipher.clampWindow(effective) : 10
    const timestampSeconds = Math.floor(Date.now() / 1000)
    const timeSlot = Math.floor(timestampSeconds / windowSeconds)
    return Cipher.encodePayload(hashIdStr, timeSlot, windowSeconds, this.encryptionKey)
  }

  /**
   * Verify requestId with user-provided secret.
   * @description Decodes, checks expiry, compares derived code to secret.
   * @param requestId - Encoded payload to verify
   * @param secret - Number or string digits from user
   * @returns True when not expired and code matches
   */
  verify(requestId: Types.RequestId, secret: Types.VerifySecret): boolean {
    const decodedPayload = Cipher.decodePayload(requestId, this.encryptionKey)
    if (!decodedPayload) {
      return false
    }
    if (Cipher.isExpired(requestId, this.encryptionKey)) {
      return false
    }
    const expectedCode = Cipher.deriveSecret(decodedPayload.hashId, requestId)
    const actualCode = typeof secret === 'number'
      ? secret
      : parseInt(String(secret).replace(/\D/g, ''), 10)
    if (Number.isNaN(actualCode)) {
      return false
    }
    return expectedCode >>> 0 === actualCode >>> 0
  }
}

/**
 * Re-export types.
 * @description Public types from Types module for consumers.
 */
export type * from '@app/Types.ts'
