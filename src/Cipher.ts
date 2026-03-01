import type * as Types from '@app/Types.ts'

/**
 * Payload encoding, hashing, and time-slot logic.
 * @description Fixed schema, XOR transform, and expiry checks.
 */
export default class Cipher {
  /** Encoding and hash constants plus derived lengths. */
  private static readonly schema = {
    alphabetOut: '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ-_',
    alphabetOutSize: 64,
    alphabetRaw: '0123456789abcdefghijklmnopqrstuvwxyz',
    alphabetRawSize: 36,
    blockCount: 13,
    hashHexLen: 197,
    maxWindow: 60,
    minWindow: 1,
    mixConstants: [2654435761, 1597334677, 2246822507, 3266489909],
    slotLen: 6,
    windowLen: 2,
    get payloadLen(): number {
      return this.slotLen + this.windowLen + this.hashHexLen
    },
    seeds: [0xdeadbeef, 0x41c6ce57, 0x8b3c9a2f, 0x7f2d1e4b, 0xc4a5b6d7],
    get slotBase(): number {
      return this.alphabetRawSize ** this.slotLen
    }
  }

  /** Hash output length in hex chars (197). */
  static get hashHexLen(): number {
    return Cipher.schema.hashHexLen
  }

  /**
   * Clamp expire time to valid window range.
   * @description Floors and bounds value between min and max window.
   * @param expireTime - Desired window in seconds
   * @returns Clamped window in 1–60
   */
  static clampWindow(expireTime: number): number {
    return Math.max(
      Cipher.schema.minWindow,
      Math.min(Cipher.schema.maxWindow, Math.floor(expireTime))
    )
  }

  /**
   * Decode requestId to slot, window, and hashId.
   * @description Validates length, optional XOR, and hex segment.
   * @param requestId - Encoded payload string
   * @param encryptionKey - Key for XOR inverse when non-empty
   * @returns Decoded payload or null when invalid
   */
  static decodePayload(
    requestId: Types.RequestId,
    encryptionKey: string
  ): Types.DecodedPayload | null {
    const payloadString = String(requestId)
    if (payloadString.length !== Cipher.schema.payloadLen) {
      return null
    }
    const rawPayload = encryptionKey.length
      ? Cipher.xorInverse(payloadString, encryptionKey)
      : payloadString
    const slotString = rawPayload.slice(0, Cipher.schema.slotLen)
    const windowString = rawPayload.slice(
      Cipher.schema.slotLen,
      Cipher.schema.slotLen + Cipher.schema.windowLen
    )
    const hashId = rawPayload.slice(
      Cipher.schema.slotLen + Cipher.schema.windowLen,
      Cipher.schema.payloadLen
    )
    const timeSlot = parseInt(slotString, 36)
    const windowSeconds = parseInt(windowString, 10)
    if (Number.isNaN(timeSlot) || Number.isNaN(windowSeconds)) {
      return null
    }
    if (hashId.length !== Cipher.hashHexLen || !/^[0-9a-f]{197}$/.test(hashId)) {
      return null
    }
    if (windowSeconds < Cipher.schema.minWindow || windowSeconds > Cipher.schema.maxWindow) {
      return null
    }
    return { hashId, slot: timeSlot, window: windowSeconds }
  }

  /**
   * Derive numeric secret from hashId and requestId.
   * @description FNV-1a style mix, modulo 1e10, non-negative.
   * @param hashId - 197-char hex hash
   * @param requestId - Full encoded payload
   * @returns Integer code in 0–1e10
   */
  static deriveSecret(hashId: Types.HashId, requestId: Types.RequestId): number {
    let hashState = 0x811c9dc5
    const combinedInput = hashId + requestId
    for (let charIndex = 0; charIndex < combinedInput.length; charIndex++) {
      hashState = Math.imul(hashState ^ combinedInput.charCodeAt(charIndex), 16777619)
    }
    const codeValue = (hashState >>> 0) % 1e10
    return Math.abs(codeValue)
  }

  /**
   * Encode hashId, slot, and window into requestId.
   * @description Builds raw payload then optional XOR with key.
   * @param hashId - 197-char hex hash
   * @param timeSlot - Slot index (base-36)
   * @param windowSeconds - Window size 1–60
   * @param encryptionKey - Key for XOR when non-empty
   * @returns Encoded requestId string
   */
  static encodePayload(
    hashId: Types.HashId,
    timeSlot: number,
    windowSeconds: number,
    encryptionKey: string
  ): Types.RequestId {
    const slotValue = ((timeSlot % Cipher.schema.slotBase) + Cipher.schema.slotBase) %
      Cipher.schema.slotBase
    const slotString = slotValue.toString(36).padStart(Cipher.schema.slotLen, '0')
    const windowString = String(windowSeconds).padStart(Cipher.schema.windowLen, '0')
    const rawPayload = slotString + windowString + hashId
    if (rawPayload.length !== Cipher.schema.payloadLen) {
      return rawPayload
    }
    if (!encryptionKey.length) {
      return rawPayload
    }
    return Cipher.xorTransform(rawPayload, encryptionKey)
  }

  /**
   * Generate 197-char hex hash from input.
   * @description Multi-block mix with seeds; output trimmed to 197 hex.
   * @param inputString - Input to hash (trimmed)
   * @returns 197 lowercase hex chars
   */
  static generateHash(inputString: string): string {
    const trimmedInput = String(inputString).trim()
    let hexOutput = ''
    for (let blockIndex = 0; blockIndex < Cipher.schema.blockCount; blockIndex++) {
      const seedA = Cipher.schema.seeds[blockIndex % 5]!
      const seedB = Cipher.schema.seeds[(blockIndex + 1) % 5]!
      const [statePart1, statePart2] = Cipher.mixBlock(
        seedA ^ blockIndex,
        seedB ^ (blockIndex * 7),
        trimmedInput
      )
      hexOutput += (statePart1 >>> 0).toString(16).padStart(8, '0')
      hexOutput += (statePart2 >>> 0).toString(16).padStart(8, '0')
    }
    return hexOutput.substring(0, Cipher.hashHexLen)
  }

  /**
   * Check if requestId is past its time window.
   * @description Decodes then compares current slot to payload slot.
   * @param requestId - Encoded payload
   * @param encryptionKey - Key for decode
   * @returns True when expired or decode failed
   */
  static isExpired(requestId: Types.RequestId, encryptionKey: string): boolean {
    const decodedPayload = Cipher.decodePayload(requestId, encryptionKey)
    if (!decodedPayload) {
      return true
    }
    const timestampSeconds = Math.floor(Date.now() / 1000)
    const currentTimeSlot = Math.floor(timestampSeconds / decodedPayload.window) %
      Cipher.schema.slotBase
    return currentTimeSlot !== decodedPayload.slot % Cipher.schema.slotBase
  }

  /**
   * Mix block: fold input into two state words.
   * @description Uses mixConstants and bit shifts; returns uint32 pair.
   * @param statePart1 - First state word
   * @param statePart2 - Second state word
   * @param inputString - Chars to mix in
   * @returns Tuple of two uint32 values
   */
  private static mixBlock(
    statePart1: number,
    statePart2: number,
    inputString: string
  ): [number, number] {
    const [mix0, mix1, mix2, mix3] = Cipher.schema.mixConstants
    for (let charIndex = 0; charIndex < inputString.length; charIndex++) {
      const charCode = inputString.charCodeAt(charIndex)
      statePart1 = Math.imul(statePart1 ^ charCode, mix0!)
      statePart2 = Math.imul(statePart2 ^ charCode, mix1!)
    }
    statePart1 = Math.imul(statePart1 ^ (statePart1 >>> 16), mix2!) ^
      Math.imul(statePart2 ^ (statePart2 >>> 13), mix3!)
    statePart2 = Math.imul(statePart2 ^ (statePart2 >>> 16), mix2!) ^
      Math.imul(statePart1 ^ (statePart1 >>> 13), mix3!)
    return [statePart1 >>> 0, statePart2 >>> 0]
  }

  /**
   * XOR-decode ciphertext with key via alphabets.
   * @description Output alphabet index XOR key index to raw char.
   * @param ciphertext - Encoded string
   * @param encryptionKey - Repeating key
   * @returns Plaintext or ciphertext on invalid char
   */
  private static xorInverse(ciphertext: string, encryptionKey: string): string {
    let decodedChars = ''
    for (let charIndex = 0; charIndex < ciphertext.length; charIndex++) {
      const outputCharIndex = Cipher.schema.alphabetOut.indexOf(ciphertext.charAt(charIndex))
      if (outputCharIndex === -1) {
        return ciphertext
      }
      const keyCharIndex = Cipher.schema.alphabetRaw.indexOf(
        encryptionKey.charAt(charIndex % encryptionKey.length)
      )
      if (keyCharIndex === -1) {
        return ciphertext
      }
      const rawCharIndex = outputCharIndex ^ keyCharIndex
      if (rawCharIndex >= Cipher.schema.alphabetRawSize) {
        return ciphertext
      }
      decodedChars += Cipher.schema.alphabetRaw[rawCharIndex]
    }
    return decodedChars
  }

  /**
   * XOR-encode plaintext with key via alphabets.
   * @description Raw index XOR key index to output alphabet char.
   * @param plaintext - Raw payload string
   * @param encryptionKey - Repeating key
   * @returns Ciphertext or plaintext on invalid char
   */
  private static xorTransform(plaintext: string, encryptionKey: string): string {
    let encodedChars = ''
    for (let charIndex = 0; charIndex < plaintext.length; charIndex++) {
      const rawCharIndex = Cipher.schema.alphabetRaw.indexOf(plaintext.charAt(charIndex))
      if (rawCharIndex === -1) {
        return plaintext
      }
      const keyCharIndex = Cipher.schema.alphabetRaw.indexOf(
        encryptionKey.charAt(charIndex % encryptionKey.length)
      )
      if (keyCharIndex === -1) {
        return plaintext
      }
      const outputCharIndex = rawCharIndex ^ keyCharIndex
      if (outputCharIndex >= Cipher.schema.alphabetOutSize) {
        return plaintext
      }
      encodedChars += Cipher.schema.alphabetOut[outputCharIndex]
    }
    return encodedChars
  }
}
