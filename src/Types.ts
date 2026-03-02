/** Connector identifier from caller. */
export type ConnectorId = string

/** 197-char hex hash from generate. */
export type HashId = string

/** Encoded payload string from request. */
export type RequestId = string

/** Numeric code from decode for verification. */
export type CodeId = number

/** Expiry window in seconds (1–60). */
export type ExpireTime = number

/** Secret value for verify: number or string. */
export type VerifySecret = string | number

/**
 * Decoded request payload parts.
 * @description Slot, window, and hashId from requestId.
 */
export interface DecodedPayload {
  /** 197-char hex hash segment */
  hashId: HashId
  /** Time slot index (base-36) */
  slot: number
  /** Window size in seconds */
  window: number
}
