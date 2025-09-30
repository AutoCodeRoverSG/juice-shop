/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// Additional Sonar issues for testing

import { type Request, type Response, type NextFunction } from 'express'

// Issue: Weak cryptographic algorithm (Security - Major)
import crypto from 'crypto'

export function weakEncryption(data: string): string {
  // MD5 is considered cryptographically weak
  return crypto.createHash('md5').update(data).digest('hex')
}

// Issue: Empty catch block (Code Smell - Major)
export function emptyCatchBlock(): void {
  try {
    // Some risky operation
    JSON.parse('invalid json')
  } catch (error) {
    // Empty catch block - bad practice
  }
}

// Issue: Magic numbers (Code Smell - Minor)
export function magicNumbers(value: number): boolean {
  return value > 42 && value < 1337 && value !== 999
}

module.exports = {
  weakEncryption,
  emptyCatchBlock,
  magicNumbers
}