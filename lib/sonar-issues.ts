/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

// This file contains intentional Sonar code quality issues for testing purposes

import { type Request, type Response } from 'express'
import fs from 'fs'
import crypto from 'crypto'

// Issue 1: Unused import (Code Smell - Major)
import * as path from 'path'

// Issue 2: Unused variable (Code Smell - Minor)
const UNUSED_CONSTANT = 'This variable is never used'

// Issue 3: Hard-coded credentials (Security Hotspot - Blocker)
const DATABASE_PASSWORD = 'admin123'
const API_KEY = 'sk-1234567890abcdef'

// Issue 4: Function with too many parameters (Code Smell - Major)
export function processUserData(
  userId: string,
  userName: string,
  userEmail: string,
  userPassword: string,
  userAge: number,
  userAddress: string,
  userPhone: string,
  userCountry: string,
  userRole: string,
  userStatus: string
): void {
  console.log('Processing user data...')
}

// Issue 5: Cognitive complexity too high (Code Smell - Critical)
export function complexFunction(data: any): any {
  if (data) {
    if (data.type === 'user') {
      if (data.status === 'active') {
        if (data.permissions) {
          if (data.permissions.read) {
            if (data.permissions.write) {
              if (data.permissions.delete) {
                if (data.role === 'admin') {
                  if (data.department === 'IT') {
                    if (data.clearance >= 5) {
                      return 'full_access'
                    } else {
                      return 'limited_access'
                    }
                  } else {
                    return 'department_access'
                  }
                } else {
                  return 'user_access'
                }
              } else {
                return 'read_write_access'
              }
            } else {
              return 'read_only_access'
            }
          } else {
            return 'no_access'
          }
        } else {
          return 'default_access'
        }
      } else {
        return 'inactive_user'
      }
    } else {
      return 'invalid_type'
    }
  } else {
    return null
  }
}

// Issue 6: Potential null pointer dereference (Bug - Major)
export function processRequest(req: Request): string {
  const userAgent = req.headers['user-agent']
  return userAgent.toLowerCase() // Potential null/undefined dereference
}

// Issue 7: Resource leak - file handle not closed (Bug - Major)
export function readConfigFile(): string {
  const fd = fs.openSync('/tmp/config.txt', 'r')
  const buffer = Buffer.alloc(1024)
  fs.readSync(fd, buffer, 0, 1024, 0)
  // Missing fs.closeSync(fd) - resource leak
  return buffer.toString()
}

// Issue 8: Dead code - unreachable statement (Code Smell - Major)
export function unreachableCode(): string {
  return 'This will always return here'
  console.log('This line is unreachable') // Dead code
  return 'This will never be reached'
}

// Issue 9: Duplicate code blocks (Code Smell - Major)
export function validateUserInput(input: string): boolean {
  if (!input) {
    console.log('Input validation failed: empty input')
    return false
  }
  if (input.length < 3) {
    console.log('Input validation failed: too short')
    return false
  }
  if (input.length > 100) {
    console.log('Input validation failed: too long')
    return false
  }
  return true
}

export function validatePasswordInput(password: string): boolean {
  if (!password) {
    console.log('Input validation failed: empty input') // Duplicate
    return false
  }
  if (password.length < 3) {
    console.log('Input validation failed: too short') // Duplicate
    return false
  }
  if (password.length > 100) {
    console.log('Input validation failed: too long') // Duplicate
    return false
  }
  return true
}

// Issue 10: SQL injection vulnerability pattern (Security - Blocker)
export function searchUsers(query: string): string {
  // This simulates a SQL injection vulnerability pattern
  const sqlQuery = `SELECT * FROM users WHERE name LIKE '%${query}%'`
  console.log('Executing query:', sqlQuery)
  return sqlQuery
}

// Additional complexity for the cognitive complexity function
export function anotherComplexFunction(input: any): any {
  for (let i = 0; i < input.length; i++) {
    if (input[i].type === 'data') {
      try {
        if (input[i].value) {
          switch (input[i].format) {
            case 'json':
              if (input[i].valid) {
                for (let j = 0; j < input[i].items.length; j++) {
                  if (input[i].items[j].active) {
                    return input[i].items[j]
                  }
                }
              }
              break
            case 'xml':
              if (input[i].parsed) {
                return input[i].content
              }
              break
            default:
              return null
          }
        }
      } catch (error) {
        console.log('Error processing item:', error)
      }
    }
  }
  return null
}