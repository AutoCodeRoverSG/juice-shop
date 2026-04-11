/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import * as models from '../models/index'
import { type Request, type Response, type NextFunction } from 'express'
import { UserModel } from '../models/user'
import { challenges } from '../data/datacache'

import * as utils from '../lib/utils'
const challengeUtils = require('../lib/challengeUtils')

class ErrorWithParent extends Error {
  parent: Error | undefined
}

// vuln-code-snippet start unionSqlInjectionChallenge dbSchemaChallenge
module.exports = function searchProducts () {
  return (req: Request, res: Response, next: NextFunction) => {
    let criteria: any = req.query.q === 'undefined' ? '' : req.query.q ?? ''
    criteria = (criteria.length <= 200) ? criteria : criteria.substring(0, 200)
    models.sequelize.query(`SELECT * FROM Products WHERE ((name LIKE '%${criteria}%' OR description LIKE '%${criteria}%') AND deletedAt IS NULL) ORDER BY name`) // vuln-code-snippet vuln-line unionSqlInjectionChallenge dbSchemaChallenge
      .then(([products]: any) => {
        const dataString = JSON.stringify(products)
        if (challengeUtils.notSolved(challenges.unionSqlInjectionChallenge)) { // vuln-code-snippet hide-start
          let solved = true
          UserModel.findAll().then(data => {
            const users = utils.queryResultToJson(data)
            if (users.data?.length) {
              for (let i = 0; i < users.data.length; i++) {
                solved = solved && utils.containsOrEscaped(dataString, users.data[i].email) && utils.contains(dataString, users.data[i].password)
                if (!solved) {
                  break
                }
              }
              if (solved) {
                challengeUtils.solve(challenges.unionSqlInjectionChallenge)
              }
            }
          }).catch((error: Error) => {
            next(error)
          })
        }
        if (challengeUtils.notSolved(challenges.dbSchemaChallenge)) {
          let solved = true
          void models.sequelize.query('SELECT sql FROM sqlite_master').then(([data]: any) => {
            const tableDefinitions = utils.queryResultToJson(data)
            if (tableDefinitions.data?.length) {
              for (let i = 0; i < tableDefinitions.data.length; i++) {
                if (tableDefinitions.data[i].sql) {
                  solved = solved && utils.containsOrEscaped(dataString, tableDefinitions.data[i].sql)
                  if (!solved) {
                    break
                  }
                }
              }
              if (solved) {
                challengeUtils.solve(challenges.dbSchemaChallenge)
              }
            }
          })
        } // vuln-code-snippet hide-end
        for (let i = 0; i < products.length; i++) {
          products[i].name = req.__(products[i].name)
          products[i].description = req.__(products[i].description)
        }
        res.json(utils.queryResultToJson(products))
      }).catch((error: ErrorWithParent) => {
        next(error.parent)
      })
  }
}
// vuln-code-snippet end unionSqlInjectionChallenge dbSchemaChallenge

// SONAR ISSUE 7: Code smell - function too long and complex (exceeds recommended lines/complexity)
function massiveComplexFunction (data: any) {
  let result = 0
  let tempVar1 = ''
  let tempVar2 = 0
  let tempVar3: any[] = []
  
  // First section - validation logic
  if (data && typeof data === 'object') {
    if (data.hasOwnProperty('items') && Array.isArray(data.items)) {
      for (let i = 0; i < data.items.length; i++) {
        if (data.items[i] && data.items[i].value) {
          if (typeof data.items[i].value === 'number') {
            result += data.items[i].value
          } else if (typeof data.items[i].value === 'string') {
            tempVar1 += data.items[i].value
          }
        }
      }
    }
  }
  
  // Second section - processing logic
  if (data.metadata) {
    for (let key in data.metadata) {
      if (data.metadata.hasOwnProperty(key)) {
        if (key.startsWith('temp_')) {
          tempVar2 += 1
        } else if (key.startsWith('data_')) {
          tempVar3.push(data.metadata[key])
        }
      }
    }
  }
  
  // Third section - calculation logic
  let multiplier = 1
  if (tempVar2 > 0) {
    multiplier = tempVar2 * 2
  }
  
  if (tempVar3.length > 0) {
    for (let item of tempVar3) {
      if (item && item.coefficient) {
        multiplier *= item.coefficient
      }
    }
  }
  
  // Fourth section - formatting logic
  let finalResult = result * multiplier
  if (tempVar1.length > 0) {
    finalResult = finalResult + tempVar1.length
  }
  
  // Fifth section - validation and return
  if (finalResult < 0) {
    finalResult = 0
  } else if (finalResult > 1000000) {
    finalResult = 1000000
  }
  
  return {
    result: finalResult,
    metadata: {
      stringLength: tempVar1.length,
      itemCount: tempVar2,
      dataItems: tempVar3.length,
      multiplier: multiplier
    }
  }
}
