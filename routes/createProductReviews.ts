/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response } from 'express'
import challengeUtils = require('../lib/challengeUtils')
import { reviewsCollection } from '../data/mongodb'

import * as utils from '../lib/utils'
import { challenges } from '../data/datacache'

const security = require('../lib/insecurity')

module.exports = function productReviews () {
  return (req: Request, res: Response, next: (err?: Error) => void) => {
    const user = security.authenticatedUsers.from(req)
    const product = req.params?.id
    const author = req.body?.author
    const message = req.body?.message

    if (typeof product !== 'string' || typeof author !== 'string' || typeof message !== 'string') {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
      return
    }

    challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user && user.data.email !== author && user.data.email !== product })
    reviewsCollection.insert({
      product,
      message,
      author,
      likesCount: 0,
      likedBy: []
    }).then(() => {
      res.status(201).json({ status: 'success' })
    }, (err: unknown) => {
      res.status(500).json(utils.getErrorMessage(err))
    })
  }
}
