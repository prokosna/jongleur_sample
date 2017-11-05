const express = require('express')
const router = express.Router()
const qs = require('qs')
const request = require('request')
const base64 = require('base-64')

function code (req, res, next) {
  const uri = `${req.body.uri}/authorize`
  const redirectUri = `${req.body.sample}/result/code`
  const params = {
    response_type: 'code',
    client_id: req.body.client,
    redirect_uri: redirectUri,
    scope: 'openid'
  }
  req.session.uri = req.body.uri
  req.session.reqUri = `${uri}?${qs.stringify(params)}`
  req.session.client = req.body.client
  req.session.secret = req.body.secret
  req.session.redirectUri = redirectUri
  res.redirect(302, `${uri}?${qs.stringify(params)}`)
}

function implicit (req, res, next) {
  const uri = `${req.body.uri}/authorize`
  const redirectUri = `${req.body.sample}/result/implicit`
  const params = {
    response_type: 'id_token token',
    client_id: req.body.client,
    redirect_uri: redirectUri,
    scope: 'openid'
  }
  req.session.reqUri = `${uri}?${qs.stringify(params)}`
  req.session.client = req.body.client
  req.session.secret = req.body.secret
  res.redirect(302, `${uri}?${qs.stringify(params)}`)
}

function client (req, res, next) {
  const uri = `${req.body.uri}/api/v1/oidc/tokens`
  const user = req.body.client
  const pass = req.body.secret
  const params = {}
  params.reqUri = uri
  params.reqHeaders = JSON.stringify({
    Authorization: `Basic ${base64.encode(`${user}:${pass}`)}`,
    'Content-Type': 'application/x-www-form-urlencoded'
  }, null, 4)
  const form = {
    grant_type: 'client_credentials'
  }
  params.reqBody = JSON.stringify(form, null, 4)
  request.post(uri, {
    form,
    auth: {
      user,
      pass,
      sendImmediately: true
    },
    json: true
  }, (err, resp, body) => {
    if (err) {
      res.render('client', params)
      return
    }
    params.resBody = JSON.stringify(body, null, 4)
    res.render('client', params)
  })
}

function password (req, res, next) {
  const uri = `${req.body.uri}/api/v1/oidc/tokens`
  const user = req.body.client
  const pass = req.body.secret
  const name = req.body.user
  const password = req.body.password
  const params = {}
  params.reqUri = uri
  params.reqHeaders = JSON.stringify({
    Authorization: `Basic ${base64.encode(`${user}:${pass}`)}`,
    'Content-Type': 'application/x-www-form-urlencoded'
  }, null, 4)

  const form = {
    grant_type: 'password',
    username: name,
    password,
  }
  params.reqBody = JSON.stringify(form, null, 4)
  request.post(uri, {
    form,
    auth: {
      user,
      pass,
      sendImmediately: true
    },
    json: true
  }, (err, resp, body) => {
    if (err) {
      res.render('password', params)
      return
    }
    params.resBody = JSON.stringify(body, null, 4)
    res.render('password', params)
  })
}

router.post('/', (req, res, next) => {
  if (!req.body.uri || !req.body.client || !req.body.sample) {
    throw new Error('No URI')
  }
  switch (req.body.action) {
    case 'code':
      code(req, res, next)
      break
    case 'implicit':
      implicit(req, res, next)
      break
    case 'client':
      client(req, res, next)
      break
    case 'password':
      password(req, res, next)
      break
    default:
      throw new Error('Invalid action')
  }
})

module.exports = router
