const express = require('express')
const request = require('request')
const jsonwebtoken = require('jsonwebtoken')
const base64 = require('base-64')
const router = express.Router()

router.get('/code', (req, res, next) => {
  const params = {}
  params.reqUri = req.session.reqUri
  params.redirectedUri = req.url
  params.redirectedContent = JSON.stringify(req.query, null, 4)
  if (req.query.error) {
    // error
    res.render('code', params)
    return
  }confidential
  const { code } = req.query

  // Request for tokens
  const tokensUri = `${req.session.uri}/api/v1/oidc/tokens`
  const user = req.session.client
  const pass = req.session.secret
  const form = {
    grant_type: 'authorization_code',
    code,
    redirect_uri: req.session.redirectUri
  }
  params.tokenReqUri = tokensUri
  params.tokenReqHeaders = JSON.stringify({
    Authorization: `Basic ${base64.encode(`${user}:${pass}`)}`,
    'Content-Type': 'application/x-www-form-urlencoded'
  }, null, 4)
  params.tokenReqContent = JSON.stringify(form, null, 4)
  request.post(tokensUri, {
    form: form,
    auth: {
      user,
      pass,
      sendImmediately: true
    },
    json: true
  }, (err, resp, body) => {
    if (err) {
      res.render('code', params)
      return
    }
    params.tokenResContent = JSON.stringify(body, null, 4)

    // Get uesr info
    const { access_token, id_token } = body
    const userUri = `${req.session.uri}/api/v1/oidc/userinfo`
    const userHeaders = {
      Authorization: `Bearer ${access_token}`
    }
    params.userUri = userUri
    params.userHeaders = JSON.stringify(userHeaders, null, 4)
    request.get(userUri, {
      headers: userHeaders,
      json: true
    }, (err, resp, body) => {
      if (err) {
        res.render('code', params)
        return
      }
      params.userResContent = JSON.stringify(body, null, 4)

      // Get key
      const keyUri = `${req.session.uri}/api/v1/oidc/key_pem`
      params.keyUri = keyUri
      request.get(keyUri, {}, (err, resp, body) => {
        if (err) {
          res.render('code', params)
          return
        }
        const keyContent = body
        params.keyContent = keyContent
        jsonwebtoken.verify(id_token, keyContent, {
          algorithms: ['RS256']
        }, (err, decoded) => {
          if (err) {
            params.decodedUser = err
            res.render('code', params)
            return
          }
          params.decodedUser = JSON.stringify(decoded, null, 4)

          // Introspect
          const introspectUri = `${req.session.uri}/api/v1/oidc/introspect`
          params.introspectUri = introspectUri
          params.introspectReqHeaders = JSON.stringify({
            Authorization: `Basic ${base64.encode(`${user}:${pass}`)}`,
            'Content-Type': 'application/x-www-form-urlencoded'
          }, null, 4)
          const introspectForm = {
            token: access_token
          }
          params.introspectReqContent = JSON.stringify(introspectForm, null, 4)
          request.post(introspectUri, {
            form: introspectForm,
            auth: {
              user,
              pass,
              sendImmediately: true
            },
            json: true
          }, (err, resp, body) => {
            if (err) {
              res.render('code', params)
              return
            }

            params.introspectResContent = JSON.stringify(body, null, 4)
            res.render('code', params)
          })
        })
      })
    })
  })
})

router.get('/implicit', (req, res, next) => {
  const reqUri = req.session.reqUri
  const params = {
    reqUri,
  }
  res.render('implicit', params)
})

module.exports = router
