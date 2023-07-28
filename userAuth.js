'use strict'

const passport = require('passport')
const session = require('express-session')
const crypto = require('crypto')
const touchstoneSamlStrategy = require('passport-saml').Strategy

const log = require('./logger')
const {stringTemplate: template, formatUrl} = require('./utils')

const router = require('express-promise-router')()
const domains = new Set(process.env.APPROVED_DOMAINS.split(/,\s?/g))

const callbackURL = process.env.REDIRECT_URL || formatUrl('/auth/redirect')

passport.use(new touchstoneSamlStrategy({
  callbackUrl: callbackURL,
  entryPoint: process.env.TOUCHSTONE_SAML_ENTRYPOINT_URL,
  issuer: process.env.TOUCHSTONE_SAML_CERT_ISSUER,
  cert: process.env.TOUCHSTONE_SAML_CERTIFICATE,
  privateKey: process.env.TOUCHSTONE_SAML_PRIVATE_KEY,
  decryptionPvk: process.env.TOUCHSTONE_SAML_DECRYPTION_PRIVATE_KEY,
  wantAssertionsSigned: true,
  metadataOrganization: {
    OrganizationName: {'#text': process.env.TOUCHSTONE_SAML_ORG_NAME},
    OrganizationDisplayName: {'#text': process.env.TOUCHSTONE_SAML_ORG_DISPLAY_NAME},
    OrganizationURL: {'#text': process.env.TOUCHSTONE_SAML_ORG_URL}
  },
  metadataContactPerson: [{
    '@contactType': 'support',
    GivenName: process.env.TOUCHSTONE_SAML_CONTACT_NAME,
    EmailAddress: process.env.TOUCHSTONE_SAML_CONTACT_EMAIL
  }]},
  (profile, done) => done(null, profile)))

const md5 = (data) => crypto.createHash('md5').update(data).digest('hex')

router.use(session({
  secret: process.env.SESSION_SECRET,
  resave: true,
  saveUninitialized: true
}))

router.use(passport.initialize())
router.use(passport.session())

// seralize/deseralization methods for extracting user information from the
// session cookie and adding it to the req.passport object
passport.serializeUser((user, done) => done(null, user))
passport.deserializeUser((obj, done) => done(null, obj))

router.get('/login', passport.authenticate('saml', {}))

router.get('/logout', (req, res) => {
  req.logout()
  res.redirect('/')
})

router.get('/auth/redirect', passport.authenticate('saml', {failureRedirect: formatUrl('/login')}), (req, res) => {
  res.redirect(req.session.authRedirect || formatUrl('/'))
})

router.get('/metadata', function (req, res) {
  res.type('application/xml')
  res.send((touchstoneSamlStrategy.generateServiceProviderMetadata(
    process.env.TOUCHSTONE_SAML_SP_ENCRYPTION_CERT,
    process.env.TOUCHSTONE_SAML_MD_SIGNING_CERT
  )))
})

router.use((req, res, next) => {
  const isDev = process.env.NODE_ENV === 'development'
  const passportUser = (req.session.passport || {}).user || {}
  if (isDev || (req.isAuthenticated() && isAuthorized(passportUser))) {
    setUserInfo(req)
    return next()
  }

  if (req.isAuthenticated() && !isAuthorized(passportUser)) {
    return next(Error('Unauthorized'))
  }

  log.info('User not authenticated')
  req.session.authRedirect = formatUrl(req.path)
  res.redirect(formatUrl('/login'))
})

function isAuthorized(user) {
  const [{value: userEmail = ''} = {}] = user.emails || []
  const [userDomain] = userEmail.split('@').slice(-1)
  const checkRegexEmail = () => {
    const domainsArray = Array.from(domains)
    for (const domain of domainsArray) {
      if (userDomain.match(domain)) return true
    }
  }
  return domains.has(userDomain) || domains.has(userEmail) || checkRegexEmail()
}

function setUserInfo(req) {
  if (process.env.NODE_ENV === 'development') {
    req.userInfo = {
      email: process.env.TEST_EMAIL || template('footer.defaultEmail'),
      userId: '10',
      analyticsUserId: md5('10library')
    }
    return
  }

  req.userInfo = req.userInfo ? req.userInfo : {
    userId: req.session.passport.user.id,
    analyticsUserId: md5(req.session.passport.user.id + 'library'),
    email: req.session.passport.user.email
  }
}

module.exports = router
