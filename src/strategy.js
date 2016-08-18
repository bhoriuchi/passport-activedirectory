import util from 'util'
import passport from 'passport'
import ActiveDirectory from 'activedirectory'

/*
 * modified version of passport-windowsauth (https://github.com/auth0/passport-windowsauth)
 * using activedirectory (https://github.com/gheeres/node-activedirectory)
 *
 * Additional features are that the ad connection is passed to the verify function so that
 * the user can take advantage of the query functions provided by activedirectory
 * when using ldap authentication
 *
 * Signature: verify ( [req], profile, [adClient], done)
 *
 */

const DEFAULT_USERNAME_FIELD = 'username'
const DEFAULT_PASSWORD_FIELD = 'password'
const DEFAULT_ATTRS = [
  'dn',
  'displayName',
  'givenName',
  'sn',
  'title',
  'userPrincipalName',
  'sAMAccountName',
  'mail',
  'description'
]

const DEFAULT_FILTER = (username) => {
  return `(&(objectclass=user)(|(sAMAccountName=${username})(UserPrincipalName=${username})))`
}

function getUserNameFromHeader (req) {
  if (!req.headers['x-iisnode-logon_user']) return null;
  return req.headers['x-iisnode-logon_user'].split('\\')[1];
}

function Strategy (options, verify) {
  if (typeof options === 'function') {
    verify = options
    options = {}
  }
  if (!verify) throw new Error('windows authentication strategy requires a verify function')

  passport.Strategy.call(this)

  this.name = 'ActiveDirectory'
  this._verify = verify

  this._options = options
  this._passReqToCallback = options.passReqToCallback
  this._integrated = options.integrated === false ? options.integrated : true
  this._getUserNameFromHeader = options.getUserNameFromHeader || getUserNameFromHeader

  if (!this._integrated) {
    this._usernameField = options.usernameField || DEFAULT_USERNAME_FIELD;
    this._passwordField = options.passwordField || DEFAULT_PASSWORD_FIELD;
  }

  this._ad = (typeof options.ldap === 'function') ? options.ldap : new ActiveDirectory(options.ldap)
}

util.inherits(Strategy, passport.Strategy)

Strategy.prototype.mapProfile = function (i) {
  if (!i) return i

  // allow custom profile mapper
  if (typeof this._options.mapProfile === 'function') {
    let userProfile = this._options.mapProfile(i)
    userProfile._json = i
    return userProfile
  }

  // default profile mapper
  return {
    id: i.objectGUID || i.uid,
    displayName: i.displayName,
    name: {
      familyName: i.sn || i.surName,
      givenName: i.gn || i.givenName
    },
    emails: (i.mail ? [{value: i.mail}] : undefined),
    _json: i
  }
}

Strategy.prototype.authenticate = function (req, options = {}) {
  let [ username, password ] = [ null, null ]

  // get username and password
  if (this._integrated) {
    username = this._getUserNameFromHeader(req)
    if (!username) {
      return this.fail()
    }
  } else {
    username = req.body[this._usernameField] || req.query[this._usernameField]
    password = req.body[this._passwordField] || req.query[this._passwordField]
  }

  // helper functions
  let verified = (err, user, info) => {
    if (err) { return this.error(err) }
    if (!user) { return this.fail(info) }
    this.success(user, info)
  }

  let verify = (userProfile) => {
    if (this._passReqToCallback) {
      if (this._ad) return this._verify(req, userProfile, this._ad, verified)
      else return this._verify(req, userProfile, verified)
    } else {
      if (this._ad) return this._verify(userProfile, this._ad, verified)
      else return this._verify(userProfile, verified)
    }
  }

  let auth = (userProfile) => {
    return this._ad.authenticate(userProfile._json.dn, password, (err, auth) => {
      if (err) return this.error(err)
      if (!auth) return this.fail(`Authentication failed for ${username}`)
      return verify(userProfile)
    })
  }

  // look for the user if using ldap auth
  if (this._ad) {
    let ldap = this._options.ldap
    let filter = (typeof ldap.filter === 'function') ? ldap.filter(username) : DEFAULT_FILTER(username)
    let attributes = ldap.attributes || DEFAULT_ATTRS
    attributes = Array.isArray(attributes) ? attributes : [attributes]

    // require the dn attribute which will be used during authentication
    if (attributes.indexOf('dn') === -1) attributes.push('dn')

    return this._ad.find({ filter, attributes }, (err, results) => {
      if (err) return this.error(err)
      if (!results || !results.users || !Array.isArray(results.users) || !results.users.length) {
        return this.fail(`The user "${username}" was not found`)
      }
      let userProfile = this.mapProfile(results.users[0])
      return this._integrated ? verify(userProfile) : auth(userProfile)
    })
  }

  // non-ldap auth
  return verify({ name: username, id: username })
}

export default Strategy
