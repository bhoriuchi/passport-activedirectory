# passport-activedirectory

Active Directory strategy for [`passport.js`](https://github.com/jaredhanson/passport)

---

This Strategy is a *"fork"* of [`passport-windowsauth`](https://github.com/auth0/passport-windowsauth) that uses the [`activedirectory`](https://github.com/gheeres/node-activedirectory) module instead of directly calling [`ldapjs`](https://github.com/mcavage/node-ldapjs).

The module works almost identically except that the `verify` function is passed the `ActiveDirectory` object as a parameter so that you can use the query functions included in [`activedirectory`](https://github.com/gheeres/node-activedirectory) during verification. This is useful when using nested AD groups where you want to identify if a user is a member of a root level group.

### Example

```js
var passport = require('passport')
var ActiveDirectoryStrategy = require('passport-activedirectory')

passport.use(new ActiveDirectoryStrategy({
  ldap: {
    url: 'ldap://my.domain.com',
    baseDN: 'DC=my,DC=domain,DC=com',
    username: 'readuser@my.domain.com',
    password: 'readuserspassword'
  }
}, function (profile, ad, done) {
  ad.isMemberOf(profile._json.dn, 'AccessGroup', function (err, isMember) {
    if (err) return done(err)
    return done(null, profile)
  })
}))
```

### API

#### ActiveDirectoryStrategy ( `options`, `verify` )

* `options` { `Object` } - Options for connecting and verification
  * [`integrated=false`] { `Boolean` } - Use windows integrated login
  * [`passReqToCallback=false`] { `Boolean` } - Pass the request to the callback
  * [`usernameField="username"`] { `String` } - request body field to use for the username
  * [`passwordField="password"`] { `String` } - request body field to use for the password
  * [`mapProfile`] { `Function` } - Custom profile mapping function. Takes user object as only parameter and returns a profile object. `_json` is added to the object with the full object
  * [`ldap`] { `Object` } - LDAP connection object. Extended properties are documented [here](https://github.com/gheeres/node-activedirectory#optional-parameters--extended-functionality)
    * `url` { `String` } - LDAP URL (e.g. `ldap://my.domain.com`)
    * `baseDN` { `String` } - Base LDAP DN to search for users in
    * `username` { `String` } - User name of account with access to search the directory
    * `password` { `String` } - Password for username
    * [`filter`] { `Function` } - Takes `username` as its only parameter and returns an ldap query for that user
    * [`attributes`] { `Array` } - Array of attributes to include in the profile under the `profile._json` key. The `dn` property is always added because it is used to authenticate the user
* `verify` { `Function` } - Verification function. Depending on the options supplied the signature will be one of the following
  * Signatures
    * `verify ( profile, ad, done )` - Using ldap
    * `verify( req, profile, ad, done )` - Using ldap and with the `passReqToCallback` option set to `true`
    * `verify ( profile, done )` - Not using ldap
    * `verify ( req, profile, done )` - Not using ldap and with the `passReqToCallback` option set to `true`
  * Params
    * `profile` { `Object` } - User profile object
    * `req` { `Object` } - request object
    * `ad` { `Object` } - `ActiveDirectory` instance
    * `done` { `Function` } - Passport callback
