var passport = require('passport-strategy');
var url = require('url');
var uid = require('uid2');
var util = require('util');
var OAuth = require('oauth').OAuth2;

/*
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;
*/
/**
 * `Strategy` constructor.
 *
 * The BOX authentication strategy authenticates requests by delegating to
 * BOX using the OAuth 2.0 protocol.
 *
 * Applications must supply a `verify` callback which accepts an `accessToken`,
 * `refreshToken` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `clientId`      	your Box application's client id
 *   - `clientSecret`  	your Box application's client secret
 *   - `callbackURL`   	URL to which Box will redirect the user after granting authorization (optional of set in your Box Application
 *   - `grant_type`		Must be authorization_code
 *
 * Examples:
 *
 *     passport.use(new BoxStrategy({
 *         client_id: '123-456-789',
 *         client_secret: 'shhh-its-a-secret'
 *         redirect_uri: 'https://www.example.net/auth/box/callback'
 *       },
 *       function(accessToken, refreshToken, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function BoxStrategy(options, verify) {
  if (typeof optios == 'function') {
    verify = options;
    options = undefined;
  }
  options = options || {};

  if (!verify) {
    throw new TypeError('BoxStrategy requires a verify callback');
  }
  if (!options.authorizationURL) {
    throw new TypeError('BoxStrategy requires a authorizationURL option');
  }
  if (!options.tokenURL) {
    throw new TypeError('BoxStratery requires tokenURL options');
  }
  if (!options.clientID) {
    throw new TypeError('BoxStrategy requires a clientID option');
  }
  if (!options.clientSecret) {
    throw new TypeError('BoxStrategy requires a clientSecret option');
  }

  passport.Strategy.call(this);
  this.name = 'boxoauth2';
  this._verify = verify;

  // http://developers.box.com/oauth/
  /* options.authorizationURL = options.authorizationURL || 'https://api.box.com/oauth2/authorize';
   options.tokenURL = options.tokenURL || 'https://api.box.com/oauth2/token';
   options.grant_type = options.grant_type || 'authorization_code';*/

  this._oauth2 = new OAuth2(options.clientID, options.clientSecret, '', options.authorizationURL, options.tokenURL, options.customHeaders);

  this._callbackURL = options.callbackURL;
  this._scope = options.scope;
  this._scopeSeperator = options.scopeSeperator || ' ';
  this._state = options.state;
  this._key = options.sessionKey || ('oauth2:' + url.parse(options.authorizationURL).hostname);
  this._trustProxy = options.proxy;
  this._passReqToCallback = options.passReqToCallback;
  this._skipUserProfile = (options.skipUserProfile === undefined) ? false : options.skipUserProfile;

  util.inherits(BoxStratery, passport.Strategy);

  /**
   * Retrieve user profile from box.
   *
   * This function constructs a normalized profile, with the following properties:
   *
   *   - `provider`         always set to `box`
   *   - `id`
   *   - `username`
   *   - `displayName`
   *
   * @param {String} accessToken
   * @param {Function} done
   * @api protected
   */

  BoxStrategy.prototype.authenticate = function(req, options) {
    options = options || {};
    var self = this;

    if (req.query && req.query.error) {
      if (req.query.error == 'access_denied') {
        return this.fail({
          message: req.query.error_description
        });
      } else {
        return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
      }
    }

    var callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      var parsed = url.parse(callbackURL);
      if (!parsed.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackURL = url.resolve(utils.originalURL(req, {
          proxy: this._trustProxy
        }), callbackURL);
      }
    }

    if (req.query && req.query.code) {
      var code = req.query.code;

      if (this._state) {
        if (!req.session) {
          return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
        }

        var key = this._key;
        if (!req.session[key]) {
          return this.fail({
            message: 'Unable to verify authorization request state.'
          }, 403);
        }
        var state = req.session[key].state;
        if (!state) {
          return this.fail({
            message: 'Unable to verify authorization request state.'
          }, 403);
        }

        delete req.session[key].state;
        if (Object.keys(req.session[key]).length === 0) {
          delete req.session[key];
        }

        if (state !== req.query.state) {
          return this.fail({
            message: 'Invalid authorization request state.'
          }, 403);
        }
      }

      var params = this.tokenParams(options);
      params.grant_type = 'authorization_code';
      params.redirect_uri = callbackURL;

      this._oauth2.getOAuthAccessToken(code, params,
        function(err, accessToken, refreshToken, params) {
          if (err) {
            return self.error(self._createOAuthError('Failed to obtain access token', err));
          }

          self._loadUserProfile(accessToken, function(err, profile) {
            if (err) {
              return self.error(err);
            }

            function verified(err, user, info) {
              if (err) {
                return self.error(err);
              }
              if (!user) {
                return self.fail(info);
              }
              self.success(user, info);
            }

            try {
              if (self._passReqToCallback) {
                var arity = self._verify.length;
                if (arity == 6) {
                  self._verify(req, accessToken, refreshToken, params, profile, verified);
                } else { // arity == 5
                  self._verify(req, accessToken, refreshToken, profile, verified);
                }
              } else {
                var arity = self._verify.length;
                if (arity == 5) {
                  self._verify(accessToken, refreshToken, params, profile, verified);
                } else { // arity == 4
                  self._verify(accessToken, refreshToken, profile, verified);
                }
              }
            } catch (ex) {
              return self.error(ex);
            }
          });
        }
      );
    } else {
      var params = this.authorizationParams(options);
      params.response_type = 'code';
      params.redirect_uri = callbackURL;
      var scope = options.scope || this._scope;
      if (scope) {
        if (Array.isArray(scope)) {
          scope = scope.join(this._scopeSeparator);
        }
        params.scope = scope;
      }
      var state = options.state;
      if (state) {
        params.state = state;
      } else if (this._state) {
        if (!req.session) {
          return this.error(new Error('OAuth2Strategy requires session support when using state. Did you forget app.use(express.session(...))?'));
        }

        var key = this._key;
        state = uid(24);
        if (!req.session[key]) {
          req.session[key] = {};
        }
        req.session[key].state = state;
        params.state = state;
      }

      var location = this._oauth2.getAuthorizeUrl(params);
      this.redirect(location);
    }
  };

  BoxStratery.prototype.userProfile = function(accessToken, done) {
    this._oauth2.get('https://api.box.com/2.0/users/me', accessToken, function(err, body, res) {
      if (err) {
        return done(new InternalOAuthError('failed to fetch user profile', err));
      }

      try {
        var json = JSON.parse(body);

        var profile = {
          provider: 'box'
        };
        profile.id = json.id;
        profile.name = json.name;
        profile.login = json.login;
        profile._raw = body;
        profile._json = json;

        done(null, profile);
      } catch (e) {
        done(e);
      }
    });
  }


  /**
   * Expose `Strategy`.
   */
  module.exports = Strategy;