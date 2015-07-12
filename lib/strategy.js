'use strict';

/**
 * Module dependencies.
 */
var util = require('util');
var OAuth2Strategy = require('passport-oauth2');
var Profile = require('./profile');
var InternalOAuthError = OAuth2Strategy.InternalOAuthError;

/**
 * Strategy constructor.
 *
 * The eve-oauth authentication strategy authenticates requests by delegating to
 * EVE-Online Single Sign-On (SSO) using the OAuth 2.0 protocol.
 *
 * Applications must supply a 'verify' callback which accepts an 'accessToken',
 * 'refreshToken' and service-specifig 'profile', and then calls the 'done'
 * callback supplying a 'user', which should be set to 'false' if the
 * credentials are not valid. If an exception occurred, 'err' should be set.
 *
 * Options:
 *   - 'clientID'     your EVE SSO application's Client ID
 *   - 'clientSecret' your EVE SSO application's Client Secret
 *   - 'callbackURL'  URL to which EVE SSO will redirect the user after granting
 *                    authorization
 *   - 'scope'        array of permission scopes to request. Valid scopes
 *                    include: 'publicData' (see https://developers.eveonline.com/resource/single-sign-on
 *                    for more info)
 *   - 'userAgent'    All API requests MUST include a valid User Agent string,
 *                    e.g. the domain name of your application.
 *                    (see https://developers.eveonline.com/resource/faq#guidelines
 *                    for more info)
 *
 * Example:
 *
 *   passport.user(new EveStrategy({
 *     	 clientID: '3rdparty_clientid',
 *   	   clientSecret: 'jkfopwkmif90e0womkepowe9irkjo3p9mkfwe',
 *   	   callbackURL: 'https://3rdpartysite.com/callback',
 *     	 userAgent: '3rdparysite.com'
 *     },
 *     function(accessToken, refreshToken, profile, done) {
 *     	 User.findOrCreate(..., function(err, user) {
 *     	 	 done(err, user);
 *     	 });
 *     }
 *   ));
 *
 * @constructor
 * @param {Object}   options options object as described above
 * @param {Function} verify  verify callback as described above
 */
function Strategy(options, verify) {
  options = options || {};

  if (!options.callbackURL) {
    throw new TypeError('eve-oauth strategy requires a callbackURL option');
  }

  options.authorizationURL = options.authorizationURL || 'https://login.eveonline.com/oauth/authorize';
  options.tokenURL = options.tokenURL || 'https://login.eveonline.com/oauth/token';
  options.scopeSeparator = options.scopeSeparator || ',';
  options.customHeaders = options.customHeaders || {};

  if (!options.customHeaders['User-Agent']) {
    options.customHeaders['User-Agent'] = options.userAgent || 'passport-eve-oauth';
  }

  OAuth2Strategy.call(this, options, verify);
  this.name = 'eve';
  this._characterURL = options.characterURL || 'https://login.eveonline.com/oauth/verify';
  this._oauth2.useAuthorizationHeaderforGET(true);
}

/**
 * Inherit from OAuth2Strategy
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve character profile from EVE-Online
 *
 * This function constructs a normalized profile with the following properties:
 *
 *   - 'provider'           always set to 'eve'
 *   - 'id'                 the character ID of the logged in character
 *   - 'name'               the name of the logged in character
 *   - 'expires'            the when the character's subscription expires
 *   - 'scopes'             the scopes the access token grants access to
 *   - 'topenType'          the access token's type
 *   - 'characterOwnerHash' the hash of the owner of the logged-in character
 *
 * For more in-depth information about the character profile, refer to
 * https://developers.eveonline.com/resource/single-sign-on#obtain_the_character_id
 *
 * @param  {String}   accessToken the access-token used to retrieve the character
 *                                profile
 * @param  {Function} done        function that is called when the character
 *                                profile was loaded
 * @return {Object}               the character's profile
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  this._oauth2.get(this._characterURL, accessToken, function (err, body) {
    var json;

    if (err) {
      return done(new InternalOAuthError('Failed to fetch character profile', err));
    }

    try {
      json = JSON.parse(body);
    } catch (ex) {
      return done(new Error('Failed to parse character profile'));
    }

    var profile = Profile.parse(json);
    profile.provider = 'eve';
    profile._raw = body;
    profile._json = json;

    done(null, profile);
  });
};

/**
 * Expose Strategy.
 */
module.exports = Strategy;
