'use strict';

/**
 * Parses an eve-character profile.
 *
 * @private
 * @param  {Object|String} json object or JSON-string containing the character's
 *                              profile information
 * @return {Object}             the normalized character profile
 */
exports.parse = function(json) {
  if (typeof json === 'string') {
    json = JSON.parse(json);
  }

  var profile = {
    provider: 'eve',
    id: String(json.CharacterID),
    name: json.CharacterName,
    expires: json.ExpiresOn,
    scopes: json.Scopes,
    tokenType: json.TokenType,
    characterOwnerHash: json.CharacterOwnerHash
  };

  return profile;
};
