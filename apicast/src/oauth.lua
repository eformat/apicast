local apicast_oauth = require 'oauth.apicast_oauth'
local oidc = require 'oauth.oidc'

local _M = {
  _VERSION = '0.0.2',

  apicast = apicast_oauth,
  oidc = oidc,
}

return _M
