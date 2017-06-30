pcall(require, 'luarocks.loader')
package.path = package.path .. ";./src/?.lua"


local oidc = require 'oauth.oidc'
local cjson = require 'cjson'

local loader = oidc.loader()
local config = loader:call(arg)

ngx.say(cjson.encode(config))
