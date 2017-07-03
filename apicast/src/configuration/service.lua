-----------------
--- Service configuration object.
-- @classmod Service

local setmetatable = setmetatable
local tostring = tostring
local rawget = rawget
local lower = string.lower
local gsub = string.gsub
local select = select

local http_authorization = require 'resty.http_authorization'

local oauth = require('oauth')

local _M = { }
local mt = { __index = _M  }

function _M.new(attributes)
  return setmetatable(attributes or {}, mt)
end

local http_methods_with_body = {
  POST = true,
  PUT = true,
  PATCH = true
}

local function read_body_args(...)
  local method = ngx.req.get_method()

  if not http_methods_with_body[method] then
    return {}, 'not supported'
  end

  ngx.req.read_body()

  local args = ngx.req.get_post_args()
  local results = {}

  for n=1, select('#', ...) do
    results[n] = args[select(n, ...)]
  end

  return results
end

local function read_http_header(name)
  local normalized = gsub(lower(name), '-', '_')
  return ngx.var['http_' .. normalized]
end

local backend_version_credentials = { }

function backend_version_credentials.version_1(config)
  local name = (config.user_key or 'user_key')
  local user_key

  if config.location == 'query' then
    user_key = ngx.var['arg_' .. name] or read_body_args(name)[1]

  elseif config.location == 'headers' then
    user_key = read_http_header(name)

  elseif config.location == 'authorization' then
    local auth = http_authorization.new(ngx.var.http_authorization)

    user_key = auth.userid or auth.password or auth.token
  else
    return nil, 'invalid credentials location'
  end
  ------
  -- user_key credentials.
  -- @field 1 User Key
  -- @field user_key User Key
  -- @table credentials_v1
  return { user_key, user_key = user_key }
end

function backend_version_credentials.version_2(config)
  local app_id_name = (config.app_id or 'app_id')
  local app_key_name = (config.app_key or 'app_key')

  local app_id, app_key

  if config.location == 'query' then
    app_id = ngx.var['arg_' .. app_id_name]
    app_key = ngx.var['arg_' .. app_key_name]

    if not app_id or not app_key then
      local body = read_body_args(app_id_name, app_key_name)

      app_id = app_id or body[1]
      app_key = app_key or body[2]
    end
  elseif config.location == 'headers' then
    app_id = read_http_header(app_id_name)
    app_key = read_http_header(app_key_name)

  elseif config.location == 'authorization' then
    local auth = http_authorization.new(ngx.var.http_authorization)

    app_id = auth.userid or auth.token
    app_key = auth.password
  else
    return nil, 'invalid credentials location'
  end

  ------
  -- app\_id/app\_key credentials.
  -- @field 1 app id or app key
  -- @field[opt] 2
  -- @field app_id App ID
  -- @field app_key App Key
  -- @table credentials_v2
  return { app_id, app_key, app_id = app_id, app_key = app_key }
end

function backend_version_credentials.version_oauth(config)
  local name = (config.access_token or 'access_token')
  local authorization = http_authorization.new(ngx.var.http_authorization)
  local access_token

  if config.location == 'query' then
    access_token = ngx.var['arg_' .. name] or read_body_args(name)[1]

  elseif config.location == 'headers' then
    access_token = read_http_header(name)

  elseif config.location == 'authorization' then
    access_token = authorization.token

  else
    return nil, 'invalid credentials location'
  end

  -- https://tools.ietf.org/html/rfc6750#section-2.1 says:
  -- Resource servers MUST support this method. [Bearer]
  access_token = access_token or authorization.token

  ------
  -- oauth credentials.
  -- @field 1 Access Token
  -- @field access_token Access Token
  -- @table credentials_oauth
  return { access_token, access_token = access_token }
end

-- This table can be used with `table.concat` to serialize
-- just the numeric keys, but also with `pairs` to iterate
-- over just the non numeric keys (for query building).

--- extracts credentials from the current request
-- @return @{credentials_v1}, @{credentials_v2}, or @{credentials_oauth}
-- @return[opt] error message why credentials could not be extracted
function _M:extract_credentials()
  local backend_version = tostring(self.backend_version)
  local credentials = rawget(self, 'credentials')

  if not credentials then
    return nil, 'missing credentials'
  end

  local extractor = backend_version_credentials['version_' .. backend_version]

  if not extractor then
   return nil, 'invalid backend version: ' .. backend_version
  end

  return extractor(credentials)
end

function _M:oauth()
  if self.backend_version ~= 'oauth' then
    return nil, 'not oauth'
  end

  local oidc = self.oidc

  if oidc and oidc.issuer_endpoint then
    return oauth.oidc.new(self)
  else
    return oauth.apicast.new(self)
  end
end

return _M
