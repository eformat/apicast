local get_token = require 'oauth.apicast_oauth.get_token'
local callback = require 'oauth.apicast_oauth.authorized_callback'
local authorize = require 'oauth.apicast_oauth.authorize'
local router = require 'router'

local setmetatable = setmetatable

local _M = {
  _VERSION = '0.1'
}

local mt = { __index = _M }

function _M.new(service)
  return setmetatable(
    {
      authorize = authorize.call,
      callback = callback.call,
      get_token = get_token.call,
      service = service
    }, mt)
end

function _M.transform_credentials(_, credentials)
  return credentials
end


function _M:router(service)
  local oauth = self
  local r = router:new()

  r:get('/authorize', function() oauth:authorize(service) end)
  r:post('/authorize', function() oauth:authorize(service) end)

  -- TODO: only applies to apicast oauth...
  r:post('/callback', function() oauth:callback() end)
  r:get('/callback', function() oauth:callback() end)

  r:post('/oauth/token', function() oauth:get_token(service) end)

  return r
end

function _M:call(service, method, uri, ...)
  local r = self:router(service)

  local f, params = r:resolve(method or ngx.req.get_method(),
    uri or ngx.var.uri,
    unpack(... or {}))

  return f, params
end


return _M
