local resty_env = require 'resty.env'
local http_ng = require 'resty.http_ng'
local http_cache = require 'resty.http_ng.backend.cache'
local resty_backend = require 'resty.http_ng.backend.resty'
local resty_url = require 'resty.url'
local cjson = require 'cjson'

local insert = table.insert
local setmetatable = setmetatable

local _M = {

}

inspect = require 'inspect'

local function oidc_endpoint(service)
  if service.backend_version == 'oauth' and service.oidc then
    return service.oidc.issuer_endpoint
  end
end

function _M.enabled(config)
  local cache = {}
  local services = config.services
  local endpoints = {}

  for i=1, #services do
    local endpoint = oidc_endpoint(services[i])
    if endpoint and not cache[endpoint] then
      cache[endpoint] = true
      insert(endpoints, endpoint)
    end
  end

  if #endpoints > 0 then
    return endpoints
  else
    return nil, 'no OIDC services'
  end
end

local loader = {

}

local loader_mt = { __index = loader }

function _M.loader(http_client_backend)
  local http_client = http_ng.new{
    backend = http_cache.new(http_client_backend or resty_backend),
    options = {
      ssl = { verify = resty_env.enabled('OPENSSL_VERIFY') }
    }
  }

  return setmetatable({ http_client = http_client }, loader_mt)
end

local function openid_configuration_url(endpoint)
  return resty_url.join(endpoint, '.well-known/openid-configuration')
end

function loader:issuer_configuration(endpoint)
  local http_client = self.http_client

  if not http_client then
    return nil, 'not initialized'
  end


  local res = http_client.get(openid_configuration_url(endpoint))

  if not res.ok then
    -- TODO: log the response
    return nil, 'could not get OpenID Connect configuration'
  end


  local configuration = cjson.decode(res.body)

  if not configuration then
    return nil, 'invalid JSON'
  end

  res = http_client.get(configuration.issuer)

  if not res.ok then
    -- TODO: log the response
    return nil, 'could not get OpenID Connect Issuer'
  end


  local issuer = cjson.decode(res.body)

  issuer.openid = configuration

  return issuer
end

function loader:call(endpoints)
  local issuers = {}
  for i=1, #endpoints do
    issuers[endpoints[i]] = self:issuer_configuration(endpoints[i])
  end
  return issuers
end

function _M.init(endpoints)
  if not endpoints then
    return nil
  end


end

return _M
