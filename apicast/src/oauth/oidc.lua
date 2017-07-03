local resty_env = require 'resty.env'
local http_ng = require 'resty.http_ng'
local http_cache = require 'resty.http_ng.backend.cache'
local resty_backend = require 'resty.http_ng.backend.resty'
local jwt = require 'resty.jwt'
local cjson = require 'cjson'

local insert = table.insert
local setmetatable = setmetatable
local len = string.len

local _M = {

}

local mt = {
  __index = _M
}

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

function loader:issuer_configuration(endpoint)
  local http_client = self.http_client

  if not http_client then
    return nil, 'not initialized'
  end


end

function loader:call(endpoints)
  local issuers = {}

  for i=1, #endpoints do
    local issuer, configuration = self:issuer_configuration(endpoints[i])
    issuers[endpoints[i]] = issuer
    issuers[issuer] = configuration
  end

  return issuers
end

function _M.init(endpoints)
  if not endpoints then
    return nil
  end
end

function _M.parse(config)
  return cjson.decode(config)
end

function _M.new(service)
  return setmetatable({
    service = service,
    config = service.oidc.config,
    issuer = service.oidc.issuer,
  }, mt)
end


local function timestamp_to_seconds_from_now(expiry)
  local time_now = ngx.now()
  local ttl = expiry and (expiry - time_now) or nil
  return ttl
end

-- Formats the realm public key string into Public Key File (PKCS#8) format
local function format_public_key(key)
  local formatted_key = "-----BEGIN PUBLIC KEY-----\n"
  local key_len = len(key)
  for i=1,key_len,64 do
    formatted_key = formatted_key..string.sub(key, i, i+63).."\n"
  end
  formatted_key = formatted_key.."-----END PUBLIC KEY-----"
  return formatted_key
end


-- Parses the token - in this case we assume it's a JWT token
-- Here we can extract authenticated user's claims or other information returned in the access_token
-- or id_token by RH SSO
local function parse_and_verify_token(self, jwt_token)
  -- TODO: this should be able to use DER format instead of PEM
  local jwt_obj = jwt:verify(format_public_key(self.config.public_key), jwt_token)

  if not jwt_obj.valid then
    return jwt_obj, 'JWT not valid'
  end

  if jwt_obj.payload.iss ~= self.issuer then
    ngx.log(ngx.INFO, "[jwt] issuers do not match: ", jwt_obj.payload.iss, ' ~= ', self.issuer)
    return jwt_obj, 'JWT Issuer mismatch'
  end

  if not jwt_obj.verified then
    ngx.log(ngx.INFO, "[jwt] failed verification for token, reason: ", jwt_obj.reason)
    return jwt_obj, "JWT not verified"
  end

  return jwt_obj
end


function _M:transform_credentials(credentials)
  local jwt_obj, err = parse_and_verify_token(self, credentials.access_token)

  if err then
    return nil, nil, err
  end

  if jwt_obj.payload then
    local app_id = jwt_obj.payload.azp
    local ttl = timestamp_to_seconds_from_now(jwt_obj.payload.exp)

    ------
    -- OAuth2 credentials for OIDC
    -- @field app_id Client id
    -- @table credentials_oauth
    return { app_id = app_id }, ttl
  end
end



return _M
