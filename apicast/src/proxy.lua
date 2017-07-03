------------
-- Proxy
-- Module that handles the request authentication and proxying upstream.
--
-- @module proxy
-- @author mikz
-- @license Apache License Version 2.0

local env = require 'resty.env'
local custom_config = env.get('APICAST_CUSTOM_CONFIG')
local configuration_store = require 'configuration_store'

local oauth = require 'oauth'
local resty_url = require 'resty.url'

local assert = assert
local type = type
local next = next
local insert = table.insert

local concat = table.concat
local gsub = string.gsub
local tonumber = tonumber
local setmetatable = setmetatable
local exit = ngx.exit
local encode_args = ngx.encode_args
local resty_resolver = require 'resty.resolver'
local empty = {}

local response_codes = env.enabled('APICAST_RESPONSE_CODES')

local _M = { }

local mt = {
  __index = _M
}

function _M.new(configuration)
  return setmetatable({
    configuration = assert(configuration, 'missing proxy configuration')
  }, mt)
end

-- Error Codes
local function error_no_credentials(service)
  ngx.log(ngx.INFO, 'no credentials provided for service ', service.id)
  ngx.var.cached_key = nil
  ngx.status = service.auth_missing_status
  ngx.header.content_type = service.auth_missing_headers
  ngx.print(service.error_auth_missing)
  ngx.exit(ngx.HTTP_OK)
end

local function error_authorization_failed(service)
  ngx.log(ngx.INFO, 'authorization failed for service ', service.id)
  ngx.var.cached_key = nil
  ngx.status = service.auth_failed_status
  ngx.header.content_type = service.auth_failed_headers
  ngx.print(service.error_auth_failed)
  ngx.exit(ngx.HTTP_OK)
end

local function error_no_match(service)
  ngx.header.x_3scale_matched_rules = ''
  ngx.log(ngx.INFO, 'no rules matched for service ', service.id)
  ngx.var.cached_key = nil
  ngx.status = service.no_match_status
  ngx.header.content_type = service.no_match_headers
  ngx.print(service.error_no_match)
  ngx.exit(ngx.HTTP_OK)
end

local function error_service_not_found(host)
  ngx.status = 404
  ngx.print('')
  ngx.log(ngx.WARN, 'could not find service for host: ', host)
  ngx.exit(ngx.status)
end
-- End Error Codes

local function get_debug_value(service)
  return ngx.var.http_x_3scale_debug == service.backend_authentication.value
end

local function find_service_strict(self, host)
  local found
  local services = self.configuration:find_by_host(host)

  for s=1, #services do
    local service = services[s]
    local hosts = service.hosts or {}

    for h=1, #hosts do
      if hosts[h] == host and service == self.configuration:find_by_id(service.id) then
        found = service
        break
      end
    end
    if found then break end
  end

  return found or ngx.log(ngx.WARN, 'service not found for host ', host)
end

local function find_service_cascade(self, host)
  local found
  local request = ngx.var.request
  local services = self.configuration:find_by_host(host)

  for s=1, #services do
    local service = services[s]
    local hosts = service.hosts or {}

    for h=1, #hosts do
      if hosts[h] == host then
        local name = service.system_name or service.id
        ngx.log(ngx.DEBUG, 'service ', name, ' matched host ', hosts[h])
        local usage, matched_patterns = service:extract_usage(request)

        if next(usage) and matched_patterns ~= '' then
          ngx.log(ngx.DEBUG, 'service ', name, ' matched patterns ', matched_patterns)
          found = service
          break
        end
      end
    end
    if found then break end
  end

  return found or find_service_strict(self, host)
end

if configuration_store.path_routing then
  ngx.log(ngx.WARN, 'apicast experimental path routing enabled')
  _M.find_service = find_service_cascade
else
  _M.find_service = find_service_strict
end

local http = {
  get = function(url)
    ngx.log(ngx.INFO, '[http] requesting ', url)
    local backend_upstream = ngx.ctx.backend_upstream
    local previous_real_url = ngx.var.real_url
    ngx.log(ngx.DEBUG, '[ctx] copying backend_upstream of size: ', #backend_upstream)
    local res = ngx.location.capture(assert(url), { share_all_vars = true, ctx = { backend_upstream = backend_upstream } })

    local real_url = ngx.var.real_url

    if real_url ~= previous_real_url then
      ngx.log(ngx.INFO, '[http] ', real_url, ' (',res.status, ')')
    else
      ngx.log(ngx.INFO, '[http] status: ', res.status)
    end

    ngx.var.real_url = ''

    return res
  end
}

local function output_debug_headers(service, usage, credentials)
  ngx.log(ngx.INFO, 'usage: ', usage, ' credentials: ', credentials)

  if get_debug_value(service) then
    ngx.header["X-3scale-matched-rules"] = ngx.ctx.matched_patterns
    ngx.header["X-3scale-credentials"]   = credentials
    ngx.header["X-3scale-usage"]         = usage
    ngx.header["X-3scale-hostname"]      = ngx.var.hostname
  end
end

function _M:authorize(service, usage, credentials, ttl)
  if usage == '' then
    return error_no_match(service)
  end

  output_debug_headers(service, usage, credentials)

  local internal_location = (self.oauth and '/threescale_oauth_authrep') or '/threescale_authrep'

  -- usage and credentials are expected by the internal endpoints
  ngx.var.usage = usage
  ngx.var.credentials = credentials
  -- NYI: return to lower frame
  local cached_key = ngx.var.cached_key .. ":" .. usage
  local api_keys = ngx.shared.api_keys
  local is_known = api_keys and api_keys:get(cached_key)

  if is_known == 200 then
    ngx.log(ngx.DEBUG, 'apicast cache hit key: ', cached_key)
    ngx.var.cached_key = cached_key
  else
    ngx.log(ngx.INFO, 'apicast cache miss key: ', cached_key)
    local res = http.get(internal_location)

    ngx.log(ngx.DEBUG, '[backend] response status: ', res.status, ' body: ', res.body)

    if res.status == 200 then
      if api_keys then
        ngx.log(ngx.INFO, 'apicast cache write key: ', cached_key, ', ttl: ', ttl )
        api_keys:set(cached_key, 200, ttl or 0)
      end
    else -- TODO: proper error handling
      if api_keys then api_keys:delete(cached_key) end
      error_authorization_failed(service)
    end
    -- set cached_key to nil to avoid doing the authrep in post_action
    ngx.var.cached_key = nil
  end
end

function _M:set_service(host)
  host = host or ngx.var.host
  local service = self:find_service(host)

  if not service then
    error_service_not_found(host)
  end

  ngx.ctx.service = service
  ngx.var.service_id = service.id
  return service
end

function _M.get_upstream(service)
  service = service or ngx.ctx.service

  local url = resty_url.split(service.api_backend) or empty
  local scheme = url[1] or 'http'
  local host, port, path =
    url[4], url[5] or resty_url.default_port(url[1]), url[6] or ''

  return {
    server = host,
    host = service.hostname_rewrite or host,
    uri  = scheme .. '://upstream' .. path,
    port = tonumber(port)
  }
end

function _M.set_upstream(service)
  local upstream = _M.get_upstream(service)

  ngx.ctx.upstream = resty_resolver:instance():get_servers(upstream.server, { port = upstream.port })

  ngx.var.proxy_pass = upstream.uri
  ngx.req.set_header('Host', upstream.host or ngx.var.host)
end

function _M:set_backend_upstream(service)
  service = service or ngx.ctx.service

  local backend_authentication = service.backend_authentication or {}
  local backend = service.backend or {}

  ngx.var.backend_authentication_type = backend_authentication.type
  ngx.var.backend_authentication_value = backend_authentication.value
  ngx.var.version = self.configuration.version

  -- set backend
  local url = resty_url.split(backend.endpoint or ngx.var.backend_endpoint)
  local scheme, _, _, server, port, path =
    url[1], url[2], url[3], url[4], url[5] or resty_url.default_port(url[1]), url[6] or ''

  local backend_upstream = resty_resolver:instance():get_servers(server, { port = port or nil })
  ngx.log(ngx.DEBUG, '[resolver] resolved backend upstream: ', backend_upstream)
  ngx.ctx.backend_upstream = backend_upstream

  ngx.var.backend_endpoint = scheme .. '://backend_upstream' .. path
  ngx.var.backend_host = backend.host or server or ngx.var.backend_host
end

-----
-- call the proxy and return a handler function
-- that will perform an action based on the path and backend version
-- @string host optional hostname, uses `ngx.var.host` otherwise
-- @treturn nil|function access function (when the request needs to be authenticated with this)
-- @treturn nil|function handler function (when the request is not authenticated and has some own action)
function _M:call(host)
  host = host or ngx.var.host
  local service = ngx.ctx.service or self:set_service(host)

  self:set_backend_upstream(service)

  if service then
    self.oauth = service:oauth()

    -- means that OAuth integration has own router
    if self.oauth and self.oauth.call then
      local f, params = self.oauth:call(service)

      if f then
        ngx.log(ngx.DEBUG, 'apicast oauth flow')
        return nil, function() return f(params) end
      end
    end
  end

  return function()
    -- call access phase
    return self:access(service)
  end
end

function _M:access(service)
  local request = ngx.var.request -- NYI: return to lower frame

  ngx.var.secret_token = service.secret_token

  local credentials, err = service:extract_credentials()

  if not credentials or #credentials == 0 then
    if err then
      ngx.log(ngx.WARN, "cannot get credentials: ", err)
    end
    return error_no_credentials(service)
  end

  insert(credentials, 1, service.id)

  local _, matched_patterns, usage_params = service:extract_usage(request)

  ngx.var.cached_key = concat(credentials, ':')

  -- remove integer keys for serialization
  -- as ngx.encode_args can't serialize integer keys
  for i=1,#credentials do
    credentials[i] = nil
  end

  local ctx = ngx.ctx

  -- save those tables in context so they can be used in the backend client
  ctx.usage = usage_params
  ctx.credentials = credentials
  ctx.matched_patterns = matched_patterns

  local ttl


  credentials = encode_args(credentials)
  local usage = encode_args(usage_params)

  return self:authorize(service, usage, credentials, ttl)
end


local function response_codes_encoded_data()
  local params = {}

  if not response_codes then
    return ''
  end

  if response_codes then
    params["log[code]"] = ngx.var.status
  end

  return ngx.escape_uri(ngx.encode_args(params))
end

function _M:post_action()

  local cached_key = ngx.var.cached_key

  if cached_key and cached_key ~= "null" then
    ngx.log(ngx.INFO, '[async] reporting to backend asynchronously, cached_key: ', cached_key)

    local service_id = ngx.var.service_id
    local service = ngx.ctx.service or self.configuration:find_by_id(service_id)
    self:set_backend_upstream(service)

    local auth_uri = service.backend_version == 'oauth' and 'threescale_oauth_authrep' or 'threescale_authrep'
    local res = http.get("/".. auth_uri .."?log=" .. response_codes_encoded_data())

    if res.status ~= 200 then
      local api_keys = ngx.shared.api_keys

      if api_keys then
        ngx.log(ngx.NOTICE, 'apicast cache delete key: ', cached_key, ' cause status ', res.status)
        api_keys:delete(cached_key)
      else
        ngx.log(ngx.ALERT, 'apicast cache error missing shared memory zone api_keys')
      end
    end
  else
    ngx.log(ngx.INFO, '[async] skipping after action, no cached key')
  end

  exit(ngx.HTTP_OK)
end

if custom_config then
  local path = package.path
  local module = gsub(custom_config, '%.lua$', '') -- strip .lua from end of the file
  package.path = package.path .. ';' .. ngx.config.prefix() .. '?.lua;'
  local ok, c = pcall(function() return require(module) end)
  package.path = path

  if ok then
    if type(c) == 'table' and type(c.setup) == 'function' then
      ngx.log(ngx.DEBUG, 'executing custom config ', custom_config)
      c.setup(_M)
    else
      ngx.log(ngx.ERR, 'failed to load custom config ', custom_config, ' because it does not return table with function setup')
    end
  else
    ngx.log(ngx.ERR, 'failed to load custom config ', custom_config, ' with ', c)
  end
end

return _M
