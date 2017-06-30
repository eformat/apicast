local setmetatable = setmetatable
local format = string.format
local ipairs = ipairs
local insert = table.insert
local rawset = rawset
local encode_args = ngx.encode_args

local resty_url = require 'resty.url'
local http_ng = require "resty.http_ng"
local user_agent = require 'user_agent'
local cjson = require 'cjson'
local resty_env = require 'resty.env'
local configuration = require 'configuration'
local re = require 'ngx.re'

local _M = {
  _VERSION = '0.1'
}
local mt = {
  __index = _M
}

function _M.new(url, options)
  local endpoint = url or resty_env.get('THREESCALE_PORTAL_ENDPOINT')
  local opts = options or {}

  local http_client = http_ng.new{
    backend = opts.client,
    options = {
      headers = { ['User-Agent'] = user_agent() },
      ssl = { verify = resty_env.enabled('OPENSSL_VERIFY') }
    }
  }

  local path = resty_url.split(endpoint or '')

  return setmetatable({
    endpoint = endpoint,
    path = path and path[6],
    options = opts,
    http_client = http_client
  }, mt)
end

local status_code_errors = setmetatable({
  [403] = 'invalid status: 403 (Forbidden)',
  [404] = 'invalid status: 404 (Not Found)'
}, {
  __index = function(t,k)
    local msg = format('invalid status: %s', k)
    rawset(t,k,msg)
    return msg
  end
})

local status_error_mt = {
  __tostring = function(t)
    return t.error
  end,
  __index = function(t,k)
    return t.response[k] or t.response.request[k]
  end
}

local function status_code_error(response)
  return setmetatable({
    error = status_code_errors[response.status],
    response = response
  }, status_error_mt)
end

function _M:index(host)
  local http_client = self.http_client

  if not http_client then
    return nil, 'not initialized'
  end

  local path = self.path

  if not path then
    return nil, 'wrong endpoint url'
  end

  local env = resty_env.get('THREESCALE_DEPLOYMENT_ENV')

  if not env then
    return nil, 'missing environment'
  end

  local url = resty_url.join(self.endpoint, '/', env, '.json?', encode_args({ host = host }))
  local res, err = http_client.get(url)

  if not res and err then
    ngx.log(ngx.DEBUG, 'index get error: ', err, ' url: ', url)
    return nil, err
  end

  ngx.log(ngx.DEBUG, 'index get status: ', res.status, ' url: ', url)

  if res.status == 200 then
    local json = cjson.decode(res.body)

    local configs = {}

    local proxy_configs = json.proxy_configs or {}

    for i=1, #proxy_configs do
      configs[i] = proxy_configs[i].proxy_config.content
    end

    return cjson.encode({ services = configs })
  else
    return nil, 'invalid status'
  end
end

function _M:call(environment)
  if self == _M  or not self then
    local host = environment
    local m = _M.new()
    local ret, err = m:index(host)

    if not ret then
      return m:call()
    else
      return ret, err
    end
  end

  local http_client = self.http_client

  if not http_client then
    return nil, 'not initialized'
  end

  local env = environment or resty_env.get('THREESCALE_DEPLOYMENT_ENV')
  if not env then
    return nil, 'missing environment'
  end
  local configs = {}

  local res, err = self:services()

  if not res and err then
    ngx.log(ngx.WARN, 'failed to get list of services: ', err, ' url: ', err.url)
    return nil, err
  end

  local config
  for _, object in ipairs(res) do
    config, err = self:config(object.service, env, 'latest')

    if config then
      insert(configs, config)
    else
      ngx.log(ngx.INFO, 'could not get configuration for service ', object.service.id, ': ', err)
    end
  end

  for i, c in ipairs(configs) do
    configs[i] = c.content
  end

  return cjson.encode({ services = configs })
end

local services_subset = function()
  local services = resty_env.get('APICAST_SERVICES')

  if services then
    local ids = re.split(services, ',', 'oj')
    for i=1, #ids do
      ids[i] = { service = { id = ids[i] } }
    end
    services = ids
  end

  return services
end

function _M:services()
  local services = services_subset()
  if services then return services end

  local http_client = self.http_client

  if not http_client then
    return nil, 'not initialized'
  end

  local url = resty_url.join(self.endpoint, '/admin/api/services.json')

  local res, err = http_client.get(url)

  if not res and err then
    ngx.log(ngx.DEBUG, 'services get error: ', err, ' url: ', url)
    return nil, err
  end

  ngx.log(ngx.DEBUG, 'services get status: ', res.status, ' url: ', url)

  if res.status == 200 then
    local json = cjson.decode(res.body)

    return json.services or {}
  else
    return nil, status_code_error(res)
  end
end

function _M:config(service, environment, version)
  local http_client = self.http_client

  if not http_client then return nil, 'not initialized' end

  local id = service and service.id

  if not id then return nil, 'invalid service, missing id' end
  if not environment then return nil, 'missing environment' end
  if not version then return nil, 'missing version' end

  local version_override = resty_env.get(format('APICAST_SERVICE_%s_CONFIGURATION_VERSION', id))

  local url = resty_url.join(
    self.endpoint,
    '/admin/api/services/', id , '/proxy/configs/', environment, '/',
    format('%s.json', version_override or version)
  )

  local res, err = http_client.get(url)

  if not res and err then
    ngx.log(ngx.DEBUG, 'services get error: ', err, ' url: ', url)
    return nil, err
  end

  ngx.log(ngx.DEBUG, 'services get status: ', res.status, ' url: ', url, ' body: ', res.body)

  if res.status == 200 then
    local config = cjson.decode(res.body).proxy_config
    local service = configuration.parse_service(config)

    return config
  else
    return nil, status_code_error(res)
  end
end


return _M
