local configuration_store = require('configuration_store')
local configuration_parser = require 'configuration_parser'
local mock_loader = require 'configuration_loader.mock'
local file_loader = require 'configuration_loader.file'
local remote_loader_v1 = require 'configuration_loader.remote_v1'
local remote_loader_v2 = require 'configuration_loader.remote_v2'
local util = require 'util'
local env = require('resty.env')
local resty_url = require('resty.url')
local synchronization = require('resty.synchronization').new(1)
local keycloak = require 'oauth.keycloak'
local cjson = require 'cjson'

local error = error
local len = string.len
local assert = assert
local pcall = pcall
local tonumber = tonumber

local noop = function(...) return ... end

local _M = {
  _VERSION = '0.1'
}

function _M.load(host)
  local uri = resty_url.parse(env.get('APICAST_CONFIGURATION'))

  if uri then
    local scheme = uri.scheme

    if scheme == 'file' then
      env.set('THREESCALE_CONFIG_FILE', uri.path)
    elseif scheme == 'http' or scheme == 'https' then
      env.set('THREESCALE_PORTAL_ENDPOINT', uri)
    else
      ngx.log(ngx.WARN, 'unknown configuration URI: ', uri)
    end
  end

  return mock_loader.call() or file_loader.call() or remote_loader_v2:call(host) or remote_loader_v1.call(host)
end

function _M.boot(host)
  return _M.load(host) or error('missing configuration')
end

_M.mock = mock_loader.save

local function ttl()
  return tonumber(env.get('APICAST_CONFIGURATION_CACHE'), 10)
end

function _M.global(contents)
  local module = require('module')

  return _M.configure(module.configuration, contents)
end

function _M.configure(configuration, contents)
  if not configuration then
    return nil, 'not initialized'
  end

  local config, err = configuration_parser.parse(contents)

  if err then
    ngx.log(ngx.WARN, 'not configured: ', err)
    ngx.log(ngx.DEBUG, 'config: ', contents)

    return nil, err
  end

  if config then
    return configuration:store(config, ttl())
  end
end

function _M.configured(configuration, host)
  if not configuration or not configuration.find_by_host then return nil, 'not initialized' end

  local hosts = configuration:find_by_host(host, false)

  return #hosts > 0
end

-- Cosocket API is not available in the init_by_lua* context (see more here: https://github.com/openresty/lua-nginx-module#cosockets-not-available-everywhere)
-- For this reason a new process needs to be started to download the configuration through 3scale API
function _M.run_external_command(cmd, cwd)
  cwd = cwd or env.get('TEST_NGINX_APICAST_PATH') or ngx.config.prefix()
  local config, err, code = util.system("cd '" .. cwd .."' && libexec/"..(cmd or "boot"))

  -- Try to read the file in current working directory before changing to the prefix.
  if err then config = file_loader.call() end

  if config and len(config) > 0 then
    return config
  elseif err then
    if code then
      return nil, err, code
    else
      ngx.log(ngx.ERR, 'failed to read output from command ', cmd, ' err: ', err)
      return nil, err
    end
  end
end

local boot = {
  rewrite = noop,
  ttl = function() return tonumber(env.get('APICAST_CONFIGURATION_CACHE'), 10) end
}

function boot.init(configuration)
  local config, err, code = _M.run_external_command()
  local init = _M.configure(configuration, config)

  if config and init then
    ngx.log(ngx.DEBUG, 'downloaded configuration: ', config)
  else
    ngx.log(ngx.EMERG, 'failed to load configuration, exiting (code ', code, ')\n',  err)
    os.exit(1)
  end

  if ttl() == 0 then
    ngx.log(ngx.EMERG, 'cache is off, cannot store configuration, exiting')
    os.exit(0)
  end

  if keycloak.enabled() then
    local keycloak_config
    keycloak_config, err, code = _M.run_external_command("keycloak")
    if keycloak_config then
      ngx.log(ngx.DEBUG, 'downloaded keycloak configuration: ', keycloak_config)
      configuration.keycloak = cjson.decode(keycloak_config)
    else
      -- TODO: consider exiting if there is problem with keycloak configuration
      ngx.log(ngx.WARN, 'failed to load keycloak configuration, exiting (code ', code, ')\n',  err)
    end
  end
end

local function refresh_configuration(configuration)
  local config = _M.load()
  local init, err = _M.configure(configuration, config)

  if init then
    ngx.log(ngx.DEBUG, 'updated configuration via timer: ', config)
  else
    ngx.log(ngx.EMERG, 'failed to update configuration: ', err)
  end
end

function boot.init_worker(configuration)
  local interval = ttl() or 0

  local function schedule(...)
    local ok, err = ngx.timer.at(...)

    if not ok then
      ngx.log(ngx.ERR, "failed to create the auto update timer: ", err)
      return
    end
  end

  local handler

  handler = function (premature, ...)
    if premature then return end

    ngx.log(ngx.INFO, 'auto updating configuration')

    local updated, err = pcall(refresh_configuration, ...)

    if updated then
      ngx.log(ngx.INFO, 'auto updating configuration finished successfuly')
    else
      ngx.log(ngx.ERR, 'auto updating configuration failed with: ', err)
    end

    schedule(interval, handler, ...)
  end

  if interval > 0 then
    schedule(interval, handler, configuration)
  end
end

local lazy = { init_worker = noop }

function lazy.init(configuration)
  local keycloak_config = _M.run_external_command("keycloak")

  if keycloak_config then
    configuration.keycloak = cjson.decode(keycloak_config)
  end

  configuration.configured = true
end

function lazy.rewrite(configuration, host)
  if not host then
    return nil, 'missing host'
  end

  local sema = synchronization:acquire(host)

  if ttl() == 0 then
    configuration = configuration_store.new(configuration.cache_size)
  end

  local ok, err = sema:wait(15)

  if ok and not _M.configured(configuration, host) then
    ngx.log(ngx.INFO, 'lazy loading configuration for: ', host)
    local config = _M.load(host)
    _M.configure(configuration, config)
  end

  configuration.keycloak = keycloak.load_configuration()

  if ok then
    synchronization:release(host)
    sema:post()
  else
    ngx.log(ngx.WARN, 'failed to acquire lock to lazy load: ', host, ' error: ', err)
  end

  return configuration
end

local modes = {
  boot = boot, lazy = lazy, default = 'lazy'
}

function _M.new(mode)
  mode = mode or env.get('APICAST_CONFIGURATION_LOADER') or modes.default
  local loader = modes[mode]
  ngx.log(ngx.INFO, 'using ', mode, ' configuration loader')
  return assert(loader, 'invalid config loader mode')
end

return _M
