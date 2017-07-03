insulate('Configuration object', function()

  insulate('.mock', function()
    local configuration = require 'configuration_loader'
    local mock_loader = require 'configuration_loader.mock'

    it('saves mock configuration', function()
      local config = { 'foo' }
      configuration.mock(config)

      assert.equal(config, mock_loader.config)
    end)
  end)

  describe('.init', function()
    local configuration = require 'configuration_loader'

    it('runs boot', function()
      local config, err = configuration.run_external_command('boot', 'apicast')

      assert.falsy(config)
      assert.match('missing configuration', err)
    end)
  end)

  describe('lazy', function()
    local configuration_loader = require 'configuration_loader'

    it('configures proxy on init', function()
      local config = {}
      local lazy = configuration_loader.new('lazy')

      assert.falsy(config.configured)
      lazy.init(config)
      assert.truthy(config.configured)
    end)
  end)


  describe('.configured', function()
    local _M = require('configuration_loader')
    local configuration_store = require('configuration_store')

    it('returns false when not configured', function()
      local configuration = {}
      assert.falsy(_M.configured(configuration))
    end)

    it('returns true when configured', function()
      local config = configuration_store.new()
      config:add({ id = 42, hosts = { 'example.com' } })

      assert.truthy(_M.configured(config, 'example.com'))
    end)

    it('returns false when configuration is stale', function()
      local config = configuration_store.new()
      config:add({ id = 42, hosts = { 'example.com' } }, -1)

      assert.falsy(_M.configured(config, 'example.com'))
    end)
  end)

  describe('.configure', function()
    local _M = require('configuration_loader')
    local configuration_store = require('configuration_store')
    local cjson = require('cjson')

    it('returns true with empty configuration', function()
      local config = configuration_store.new()
      assert.truthy(_M.configure(config, '{}'))
    end)

    it('returns true with blank configuration', function()
      local config = configuration_store.new()
      assert.falsy(_M.configure(config, ''))
    end)

    it('stores the configuration', function()
      local config = configuration_store.new()

      assert.truthy(_M.configure(config, cjson.encode({ services = {
        { id = 42, proxy = { hosts = { 'localhost' } } }
      }})))

      assert.truthy(config:find_by_id('42'))
    end)
  end)

  describe('lazy loader', function()
    local _M = require('configuration_loader')
    local loader

    before_each(function() loader = _M.new('lazy') end)

    it('does not crash on rewrite', function()
      local configuration = {}
      assert.same(configuration, loader.rewrite(configuration, 'example.com'))
    end)
  end)
end)
