local configuration_store = require 'configuration_store'
local Service = require 'configuration.service'

describe('Proxy', function()
  local configuration, proxy

  before_each(function()
    configuration = configuration_store.new()
    proxy = require('proxy').new(configuration)
  end)

  it('has access function', function()
    assert.truthy(proxy.access)
    assert.same('function', type(proxy.access))
  end)

  describe(':call', function()
    before_each(function()
      ngx.var = { backend_endpoint = 'http://localhost:1853' }
      configuration:add(Service.new({ id = 42, hosts = { 'localhost' }}))
    end)

    it('has authorize function after call', function()
      proxy:call('localhost')

      assert.truthy(proxy.authorize)
      assert.same('function', type(proxy.authorize))
    end)

    it('returns access function', function()
      local access = proxy:call('localhost')

      assert.same('function', type(access))
    end)

    it('returns oauth handler when matches oauth route', function()
      local service = configuration:find_by_id(42)
      service.backend_version = 'oauth'
      stub(ngx.req, 'get_method', function() return 'GET' end)
      ngx.var.uri = '/authorize'

      local access, handler = proxy:call('localhost')

      assert.equal(nil, access)
      assert.same('function', type(handler))
    end)
  end)

  it('has post_action function', function()
    assert.truthy(proxy.post_action)
    assert.same('function', type(proxy.post_action))
  end)

  it('finds service by host', function()
    local example = { id = 42, hosts = { 'example.com'} }

    configuration:add(example)

    assert.same(example, proxy:find_service('example.com'))
    assert.falsy(proxy:find_service('unknown'))
  end)

  it('does not return old configuration when new one is available', function()
    local foo = { id = '42', hosts = { 'foo.example.com'} }
    local bar = { id = '42', hosts = { 'bar.example.com'} }

    configuration:add(foo, -1) -- expired record
    assert.equal(foo, proxy:find_service('foo.example.com'))

    configuration:add(bar, -1) -- expired record
    assert.equal(bar, proxy:find_service('bar.example.com'))
    assert.falsy(proxy:find_service('foo.example.com'))
  end)

  describe('.get_upstream', function()
    local get_upstream = proxy.get_upstream

    it('sets correct upstream port', function()
      assert.same(443, get_upstream({ api_backend = 'https://example.com' }).port)
      assert.same(80, get_upstream({ api_backend = 'http://example.com' }).port)
      assert.same(8080, get_upstream({ api_backend = 'http://example.com:8080' }).port)
    end)
  end)

  describe('.authorize', function()
    local authorize = proxy.authorize
    local service = { backend_authentication = { value = 'not_baz' } }
    local usage = 'foo'
    local credentials = 'client_id=blah'

    it('takes ttl value if sent', function()
      local ttl = 80
      ngx.var = { cached_key = credentials, usage=usage, credentials=credentials, http_x_3scale_debug='baz', real_url='blah' }
      ngx.ctx = { backend_upstream = ''}
      ngx.shared = { api_keys = { cached_key = 'client_id=blah:foo', get = function () return {} end } }

      stub(ngx.shared.api_keys, 'set')
      stub(ngx.location, 'capture', function() return { status = 200 } end)

      authorize(proxy, service, usage, credentials, ttl)
      assert.spy(ngx.shared.api_keys.set).was.called_with(ngx.shared.api_keys, 'client_id=blah:foo', 200, 80)
    end)

    it('works with no ttl', function()
      ngx.var = { cached_key = "client_id=blah", usage=usage, credentials=credentials, http_x_3scale_debug='baz', real_url='blah' }
      ngx.ctx = { backend_upstream = ''}
      ngx.shared = { api_keys = { cached_key = 'client_id=blah:foo', get = function () return {} end } }

      stub(ngx.shared.api_keys, 'set')
      stub(ngx.location, 'capture', function() return { status = 200 } end)

      authorize(proxy, service, usage, credentials)
      assert.spy(ngx.shared.api_keys.set).was.called_with(ngx.shared.api_keys, 'client_id=blah:foo', 200, 0)
    end)
  end)
end)
