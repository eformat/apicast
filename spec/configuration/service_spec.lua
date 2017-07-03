local Service = require 'configuration.service'

describe('Service object', function()
  describe(':credentials', function()

    describe('backend_version=1', function()
      it('returns only GET parameters', function()
        local service = Service.new({
          backend_version = 1,
          credentials = { location = 'query' }
        })

        ngx.var = { arg_user_key = 'foobar' }

        assert.same({ 'foobar', user_key = 'foobar' }, assert(service:extract_credentials()))
      end)

      it('returns POST ', function()
        local service = Service.new({
          backend_version = 1,
          credentials = { location = 'query' }
        })

        ngx.var = {}
        stub(ngx.req, 'get_method', function() return 'POST' end)
        stub(ngx.req, 'read_body')
        stub(ngx.req, 'get_post_args', function() return { user_key = 'post' } end)

        assert.same({ 'post', user_key = 'post' }, assert(service:extract_credentials()))
      end)

      it('uses http authorization header', function()
        local service = Service.new({
          backend_version = 1,
          credentials = { location = 'authorization' }
        })

        ngx.var = { http_authorization = 'Bearer token' }

        assert.same({ 'token', user_key = 'token' }, assert(service:extract_credentials()))
      end)


      it('returns Headers ', function()
        local service = Service.new({
          backend_version = 1,
          credentials = { location = 'headers', user_key = 'some-user-key' }
        })

        ngx.var = { http_some_user_key = 'val'  }

        assert.same({ 'val', user_key = 'val' }, assert(service:extract_credentials()))
      end)
    end)

    describe('backend_version=2', function()
      it('returns only GET parameters', function()
        local service = Service.new({
          backend_version = 2,
          credentials = { location = 'query' }
        })

        stub(ngx.req, 'get_method', function() return 'GET' end)
        ngx.var = { arg_app_id = 'foobar' }

        assert.same({ 'foobar', app_id = 'foobar' }, assert(service:extract_credentials()))
      end)

      it('returns POST ', function()
        local service = Service.new({
          backend_version = 2,
          credentials = { location = 'query' }
        })

        ngx.var = {}
        stub(ngx.req, 'get_method', function() return 'POST' end)
        stub(ngx.req, 'read_body')
        stub(ngx.req, 'get_post_args', function() return { app_id = 'post' } end)

        assert.same({ 'post', app_id = 'post' }, assert(service:extract_credentials()))
      end)

      it('uses http authorization header', function()
        local service = Service.new({
          backend_version = 2,
          credentials = { location = 'authorization' }
        })

        ngx.var = { http_authorization = 'Bearer token' }

        assert.same({ 'token', app_id = 'token' }, assert(service:extract_credentials()))
      end)

      it('returns Headers ', function()
        local service = Service.new({
          backend_version = 2,
          credentials = {
            location = 'headers',
            app_id = 'some-app-id',
            app_key = 'some-app-key'
          }
        })

        ngx.var = { http_some_app_id = 'id', http_some_app_key = 'key'  }

        assert.same({ 'id', 'key', app_id = 'id', app_key = 'key' },
          assert(service:extract_credentials()))
      end)
    end)

    describe('backend_version=oauth', function()
      it('returns only GET parameters', function()
        local service = Service.new({
          backend_version = 'oauth',
          credentials = { location = 'query' }
        })

        ngx.var = { arg_access_token = 'foobar' }

        assert.same({ 'foobar', access_token = 'foobar' }, assert(service:extract_credentials()))
      end)

      it('returns POST ', function()
        local service = Service.new({
          backend_version = 'oauth',
          credentials = { location = 'query' }
        })

        ngx.var = {}
        stub(ngx.req, 'get_method', function() return 'POST' end)
        stub(ngx.req, 'read_body')
        stub(ngx.req, 'get_post_args', function() return { access_token = 'post' } end)

        assert.same({ 'post', access_token = 'post' }, assert(service:extract_credentials()))
      end)

      it('uses http authorization header', function()
        local service = Service.new({
          backend_version = 'oauth',
          credentials = { location = 'authorization' }
        })

        ngx.var = { http_authorization = 'Bearer token' }

        assert.same({ 'token', access_token = 'token' }, assert(service:extract_credentials()))
      end)


      it('returns Headers ', function()
        local service = Service.new({
          backend_version = 'oauth',
          credentials = { location = 'headers', access_token = 'some-access-token' }
        })

        ngx.var = { http_some_access_token = 'val'  }

        assert.same({ 'val', access_token = 'val' }, assert(service:extract_credentials()))
      end)
    end)

  end)

  describe(':oauth()', function()
    describe('backend_version=oauth', function()
      it('returns OIDC object when there is OIDC config', function()
        local service = Service.new({backend_version = 'oauth', oidc = { issuer_endpoint = 'http://example.com' }})

        assert.same(require('oauth.oidc'), service:oauth())
      end)

      it('returns APIcast OAuth object when there is no OIDC config', function()
        local service = Service.new({backend_version = 'oauth', oidc = { }})

        assert.same(require('oauth.apicast_oauth'), service:oauth())
      end)

    end)
  end)
end)
