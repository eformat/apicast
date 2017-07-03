local oauth = require 'oauth'

describe('OAuth', function()
  describe('.oidc', function()
    it(function() assert.equal(require('oauth.oidc'), oauth.oidc) end)
  end)

  describe('.apicast', function()
    it(function() assert.equal(require('oauth.apicast_oauth'), oauth.apicast) end)
  end)

end)
