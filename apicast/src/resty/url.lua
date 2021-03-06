local tostring = tostring
local re_match = ngx.re.match
local concat = table.concat

local _M = {
  _VERSION = '0.1'
}

function _M.default_port(scheme)
  if scheme == 'http' then
    return 80
  elseif scheme == 'https' then
    return 443
  end
end

function _M.split(url, protocol)
  if not url then
    return nil, 'missing endpoint'
  end

  if not protocol then
    protocol = 'https?'
  end

  local m = re_match(url, "^(" .. protocol .. "):\\/\\/(?:(.+)@)?([^\\/\\s]+?)(?::(\\d+))?(\\/.*)?$", 'oj')

  if not m then
    return nil, 'invalid endpoint' -- TODO: maybe improve the error message?
  end

  local scheme, userinfo, host, port, path = m[1], m[2], m[3], m[4], m[5]
  local user, pass

  if path == '/' then path = nil end

  if userinfo then
    local m2 = re_match(tostring(userinfo), "^([^:\\s]+)?(?::(.*))?$", 'oj') or {}
    user, pass = m2[1], m2[2]
  end

  return { scheme, user or false, pass or false, host, port or false, path or nil }
end

function _M.join(...)
  return concat({ ... }, '')
end


return _M
