--[[
Copyright 2018 JobTeaser

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
--]]

local resty_hmac = require('resty.hmac')
local resty_sha256 = require('resty.sha256')
local str = require('resty.string')

local _M = { _VERSION = '0.2.0' }

local function get_credentials()
  local access_key = os.getenv('AWS_ACCESS_KEY_ID')
  local secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')

  return {
    access_key = access_key,
    secret_key = secret_key
  }
end

local function get_iso8601_basic(timestamp)
  return os.date('!%Y%m%dT%H%M%SZ', timestamp)
end

local function get_iso8601_basic_short(timestamp)
  return os.date('!%Y%m%d', timestamp)
end

local function get_derived_signing_key(secret_key, timestamp, opts)
  local h_date = resty_hmac:new('AWS4' .. secret_key, resty_hmac.ALGOS.SHA256)
  h_date:update(get_iso8601_basic_short(timestamp))
  local k_date = h_date:final()

  local h_region = resty_hmac:new(k_date, resty_hmac.ALGOS.SHA256)
  h_region:update(opts.region)
  local k_region = h_region:final()

  local h_service = resty_hmac:new(k_region, resty_hmac.ALGOS.SHA256)
  h_service:update(opts.service)
  local k_service = h_service:final()

  local h = resty_hmac:new(k_service, resty_hmac.ALGOS.SHA256)
  h:update('aws4_request')
  return h:final()
end

local function get_cred_scope(timestamp, opts)
  return get_iso8601_basic_short(timestamp)
    .. '/' .. opts.region
    .. '/' .. opts.service
    .. '/aws4_request'
end

local function get_signed_headers(opts)
  return 'host;x-amz-content-sha256;x-amz-date'
end

local function get_sha256_digest(s)
  local h = resty_sha256:new()
  h:update(s or '')
  return str.to_hex(h:final())
end

local function get_hashed_canonical_request(timestamp, host, path, query, opts)
  local body = opts.body
  if body == nil then
    body = ngx.var.request_body
  end
  local method = opts.method
  if method == nil then
    method = ngx.var.request_method
  end
  local digest = get_sha256_digest(body)
  local canonical_request = method .. '\n'
    .. path .. '\n'
    .. query .. '\n'
    .. 'host:' .. host .. '\n'
    .. 'x-amz-content-sha256:' .. digest .. '\n'
    .. 'x-amz-date:' .. get_iso8601_basic(timestamp) .. '\n'
    .. '\n'
    .. get_signed_headers(opts) .. '\n'
    .. digest
  return get_sha256_digest(canonical_request)
end

local function get_string_to_sign(timestamp, host, path, query, opts)
  return 'AWS4-HMAC-SHA256\n'
    .. get_iso8601_basic(timestamp) .. '\n'
    .. get_cred_scope(timestamp, opts) .. '\n'
    .. get_hashed_canonical_request(timestamp, host, path, query, opts)
end

local function get_signature(derived_signing_key, string_to_sign, opts)
  local h = resty_hmac:new(derived_signing_key, resty_hmac.ALGOS.SHA256)
  h:update(string_to_sign)
  return h:final(nil, true)
end

local function get_authorization(derived_signing_key, access_key, timestamp, host, path, query, opts)
  local string_to_sign = get_string_to_sign(timestamp, host, path, query, opts)
  local auth = 'AWS4-HMAC-SHA256 '
    .. 'Credential=' .. access_key .. '/' .. get_cred_scope(timestamp, opts)
    .. ', SignedHeaders=' .. get_signed_headers(opts)
    .. ', Signature=' .. get_signature(derived_signing_key, string_to_sign, opts)
  return auth
end

local INST = {}
INST.__index = INST

function _M.new(creds)
  if not creds then
    creds = get_credentials()
  end
  return setmetatable({
    creds = creds,
    key_cache = {},
    key_cache_date = "",
  }, INST)
end

function INST:aws_set_headers(host, path, query, opts)
  local timestamp = tonumber(ngx.time())

  local date = get_iso8601_basic_short(timestamp)
  if self.key_cache_date ~= date then
    self.key_cache = {}
    self.key_cache_date = date
  end

  local key_cache_id = opts.region .. '/' .. opts.service
  local derived_signing_key = self.key_cache[key_cache_id]
  if not derived_signing_key then
    derived_signing_key = get_derived_signing_key(self.creds.secret_key, timestamp, opts)
    self.key_cache[key_cache_id] = derived_signing_key
  end

  local auth = get_authorization(derived_signing_key, self.creds.access_key, timestamp, host, path, query, opts)

  local set_header_func = opts.set_header_func or ngx.req.set_header

  local body = opts.body
  if body == nil then
    body = ngx.var.request_body
  end

  set_header_func('authorization', auth)
  set_header_func('host', host)
  set_header_func('x-amz-date', get_iso8601_basic(timestamp))
  set_header_func('x-amz-content-sha256', get_sha256_digest(body))
end

return _M
