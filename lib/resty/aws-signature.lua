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

local function get_derived_signing_key(keys, timestamp, region, service, opts)
  local h_date = resty_hmac:new('AWS4' .. keys['secret_key'], resty_hmac.ALGOS.SHA256)
  h_date:update(get_iso8601_basic_short(timestamp))
  local k_date = h_date:final()

  local h_region = resty_hmac:new(k_date, resty_hmac.ALGOS.SHA256)
  h_region:update(region)
  local k_region = h_region:final()

  local h_service = resty_hmac:new(k_region, resty_hmac.ALGOS.SHA256)
  h_service:update(service)
  local k_service = h_service:final()

  local h = resty_hmac:new(k_service, resty_hmac.ALGOS.SHA256)
  h:update('aws4_request')
  return h:final()
end

local function get_cred_scope(timestamp, region, service, opts)
  return get_iso8601_basic_short(timestamp)
    .. '/' .. region
    .. '/' .. service
    .. '/aws4_request'
end

local function get_signed_headers(opts)
  if opts.use_request_body then
    return 'host;x-amz-content-sha256;x-amz-date'
  end
  return 'host;x-amz-date'
end

local function get_sha256_digest(s)
  local h = resty_sha256:new()
  h:update(s or '')
  return str.to_hex(h:final())
end

local function get_hashed_canonical_request(timestamp, host, uri, opts)
  local digest = get_sha256_digest(opts.use_request_body and ngx.var.request_body or '')
  local canonical_request = ngx.var.request_method .. '\n'
    .. uri .. '\n'
    .. '\n'
    .. 'host:' .. host .. '\n'
    .. 'x-amz-content-sha256:' .. digest .. '\n'
    .. 'x-amz-date:' .. get_iso8601_basic(timestamp) .. '\n'
    .. '\n'
    .. get_signed_headers() .. '\n'
    .. digest
  return get_sha256_digest(canonical_request)
end

local function get_string_to_sign(timestamp, region, service, host, uri, opts)
  return 'AWS4-HMAC-SHA256\n'
    .. get_iso8601_basic(timestamp) .. '\n'
    .. get_cred_scope(timestamp, region, service) .. '\n'
    .. get_hashed_canonical_request(timestamp, host, uri)
end

local function get_signature(derived_signing_key, string_to_sign, opts)
  local h = resty_hmac:new(derived_signing_key, resty_hmac.ALGOS.SHA256)
  h:update(string_to_sign)
  return h:final(nil, true)
end

local function get_authorization(keys, timestamp, region, service, host, uri, opts)
  local derived_signing_key = get_derived_signing_key(keys, timestamp, region, service, opts)
  local string_to_sign = get_string_to_sign(timestamp, region, service, host, uri, opts)
  local auth = 'AWS4-HMAC-SHA256 '
    .. 'Credential=' .. keys['access_key'] .. '/' .. get_cred_scope(timestamp, region, service, opts)
    .. ', SignedHeaders=' .. get_signed_headers(opts)
    .. ', Signature=' .. get_signature(derived_signing_key, string_to_sign, opts)
  return auth
end

local function get_service_and_region(host)
  local patterns = {
    {'s3.amazonaws.com', 's3', 'us-east-1'},
    {'s3-external-1.amazonaws.com', 's3', 'us-east-1'},
    {'s3%-([a-z0-9-]+)%.amazonaws%.com', 's3', nil}
  }

  for _,data in ipairs(patterns) do
    local region = host:match(data[1])
    if region ~= nil and data[3] == nil then
      return data[2], region
    elseif region ~= nil then
      return data[2], data[3]
    end
  end

  return nil, nil
end

local INST = {}
INST.__index = INST

function _M.new(creds)
  if not creds then
    creds = get_credentials()
  end
  return setmetatable({
    creds = creds
  }, INST)
end

function INST:aws_set_headers(host, uri, opts)
  local timestamp = tonumber(ngx.time())
  local service, region = get_service_and_region(host)
  local auth = get_authorization(self.creds, timestamp, region, service, host, uri, opts)

  ngx.req.set_header('Authorization', auth)
  ngx.req.set_header('Host', host)
  ngx.req.set_header('x-amz-date', get_iso8601_basic(timestamp))
  ngx.req.set_header('x-amz-content-sha256', get_sha256_digest(ngx.var.request_body))
end

return _M
