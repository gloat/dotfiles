local _M = {}
local resty_string = require "resty.string"

local SECRET = "<redacted:cookie-secret>"
local PASSPHRASE = "<redacted:passphrase>"
local COOKIE_NAME = "void_auth"
local COOKIE_MAX_AGE = 30 * 24 * 3600
local HINT_NAME = "void_in"   -- readable hint (no HttpOnly): the page checks it to skip the login card

local function token()
   return ngx.md5(SECRET .. "void_access")
end

local function get_cookie(name)
    local cookie_header = ngx.var.http_cookie
    if not cookie_header then
        return nil
    end
    for k, v in string.gmatch(cookie_header, "([%w_]+)=([^;]+)") do
        if k == name then
            return v
        end
    end
    return nil
end

function _M.check()
    local cookie = get_cookie(COOKIE_NAME)
    if cookie and cookie == token() then
        return true
    end
    return false
end

function _M.set_cookie()
    ngx.header["Set-Cookie"] = {
        string.format("%s=%s; Domain=gloat.ing; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=Strict",
            COOKIE_NAME, token(), COOKIE_MAX_AGE),
        string.format("%s=1; Path=/; Max-Age=%d; Secure; SameSite=Strict", HINT_NAME, COOKIE_MAX_AGE),
    }
end

function _M.clear_cookies()
    ngx.header["Set-Cookie"] = {
        COOKIE_NAME .. "=; Domain=gloat.ing; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",
        COOKIE_NAME .. "=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict",   -- old host-only copies
        HINT_NAME .. "=; Path=/; Max-Age=0; Secure; SameSite=Strict",
    }
end

function _M.validate(pass)
    return pass == PASSPHRASE
end

return _M