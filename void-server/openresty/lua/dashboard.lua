local _M = {}
local http = require "resty.http"
local cjson = require "cjson"

-- WMO weather code → description + emoji
local weather_desc = {
    [0]  = "Clear sky",
    [1]  = "Mainly clear",
    [2]  = "Partly cloudy",
    [3]  = "Overcast",
    [45] = "Fog",
    [48] = "Depositing rime fog",
    [51] = "Light drizzle",
    [53] = "Drizzle",
    [55] = "Dense drizzle",
    [61] = "Light rain",
    [63] = "Rain",
    [65] = "Heavy rain",
    [71] = "Light snow",
    [73] = "Snow",
    [75] = "Heavy snow",
    [80] = "Rain showers",
    [81] = "Showers",
    [82] = "Violent showers",
    [95] = "Thunderstorm",
    [96] = "Thunderstorm + hail",
    [99] = "Thunderstorm + heavy hail",
}

local compass = {"N","NNE","NE","ENE","E","ESE","SE","SSE","S","SSW","SW","WSW","W","WNW","NW","NNW"}

local function read_proc_file(path)
    local f = io.open(path, "r")
    if not f then return nil end
    local content = f:read("*a")
    f:close()
    return content
end

local function get_uptime()
    local data = read_proc_file("/proc/uptime")
    if not data then return "unknown" end
    local seconds = data:match("^(%d+)")
    if not seconds then return "unknown" end
    seconds = tonumber(seconds)
    local d = math.floor(seconds / 86400)
    local h = math.floor((seconds % 86400) / 3600)
    local m = math.floor((seconds % 3600) / 60)
    if d > 0 then return string.format("%dd %dh %dm", d, h, m) end
    if h > 0 then return string.format("%dh %dm", h, m) end
    return string.format("%dm", m)
end

local function get_loadavg()
    local data = read_proc_file("/proc/loadavg")
    if not data then return "unknown" end
    return data:match("^(%S+ %S+ %S+)")
end

local function get_meminfo()
    local data = read_proc_file("/proc/meminfo")
    if not data then return "unknown", "unknown" end
    local total = tonumber(data:match("MemTotal:%s+(%d+)"))
    local avail = tonumber(data:match("MemAvailable:%s+(%d+)"))
    if not total or not avail then return "unknown", "unknown" end
    return string.format("%.1f GB", total / 1024 / 1024),
           string.format("%.1f GB", avail / 1024 / 1024)
end

local function fetch_weather(lat, lon)
    if not lat or not lon or lat == "" or lon == "" then
        return nil
    end

    local httpc = http.new()
    httpc:set_timeouts(3000, 3000, 3000)

    local ok, res = pcall(function()
        return httpc:request_uri("https://api.open-meteo.com/v1/forecast", {
            method = "GET",
            query = {
                latitude = lat,
                longitude = lon,
                current = "temperature_2m,relative_humidity_2m,apparent_temperature,weather_code,wind_speed_10m,wind_direction_10m",
                temperature_unit = "fahrenheit",
                wind_speed_unit = "mph",
                timezone = "auto",
            },
        })
    end)

    if not ok or not res or res.status ~= 200 then
        return nil
    end

    local body = cjson.decode(res.body)
    if not body or not body.current then
        return nil
    end

    local c = body.current
    local code = c.weather_code or 0
    return {
        temp        = c.temperature_2m,
        feels       = c.apparent_temperature,
        humidity    = c.relative_humidity_2m,
        wind_speed  = c.wind_speed_10m,
        wind_dir    = c.wind_direction_10m,
        desc        = weather_desc[code] or ("Code " .. tostring(code)),
        time        = c.time,
        tz          = body.timezone or "",
    }
end

function _M.render()
    -- Visitor info
    local ip        = ngx.var.remote_addr
    local country   = ngx.var.geoip2_country_name or "Unknown"
    local city      = ngx.var.geoip2_city or "Unknown"
    local lat       = ngx.var.geoip2_latitude
    local lon       = ngx.var.geoip2_longitude

    -- Fallback: use your own location if visitor geo is missing
    if not lat or lat == "" then
        lat = "39.7817"
        lon = "-89.6501"
    end

    -- Connection info
    local protocol   = ngx.var.server_protocol or "HTTP/1.1"
    local ssl_proto  = ngx.var.ssl_protocol or "N/A"
    local ssl_cipher = ngx.var.ssl_cipher or "N/A"

    -- System info
    local uptime    = get_uptime()
    local loadavg   = get_loadavg()
    local mem_total, mem_avail = get_meminfo()

    -- Weather
    local weather = fetch_weather(lat, lon)

    -- Build weather card
    local weather_html
    if weather then
        local idx = math.floor(((weather.wind_dir or 0) + 22.5) / 45) % 16
        local wind_compass = compass[idx] or "N"

        weather_html = string.format([[
        <div class="card">
            <div class="card-title">Weather — %s, %s</div>
            <div class="weather-main">
                <span class="temp">%d°F</span>
                <span class="desc">%s</span>
            </div>
            <div class="weather-grid">
                <span>Feels like %d°F</span>
                <span>Humidity %d%%</span>
                <span>Wind %d mph %s</span>
                <span>%s (%s)</span>
            </div>
        </div>
        ]], city, country,
           weather.temp, weather.desc,
           weather.feels, weather.humidity,
           weather.wind_speed, wind_compass,
           weather.time, weather.tz)
    else
        weather_html = [[
        <div class="card">
            <div class="card-title">Weather</div>
            <div class="muted">Unavailable</div>
        </div>
        ]]
    end

    -- Full page
    local html = string.format([[
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>gloat.ing — Status</title>
<link rel="stylesheet" href="/css/dashboard.css">
</head>
<body>
<h1>gloat.ing <span>// status</span></h1>
<div class="grid">
    <div class="card">
        <div class="card-title">You</div>
        <div class="row"><span class="label">IP</span><span class="value">%s</span></div>
        <div class="row"><span class="label">Location</span><span class="value">%s, %s</span></div>
        <div class="row"><span class="label">Protocol</span><span class="value">%s</span></div>
        <div class="row"><span class="label">TLS</span><span class="value">%s / %s</span></div>
    </div>
    %s
    <div class="card">
        <div class="card-title">Server</div>
        <div class="row"><span class="label">Uptime</span><span class="value">%s</span></div>
        <div class="row"><span class="label">Load</span><span class="value">%s</span></div>
        <div class="row"><span class="label">Memory</span><span class="value">%s / %s free</span></div>
        <div class="row"><span class="label">OpenResty</span><span class="value">nginx %s</span></div>
    </div>
</div>
<footer>stub_status: <a href="/status">/status</a></footer>
</body>
</html>
]],
    ip, city, country,
    protocol, ssl_proto, ssl_cipher,
    weather_html,
    uptime, loadavg, mem_total, mem_avail,
    ngx.config.nginx_version
)

    return html
end

return _M