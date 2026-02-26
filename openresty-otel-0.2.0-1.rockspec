package = "openresty-otel"
version = "0.2.0-1"

source = {
  url  = "git+https://github.com/last9/openresty-otel.git",
  tag  = "v0.2.0",
}

description = {
  summary  = "OpenTelemetry SDK for OpenResty: traces, metrics, and logs via OTLP",
  detailed = [[
    Production-ready OpenTelemetry instrumentation for OpenResty (nginx + LuaJIT).

    Features:
    - Distributed tracing via OTLP/HTTP JSON with W3C Trace Context propagation
    - One CLIENT child span per upstream attempt (handles nginx retries/failover)
    - Configurable sampling: always_on, always_off, traceid_ratio, parentbased_*
    - OTel HTTP semantic conventions v1.23+ attribute names
    - Exception events for 4xx and 5xx with error classification
    - Upstream cache status (HIT/MISS/BYPASS), connect time, retry count
    - Prometheus metrics via lua-resty-prometheus
    - W3C tracestate and Baggage passthrough
    - Attribute truncation via OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT
  ]],
  homepage = "https://github.com/last9/openresty-otel",
  license  = "Apache 2.0",
}

-- Targets LuaJIT (Lua 5.1 compatible). Uses bit.band() from LuaJIT's built-in
-- bit library instead of the 5.3 & operator. Not tested on standard Lua 5.2+;
-- the primary runtime is OpenResty/LuaJIT.
dependencies = {
  "lua == 5.1",
  "lua-resty-http >= 0.17",
}

build = {
  type    = "builtin",
  modules = {
    ["otel_tracer"]  = "lua/otel_tracer.lua",
    ["metrics_init"] = "lua/metrics_init.lua",
  },
}
