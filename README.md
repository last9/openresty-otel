# openresty-otel

OpenTelemetry SDK for OpenResty (nginx + LuaJIT). Traces, metrics, and logs via OTLP — no compilation required.

**Runtime**: LuaJIT (Lua 5.1). All code avoids Lua 5.2+ syntax (`&`, `//`, `goto`, etc.).

## Features

- **Traces** — W3C `traceparent` + `tracestate` propagation; one CLIENT child span per upstream attempt (retries/failover visible as separate spans)
- **Metrics** — `lua-resty-prometheus` counters, histograms, and gauges; nginx `stub_status` via OTel Collector
- **Logs** — JSON-structured access log + regex-parsed error log consumed by OTel Collector `filelog` receiver
- **Sampling** — `OTEL_TRACES_SAMPLER`: `always_on`, `always_off`, `traceid_ratio`, `parentbased_always_on` (default), `parentbased_traceid_ratio`
- **OTel HTTP semconv v1.23+** — `http.request.method`, `url.path`, `server.address`, `client.address`, etc.
- **Error classification** — `exception` span events for 4xx and 5xx; `error.type`: `GatewayTimeout`, `BadGateway`, `ServiceUnavailable`, `InternalServerError`, `ClientError`
- **Cache observability** — `http.cache_status` (HIT/MISS/BYPASS/EXPIRED) on upstream spans
- **Attribute limits** — `OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT` truncation (default 256)

## Installation

### Via Dockerfile (recommended)

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends git \
 && rm -rf /var/lib/apt/lists/* \
 && git clone --depth 1 https://github.com/last9/openresty-otel.git /tmp/openresty-otel \
 && cp /tmp/openresty-otel/lua/*.lua /usr/local/openresty/site/lualib/ \
 && rm -rf /tmp/openresty-otel
```

Also install the Prometheus and HTTP dependencies from OPM:

```dockerfile
RUN opm get knyar/nginx-lua-prometheus ledgetech/lua-resty-http
```

### Via OPM (once `last9` account is registered on opm.openresty.org)

```bash
opm get last9/openresty-otel
```

### Manual

Copy `lua/otel_tracer.lua` and `lua/metrics_init.lua` into your OpenResty `lualib` path:

```bash
git clone --depth 1 https://github.com/last9/openresty-otel.git
cp openresty-otel/lua/*.lua /usr/local/openresty/site/lualib/
```

## Quick Start

**1. `nginx.conf` — add to the `http {}` block:**

```nginx
lua_shared_dict prometheus_metrics 10m;
lua_package_path "/usr/local/openresty/site/lualib/?.lua;;";

# Docker DNS resolver — replace with your resolver outside Docker
resolver 127.0.0.11 valid=30s ipv6=off;

init_worker_by_lua_block {
    require("metrics_init").init()
}
```

**2. `conf.d/default.conf` — add to each proxied `server {}` block:**

```nginx
access_by_lua_block {
    require("otel_tracer").start_span()
}

log_by_lua_block {
    require("otel_tracer").finish_span()
    require("metrics_init").record()
}
```

**3. Environment variables:**

```bash
OTEL_SERVICE_NAME=my-service
OTEL_EXPORTER_OTLP_ENDPOINT=http://otel-collector:4318
OTEL_TRACES_SAMPLER=parentbased_always_on
# OTEL_TRACES_SAMPLER_ARG=0.1   # ratio for traceid_ratio samplers
# OTEL_ATTRIBUTE_VALUE_LENGTH_LIMIT=256
```

## Sampling

| `OTEL_TRACES_SAMPLER` | Behaviour |
|---|---|
| `parentbased_always_on` | Follow parent's sampled flag; new roots always sample **(default)** |
| `parentbased_traceid_ratio` | Follow parent; new roots use `OTEL_TRACES_SAMPLER_ARG` ratio |
| `always_on` | Sample everything |
| `always_off` | Drop everything |
| `traceid_ratio` | Probabilistic — ignores parent flag |

Context is always propagated upstream even for unsampled traces so downstream services can make their own decisions.

## Span model

Each proxied request produces:

```
SERVER span  GET /api/users
  └── CLIENT span  GET /api/users (upstream)        ← single upstream
  └── CLIENT span  GET /api/users (upstream 1/2)    ← on retry: attempt 1
  └── CLIENT span  GET /api/users (upstream 2/2)    ← on retry: attempt 2
```

CLIENT spans include: `server.address`, `server.port`, `http.response.status_code`, `upstream.connect_time_ms`, `http.cache_status`, `http.request.resend_count`, `error.type`.

## Error events

Both 4xx and 5xx produce an `exception` span event:

```
SpanEvent: exception
  exception.type:               ClientError | InternalServerError | BadGateway | ...
  exception.message:            "client error: HTTP 404"
  http.response.status_code:    404
```

5xx sets span status to `ERROR`; 4xx leaves it `UNSET` (client fault, per OTel server semconv).

## Example

See [`example/`](example/) for a complete Docker Compose setup with OTel Collector, Prometheus scraping, and log pipelines.

```bash
cd example
cp .env.example .env
# edit .env with your LAST9_OTLP_ENDPOINT and LAST9_OTLP_AUTH
docker compose up -d
curl http://localhost/get
```

## Compatibility

| Component | Version |
|---|---|
| OpenResty | >= 1.21.4 |
| LuaJIT | 2.1 (Lua 5.1) |
| OTel Collector | >= 0.100.0 |
| OTel semconv | 1.23+ (HTTP) |

**Lua version**: Written for **Lua 5.1 / LuaJIT**. Uses `bit.band()` for bitwise ops — not the `&` operator (Lua 5.3+).

## License

Apache 2.0
