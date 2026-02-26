FROM openresty/openresty:1.25.3.1-bullseye-fat

# Install Lua dependencies via OPM
# lua-resty-prometheus: Prometheus metrics from Lua
# lua-resty-http:       HTTP client for async OTLP export (not in base image)
RUN opm get knyar/nginx-lua-prometheus ledgetech/lua-resty-http

# Alternatively, install this package itself once published:
#   RUN opm get last9/openresty-otel

COPY nginx.conf   /usr/local/openresty/nginx/conf/nginx.conf
COPY conf.d/      /etc/nginx/conf.d/
COPY lua/         /usr/local/openresty/site/lualib/

EXPOSE 80 9145

CMD ["/usr/local/openresty/bin/openresty", "-g", "daemon off;"]
