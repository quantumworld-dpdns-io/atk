#!/bin/bash
cd /app
python3 server.py &>/dev/null &
ARCH=$(uname -m)
if command -v setarch &>/dev/null && setarch "$ARCH" -R true 2>/dev/null; then
    exec setarch "$ARCH" -R /nginx-src/build/nginx -p /app -c /app/nginx.conf
else
    exec /nginx-src/build/nginx -p /app -c /app/nginx.conf
fi
