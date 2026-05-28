#!/bin/bash
cd /app
python3 server.py &>/dev/null &
exec setarch x86_64 -R /nginx-src/build/nginx -p /app -c /app/nginx.conf
