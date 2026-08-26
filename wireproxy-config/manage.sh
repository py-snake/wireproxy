#!/bin/bash
# wireproxy management script
CONFIG_DIR="/home/multibox/wireproxy-config"
BIN="/home/multibox/source/repos/wireproxy/live.bin"

case "$1" in
  start)
    echo "Starting wireproxy with all configs..."
    nohup "$BIN" -c "$CONFIG_DIR"/nl.conf -c "$CONFIG_DIR"/ro.conf -c "$CONFIG_DIR"/warp.conf -i 127.0.0.1:9080 > /tmp/wireproxy.log 2>&1 &
    echo "Started (PID: $!)"
    sleep 2
    ;;
  stop)
    pkill -f "live.bin"
    echo "Stopped"
    ;;
  status)
    curl -s http://127.0.0.1:9080/readyz | jq . 2>/dev/null || curl -s http://127.0.0.1:9080/readyz
    ;;
  test)
    echo "Testing all proxies..."
    for port in 26002 26003 26011; do
      printf "Port %s: " $port
      timeout 10 curl -s -m 8 --socks5-hostname 127.0.0.1:$port "http://ip-api.com/line/?fields=countryCode,query" | tr '\n' ' '
      echo
    done
    ;;
  logs)
    tail -f /tmp/wireproxy.log
    ;;
  *)
    echo "Usage: $0 {start|stop|status|test|logs}"
    exit 1
    ;;
esac
