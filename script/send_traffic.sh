#!/bin/bash

DD_API_KEY="${DD_API_KEY:?Please set DD_API_KEY environment variable}"
URL="https://logs.browser-intake-datad0g.com/api/v2/logs"
DURATION=600  # 10 minutes in seconds
END_TIME=$((SECONDS + DURATION))
COUNT=0

echo "Sending 10 req/sec for 10 minutes..."
echo "Start: $(date)"

while [ $SECONDS -lt $END_TIME ]; do
  for i in $(seq 1 10); do
    COUNT=$((COUNT + 1))
    curl -s -o /dev/null -w "%{http_code}" -XPOST "$URL" \
      -H "content-type: application/json" \
      -H "dd-api-key: $DD_API_KEY" \
      -d "{\"message\":\"req $COUNT at $(date -u +%H:%M:%S) source load-test\"}" &
  done
  wait
  sleep 1
done

echo ""
echo "Done. Sent $COUNT requests."
echo "End: $(date)"
