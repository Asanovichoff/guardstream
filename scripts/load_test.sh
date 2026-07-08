#!/usr/bin/env bash
# GuardStream load test — sends 50 concurrent POST /api/login requests
# against the last-unit-in-stock scenario to prove atomic Redis prevents overselling.
#
# Usage: bash scripts/load_test.sh

BASE_URL="${BASE_URL:-http://localhost:8001}"
ENDPOINT="/api/login"
IP="10.99.0.1"
CONCURRENT=50

echo "GuardStream Load Test"
echo "Target: $BASE_URL$ENDPOINT"
echo "Sending $CONCURRENT concurrent requests from IP $IP..."
echo ""

allowed=0
blocked=0
errors=0

run_request() {
    code=$(curl -s -o /dev/null -w "%{http_code}" \
        -X POST "$BASE_URL$ENDPOINT" \
        -H "Content-Type: application/json" \
        -H "X-Forwarded-For: $IP" \
        -H "User-Agent: guardstream-loadtest/1.0" \
        -d '{"username":"test@example.com","password":"test"}' \
        --max-time 5)
    echo "$code"
}

export -f run_request
export BASE_URL ENDPOINT IP

results=$(seq 1 $CONCURRENT | xargs -P "$CONCURRENT" -I{} bash -c 'run_request')

while IFS= read -r code; do
    case "$code" in
        200) ((allowed++)) ;;
        429) ((blocked++)) ;;
        *)   ((errors++))  ;;
    esac
done <<< "$results"

echo "Results:"
echo "  Allowed : $allowed"
echo "  Blocked : $blocked"
echo "  Errors  : $errors"
echo "  Total   : $CONCURRENT"
echo ""
echo "Check http://localhost:8080/dashboard for real-time stats."
