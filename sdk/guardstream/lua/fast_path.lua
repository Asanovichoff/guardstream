-- GuardStream fast path: blocklist check + sliding window rate limit
-- KEYS[1]: blocklist key        (gs:blocked:<ip>)
-- KEYS[2]: window key           (gs:window:<ip>:<endpoint>)
-- KEYS[3]: reason key           (gs:blocked:<ip>:reason)
-- ARGV[1]: now_ms               (current time in milliseconds)
-- ARGV[2]: window_ms            (window size in milliseconds)
-- ARGV[3]: limit                (max requests per window)
-- Returns: {status, message}
--   {0, reason}  = blocked (blocklist or rate limit exceeded)
--   {1, "ok"}    = allowed

-- 1. Blocklist check first (O(1), cheaper than ZSET operations)
local blocked = redis.call('EXISTS', KEYS[1])
if blocked == 1 then
    local reason = redis.call('GET', KEYS[3])
    return {0, reason or 'Your IP has been blocked due to suspicious activity.'}
end

-- 2. Sliding window check
local now    = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local cutoff = now - window

redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', cutoff)
local count = redis.call('ZCARD', KEYS[2])

if count >= limit then
    return {0, 'rate_limited'}
end

-- 3. Record this request using a sequence counter for guaranteed uniqueness
local seq = redis.call('INCR', 'gs:seq')
redis.call('ZADD', KEYS[2], now, now .. '-' .. seq)
redis.call('PEXPIRE', KEYS[2], window)

return {1, 'ok'}
