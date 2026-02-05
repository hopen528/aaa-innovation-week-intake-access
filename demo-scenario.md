# IP Restriction Demo Scenario

## Demo Setup Requirements

### Test IPs to Use
- **Your IP**: `YOUR_ACTUAL_IP` (allowed - for live demo)
- **Blocked IP 1**: `10.0.0.5` (internal range)
- **Blocked IP 2**: `192.168.1.100` (private range)
- **Allowed IP**: `8.8.8.8` (Google DNS - safe example)

### Test API Keys (Why We Need 2 Keys)
1. **Key A**: `demo-key-normal` - No key-specific policy (affected by org-wide policy)
2. **Key B**: `demo-key-vip` - Will add key-specific ALLOW policy (to show override)

### Dashboard URLs to Monitor
- CEL Policy Dashboard: https://ddstaging.datadoghq.com/dashboard/2rv-wuu-vhj
- Monitor 403s vs 200s in real-time
- Show dry-run metrics separately

---

## Key Setup Explained

**Why 2 Keys?**
- **Key A** represents normal customers - follows org-wide policy
- **Key B** represents VIP customers - can have exceptions via key-specific policy

**Policy Precedence Rule:**
- If a key has a specific policy → Use it (ignore org-wide)
- If a key has NO specific policy → Fall back to org-wide
- This is **override**, not **additive** behavior

## Demo Flow (10 minutes)

### Act 1: Baseline - No Restrictions (2 min)
**Goal**: Show current state - all traffic allowed

1. **Show dashboard** - All requests returning 200
2. **Send test traffic** with Key A from various IPs:
   ```bash
   # All succeed (200)
   curl -H "DD-API-KEY: demo-key-unrestricted" -H "x-client-ip: 10.0.0.5"
   curl -H "DD-API-KEY: demo-key-unrestricted" -H "x-client-ip: 192.168.1.100"
   curl -H "DD-API-KEY: demo-key-unrestricted" -H "x-client-ip: 8.8.8.8"
   ```
3. **Point out problem**: "Any IP can send data - potential security risk"

---

### Act 2: Org-Wide Policy - Dry Run (3 min)
**Goal**: Safely test policy without breaking anything

1. **Create org-wide policy**:
   - Navigate to `/organization-settings/ip-policies`
   - Create policy blocking `10.0.0.0/8`
   - Mode: **dry_run**
   - Test IP feature: Show 10.0.0.5 would be blocked

2. **Wait for propagation** (~5 seconds)
   - Explain FRAMES distribution

3. **Send same traffic** - All still succeed (200)
   ```bash
   curl -H "DD-API-KEY: demo-key-unrestricted" -H "x-client-ip: 10.0.0.5"  # 200 (would block)
   ```

4. **Show dashboard**:
   - All requests still 200 (dry-run doesn't block)
   - New metric: `would_block` counter increasing
   - Show logs with "dry-run: would have blocked"

---

### Act 3: Org-Wide Policy - Enforced (3 min)
**Goal**: Show actual blocking in action

1. **Promote to enforced**:
   - Edit policy, change mode to **enforced**
   - Show audit trail entry

2. **Send test traffic**:
   ```bash
   # Blocked (403)
   curl -H "DD-API-KEY: demo-key-unrestricted" -H "x-client-ip: 10.0.0.5"

   # Allowed (200)
   curl -H "DD-API-KEY: demo-key-unrestricted" -H "x-client-ip: 8.8.8.8"
   ```

3. **Show dashboard**:
   - 403s appearing for blocked IPs
   - 200s for allowed IPs
   - Show latency metrics (< 1μs added)

---

### Act 4: Key-Specific Override (2 min)
**Goal**: Show granular control per API key

1. **Scenario**: "VIP customer needs access from 10.0.0.5"

2. **NO NEED TO RESET ORG POLICY** - Keep org-wide block in place

3. **Add key-specific policy** for Key B:
   - Navigate to API key modal for Key B
   - Add ALLOW policy for `10.0.0.0/8`
   - Mode: **enforced**
   - Explain: "This completely overrides the org-wide policy for this key only"

4. **Test the override**:
   ```bash
   # Key A: Still blocked (403) - org policy applies (no key-specific policy)
   curl -H "DD-API-KEY: demo-key-normal" -H "x-client-ip: 10.0.0.5"

   # Key B: Now allowed (200) - key policy overrides org policy
   curl -H "DD-API-KEY: demo-key-vip" -H "x-client-ip: 10.0.0.5"
   ```

5. **Explain the setup**:
   - **Key A**: Has NO key-specific policy → Falls back to org-wide policy (blocked)
   - **Key B**: Has key-specific ALLOW policy → Overrides org-wide policy (allowed)
   - This shows that key-specific policies completely replace org-wide, not add to them

---

## Demo Script Commands

```bash
# Prep: Set up variables
ORG_ID="test-org-id"
KEY_A="demo-key-normal"    # No key-specific policy
KEY_B="demo-key-vip"       # Will get key-specific allow policy
INTAKE_URL="https://logs.browser-intake-datad0g.com/api/v2/logs"

# Function to test an IP
test_ip() {
  local key=$1
  local ip=$2
  local label=$3
  echo "Testing $label (IP: $ip, Key: $key)"
  curl -X POST $INTAKE_URL \
    -H "DD-API-KEY: $key" \
    -H "x-client-ip: $ip" \
    -H "Content-Type: application/json" \
    -d '[{"message":"Test from IP restriction demo","service":"demo"}]' \
    -w "\nStatus: %{http_code}\n"
}

# Act 1: Baseline
test_ip $KEY_A "10.0.0.5" "Internal IP"
test_ip $KEY_A "8.8.8.8" "External IP"

# Act 2: After dry-run (same commands, different results in logs)

# Act 3: After enforced
test_ip $KEY_A "10.0.0.5" "Internal IP - Should block"
test_ip $KEY_A "8.8.8.8" "External IP - Should allow"

# Act 4: Key-specific override (org policy still blocking)
test_ip $KEY_A "10.0.0.5" "Key A - No key policy, blocked by org"
test_ip $KEY_B "10.0.0.5" "Key B - Has allow policy, overrides org block"
```

---

## Key Talking Points During Demo

1. **Progressive rollout**: "Notice the safe progression: disabled → dry_run → enforced"

2. **No performance impact**: "Still under 200μs budget despite policy evaluation"

3. **Instant propagation**: "FRAMES distributes globally in ~5 seconds"

4. **Fail-open design**: "If anything fails, we allow traffic - availability first"

5. **Future extensibility**: "Same system can handle country, time-based, user-agent restrictions"

---

## Backup Plans

### If policies don't propagate:
- Have pre-created policies ready
- Show the UI and explain the flow
- Use screenshots of working dashboard

### If dashboard doesn't update:
- Show raw logs with policy decisions
- Explain metrics that would appear

### If curl commands fail:
- Have a Python script ready with same logic
- Show the code to explain what's happening

---

## Questions to Anticipate

**Q: "What if I need different policies for logs vs metrics?"**
A: CEL supports product-specific rules: `request.product == "logs" && cidr(...)`

**Q: "Can I allowlist my office IP globally?"**
A: Yes, create an org-wide allow policy - it applies to all keys

**Q: "What happens if CEL expression is invalid?"**
A: API validates at creation time, runtime errors fail-open

**Q: "How do I know what's being blocked?"**
A: Dashboard shows decisions, logs include source IP and reason