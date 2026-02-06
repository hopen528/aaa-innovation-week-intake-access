# 5-Minute IP Restriction Demo

## Pre-Demo Setup (Do Before Demo)
1. Create org-wide policy blocking your phone hotspot IP - in **dry_run** mode
2. Have 2 browser tabs open:
   - IP Policies page: `/organization-settings/ip-policies`
   - Dashboard: https://ddstaging.datadoghq.com/dashboard/2rv-wuu-vhj
3. Have your laptop on office WiFi
4. Have your phone hotspot ready to connect

## Demo Script (5 minutes)

### Minute 1: Show the Problem
- **Say**: "Today, any IP can send data to our intake endpoints - let me show you"
- **Show Dashboard**: Point to all 200s, no 403s
- **Say**: "We've built IP restrictions using CEL that evaluate in 0.3μs"

### Minute 2: Show Existing Dry-Run Policy
- **Navigate** to IP Policies page
- **Show** the pre-created policy blocking your phone IP (dry_run mode)
- **Click** "Test IP" button, enter your phone's IP
- **Say**: "It would block this IP, but in dry-run it only logs"
- **Show Dashboard**: Point to dry_run metrics

### Minute 3: Enforce the Policy
- **Click** Edit → Change to **Enforced** → Save
- **Say**: "Policies propagate globally via FRAMES in ~5 seconds"
- **Switch** your laptop to phone hotspot (takes ~10 seconds)
- **Say**: "Now I'm on the blocked IP range"

### Minute 4: Demonstrate Blocking
- **Run** in terminal:
  ```bash
  curl -X POST https://logs.browser-intake-datad0g.com/api/v2/logs \
    -H "DD-API-KEY: $YOUR_KEY" \
    -H "Content-Type: application/json" \
    -d '[{"message":"This should be blocked"}]'
  ```
- **Show**: 403 Forbidden response
- **Show Dashboard**: New 403s appearing
- **Switch back** to office WiFi
- **Run same curl**: Shows 200 OK

### Minute 5: Key Points & Questions
- **Say**: "Key features:
  - Progressive rollout: dry_run → enforced
  - Sub-microsecond evaluation
  - Extensible to country, time, user-agent via CEL
  - No new infrastructure - reuses FRAMES + intake sidecar"
- **Q&A**: Quick questions

## Backup Plan (If WiFi Switch Fails)

Use the **Test IP** feature in the UI:
1. Enter different IPs in the test modal
2. Show "would block" vs "would allow" results
3. Explain: "In production, Envoy enforces this on real connection IPs"

## One-Liner Talking Points

- "0.3 microsecond evaluation - 600x under our latency budget"
- "Fail-open design - availability over security if something breaks"
- "Same system will handle scoped API keys and country restrictions"
- "Already deployed in staging, ready for production"

## The Hook

Start with: **"What if I told you we could block malicious IPs in 0.3 microseconds without any new infrastructure?"**

End with: **"This is live in staging today - we can protect your intake traffic by end of week."**