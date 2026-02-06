# 5-Minute IP Restriction Demo

## Pre-Demo Setup (Do Before Demo)
1. Set up 2 terminals sending traffic continuously:
   - **Terminal 1**: Your laptop (office WiFi)
   - **Terminal 2**: Cloud VM or colleague's machine (different IP)
2. Have 2 browser tabs open:
   - IP Policies page: `/organization-settings/ip-policies`
   - Dashboard: https://ddstaging.datadoghq.com/dashboard/2rv-wuu-vhj
3. Note the IP of Terminal 2 (the one you'll block)

## Demo Script (5 minutes)

### Minute 1: Show Baseline - Both IPs Accepted
- **Start both traffic generators** (running in background):
  ```bash
  # Terminal 1 (your laptop - will stay allowed)
  while true; do
    curl -X POST https://logs.browser-intake-datad0g.com/api/v2/logs \
      -H "DD-API-KEY: $KEY" -d '[{"message":"laptop traffic"}]'
    sleep 2
  done

  # Terminal 2 (VM/colleague - will be blocked)
  while true; do
    curl -X POST https://logs.browser-intake-datad0g.com/api/v2/logs \
      -H "DD-API-KEY: $KEY" -d '[{"message":"VM traffic"}]'
    sleep 2
  done
  ```
- **Show Dashboard**: All green, 100% success rate from both IPs
- **Say**: "Currently any IP can send data - this is the security gap"

### Minute 2-3: Create and Apply Policy
- **Navigate** to IP Policies page
- **Create policy**:
  - Block Terminal 2's IP (e.g., `34.5.6.0/24`)
  - Start with **dry_run** mode
- **Show Dashboard**: Still all 200s but "would_block" metrics appear
- **Say**: "Dry-run lets us test safely"
- **Switch to Enforced**: Edit → Change mode → Save
- **Say**: "FRAMES propagates this globally in ~5 seconds"

### Minute 4: Watch the Dashboard Change
- **Dashboard shows**:
  - Terminal 1: Still sending successfully (green line continues)
  - Terminal 2: Starts getting 403s (red line appears)
  - Success rate drops from 100% to 50%
- **Say**: "One IP blocked, other continues - surgical precision"
- **Show Terminal 2**: 403 responses appearing
- **Show Terminal 1**: Still getting 200s

### Minute 5: Key Points
- **Say**: "What we just saw:
  - Real-time IP blocking without service restart
  - 0.3μs evaluation - no performance impact
  - Safe rollout with dry-run mode
  - Extensible to country, API key scopes via CEL"
- **Remove policy**: Show immediate return to 100% success

## Visual Impact on Dashboard

What the audience will see:
```
Before Policy:        After Policy (Enforced):
┌──────────────┐     ┌──────────────┐
│ ████████████ │     │ ████████████ │  <- Laptop (allowed)
│ ████████████ │     │ ──────────── │  <- VM (blocked - goes red)
│              │     │              │
│ 100% Success │     │ 50% Success  │
│ 0 Errors     │     │ 50% 403s     │
└──────────────┘     └──────────────┘
```

## Setup Options for 2nd IP

1. **Easiest**: Ask a colleague to run the script from their machine
2. **Cloud**: Spin up a quick EC2/GCP instance (5 min setup)
3. **Phone**: Use phone as hotspot for a second laptop
4. **Local**: Run from a Docker container with different network

## One-Liner Impact Statements

- "Watch the dashboard - one line stays green, one turns red"
- "This is surgical precision - block attackers, allow customers"
- "5 seconds from policy save to global enforcement"
- "Zero service disruption - no restarts, no deployments"

## The Hook

Start: **"Let me show you how we can block malicious IPs in real-time without touching any code"**

End: **"That red line could be an attacker. That green line is your customer. This ships this week."**