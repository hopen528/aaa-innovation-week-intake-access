# IP Policies Demo Prep

## Demo Flow

1. **Show the problem** - Intake traffic has no IP restrictions today
2. **Create org-wide policy** - Block a CIDR range in dry_run mode
3. **Test IP** - Show test feature against FRAMES
4. **Promote to enforced** - Change mode
5. **Show API key integration** - Policy embedded in API key modal
6. **Show audit trail** - Link to audit events

## Pre-Demo Setup

- [ ] Clean slate: delete any existing test policies
- [ ] Have a test org ready
- [ ] Open these tabs:
  - `/organization-settings/ip-policies`
  - `/organization-settings/api-keys` (to show integration)
  - Audit trail filtered to ip_policy events
  - CEL policy dashboard: https://ddstaging.datadoghq.com/dashboard/2rv-wuu-vhj

## Talking Points

- **Performance**: 0.3μs evaluation, 600x under latency budget
- **Flexibility**: CEL expressions can extend to scoped API key, country, time, user-agent later
- **Safe rollout**: disabled → dry_run → enforced
- **No new infra**: Reuses Zoltron + FRAMES + intake sidecar

## Potential Questions

- "How fast does it propagate?" → ~5s via FRAMES
- "What if CEL fails?" → Fail open
- "Can key-specific bypass org-wide?" → No, both must pass
