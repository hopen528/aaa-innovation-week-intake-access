# IP Policy API Specification

## Overview

IP-based restriction policies allow organizations to control access to their Datadog resources based on source IP addresses. Policies can be applied org-wide (all API keys) or to specific API keys.

## Base URL

```
/api/unstable/orgs/{org_uuid}/ip-policies
```

## Authentication

All endpoints require:
- Valid API key (`DD-API-KEY` header)
- Valid application key (`DD-APPLICATION-KEY` header)
- `user_access_manage` permission

## Endpoints

### Create IP Policy

```
POST /api/unstable/orgs/{org_uuid}/ip-policies
```

Creates a new IP policy. If a policy already exists for the specified `resource_id`, it will be replaced (upsert behavior).

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `resource_id` | string | Yes | `"*"` for org-wide policy, or specific API key UUID for key-specific policy |
| `blocked_cidrs` | string[] | No* | List of CIDR blocks to block |
| `allowed_cidrs` | string[] | No* | List of CIDR blocks to allow |
| `mode` | string | No | `"disabled"`, `"dry_run"`, or `"enforced"` (default: `"enforced"`) |

*At least one of `blocked_cidrs` or `allowed_cidrs` must be provided.

**Example Request:**

```json
{
  "resource_id": "*",
  "blocked_cidrs": ["192.168.1.0/24", "10.0.0.0/8"],
  "allowed_cidrs": ["8.8.8.0/24"],
  "mode": "enforced"
}
```

**Response:** `201 Created`

```json
{
  "id": "*",
  "resource_id": "*",
  "blocked_cidrs": ["192.168.1.0/24", "10.0.0.0/8"],
  "allowed_cidrs": ["8.8.8.0/24"],
  "mode": "enforced"
}
```

---

### List IP Policies

```
GET /api/unstable/orgs/{org_uuid}/ip-policies
```

Returns all IP policies for the organization.

**Query Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `resource_id` | string | No | Filter by specific resource ID |

**Response:** `200 OK`

```json
[
  {
    "id": "*",
    "resource_id": "*",
    "blocked_cidrs": ["192.168.1.0/24"],
    "allowed_cidrs": [],
    "mode": "enforced"
  },
  {
    "id": "key-456",
    "resource_id": "key-456",
    "blocked_cidrs": ["10.0.0.0/8"],
    "allowed_cidrs": ["172.16.0.0/12"],
    "mode": "dry_run"
  }
]
```

---

### Update IP Policy

```
PATCH /api/unstable/orgs/{org_uuid}/ip-policies/{resource_id}
```

Updates an existing IP policy. Only provided fields are updated.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `resource_id` | string | `"*"` for org-wide policy, or specific API key UUID |

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `blocked_cidrs` | string[] | No | New list of CIDR blocks to block |
| `allowed_cidrs` | string[] | No | New list of CIDR blocks to allow |
| `mode` | string | No | `"disabled"`, `"dry_run"`, or `"enforced"` |

*At least one field must be provided.

**Example Request:**

```json
{
  "mode": "dry_run"
}
```

**Response:** `200 OK`

```json
{
  "id": "*",
  "resource_id": "*",
  "blocked_cidrs": ["192.168.1.0/24"],
  "allowed_cidrs": [],
  "mode": "dry_run"
}
```

---

### Delete IP Policy

```
DELETE /api/unstable/orgs/{org_uuid}/ip-policies/{resource_id}
```

Deletes an IP policy.

**Path Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `resource_id` | string | `"*"` for org-wide policy, or specific API key UUID |

**Response:** `204 No Content`

---

## Policy Modes

| Mode | Evaluates | Blocks | Description |
|------|-----------|--------|-------------|
| `disabled` | No | No | Policy is dormant, not evaluated |
| `dry_run` | Yes | No | Policy is evaluated, logs what would be blocked, but allows all traffic |
| `enforced` | Yes | Yes | Policy is fully enforced, blocks matching traffic |

**Recommended rollout:** `disabled` → `dry_run` → `enforced`

---

## Policy Evaluation Logic

1. **Org-wide policies** (`resource_id: "*"`) apply to all API keys in the organization
2. **Key-specific policies** apply only to that specific API key
3. Both policies are evaluated (if they exist) - a request must pass both to be allowed
4. If `allowed_cidrs` is specified, the request IP must match at least one allowed CIDR
5. If `blocked_cidrs` is specified, the request IP must NOT match any blocked CIDR
6. Combined: `(IP in allowlist) AND (IP not in blocklist)`

---

## Examples

### Block a malicious IP range org-wide

```bash
curl -X POST "https://api.datadoghq.com/api/unstable/orgs/{org_uuid}/ip-policies" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "*",
    "blocked_cidrs": ["1.2.3.0/24"],
    "mode": "enforced"
  }'
```

### Allow only corporate network

```bash
curl -X POST "https://api.datadoghq.com/api/unstable/orgs/{org_uuid}/ip-policies" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "*",
    "allowed_cidrs": ["10.0.0.0/8", "172.16.0.0/12"],
    "mode": "enforced"
  }'
```

### Test a policy before enforcing

```bash
# Create in dry_run mode
curl -X POST "https://api.datadoghq.com/api/unstable/orgs/{org_uuid}/ip-policies" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "resource_id": "*",
    "blocked_cidrs": ["192.168.0.0/16"],
    "mode": "dry_run"
  }'

# Later, promote to enforced
curl -X PATCH "https://api.datadoghq.com/api/unstable/orgs/{org_uuid}/ip-policies/*" \
  -H "DD-API-KEY: ${DD_API_KEY}" \
  -H "DD-APPLICATION-KEY: ${DD_APP_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"mode": "enforced"}'
```

---

## Error Responses

| Status | Description |
|--------|-------------|
| `400 Bad Request` | Invalid request body, missing required fields, or invalid CIDR format |
| `401 Unauthorized` | Invalid or missing API/application key |
| `403 Forbidden` | Missing `user_access_manage` permission |
| `404 Not Found` | Policy not found (for PATCH/DELETE) |
| `500 Internal Server Error` | Server error |

**Error Response Format:**

```json
{
  "errors": ["error message here"]
}
```
