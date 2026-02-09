---
title: "Innovation Week Access Control Policies For Intake Traffic"
source: "https://docs.google.com/document/d/1w-9Q-uSdmaUF5YR3py9d6cenphkX8mH1gspO6Be-DF4"
author: "haopeng.liu@datadoghq.com"
last_modified: "2026-02-03T20:54:38.687Z"
synced_at: "2026-02-06T20:55:05Z"
category: "other"
priority: "high"
comment_count: 11
open_comments: 11
latest_comment: "2026-02-02T18:59:05.499Z"
---
# Goal

## Goal

Build an access control layer for intake traffic at the edge

## Demo 

Below are concrete steps of the demo if we could successfully build it in the innovation week  
 

1. Send the intake http request  
   1. Send the intake request to /api/v2/logs with empty payload. Expect response with status 202\.  
2. (optional) Be able to detect and filter traffic with specific IP  
   1. From datadog logs/metrics  
   2. Abnormal detection  
3. Create a new **intake ingestion policy** to block traffic from certain IP.  
   1. (Nice-to-have) Use bits AI (via datadog MCP service or claude skills) to automatically create this policy. (Prompt: block all intake traffic sent from IP\<\> for org 2).  
   2. (Nice-to-have) A nice UI to add IP allowlist policy  
   3. (Must) Call a gRPC service to add this new policy  
4. Verify that the ingestion policy is updated in **realtime**  
   1. Wait about 2 seconds, and query the gRPC service to confirm the policy is added and propagated through FRAME  
5. Resend the intake http request (repeat step 1\)  
   1. Send the intake request to /api/v2/logs with empty payload. Expect response with status 403\. 

## Current Status

### What we already built

![][image1]

### What we plan to build (to be discussed with the team)

![][image2]

### Data plane (AuthN sidecar)

* Loads ingestion control policies from context platform (FRAME)  
  * We already use FRAME to load api keys and client tokens.  
  * Prefer to avoid directly pulling from database in the sidecar  
* A general policy engine   
  * TODO: add some pointers for this  
  * Current definition of [intake policy](https://github.com/DataDog/dd-source/blob/f6cc16f804623b02d83f4bf04db8a0e02517d12f/domains/aaa/apps/ace-contexts/acepb/policy.proto)  
  * Proposed [proto definition]()  
* New access control logic to perform IP checks for intake request  
  * We did some [basic policy checks](https://github.com/DataDog/dd-go/blob/prod/apps/authenticator-intake/authzcheck/policy.go) previously for scoped api keys.  
  * I did some simple [vibe coding]() with IP allowlist checks. We could even narrow it down to IP checks instead of private VPC checks.  
* Returns 403 for IP blocked requests

### Data plane (Envoy)

* Needs to pass the IP address from Envoy to AuthN sidecar  
  * Worked with Fabric team on it: [https://github.com/DataDog/service-discovery-platform/pull/13791](https://github.com/DataDog/service-discovery-platform/pull/13791)

### Control plane (Frame)

* Pass the IP allowlist policies/configs from DB to the sidecar  
  * Keep static stability of the sidecar and avoid directly pulling data from DB.  
  * Did some vibe coding before, [https://github.com/DataDog/dd-source/pull/345911](https://github.com/DataDog/dd-source/pull/345911)

### UX / Public API

* CRUD apis for mutating the intake IP allowlist  
* Reuse existing UI or inventing something new  
  * [https://docs.datadoghq.com/account\_management/org\_settings/ip\_allowlist/](https://docs.datadoghq.com/account_management/org_settings/ip_allowlist/)

### AI

* MCP capability to construct the IP allowlist from an AI agent 

### Features

* More control policies beyond IP allowlist, e.g. usage based throttling?

## Reference

* [Limitations of the FABRIC RBAC solution](https://docs.google.com/document/d/1XGvm5K4o1CaP2ns9DftJte_yQ2-77FE2Kz_24XKWD10/edit?tab=t.0#heading=h.n6az3ji9pk0)  
* [From scoped API key to intake ingestion control](https://docs.google.com/document/d/1FAVae6RO9GhZa7HimWJNRMULzbw39pziSFDKD6SoibM/edit?pli=1&tab=t.ggllk4iwenao#heading=h.c1zezr2v3ztf)

# IP Allowlist control

### Prompt

`Can you implement example code to access the VPC endpoint ids? Also try to summarize the logic in the current RBAC filter that performs the VPC id checks. Try to replicate that logic in golang`

 `Summary of RBAC Filter VPC ID Check Logic`  
  `From vpce_rbac.go, the filter performs these checks:`  
  `1. Extract VPC ID: Gets VPC Endpoint ID from dynamic metadata (key "234" from proxy_protocol_tlv_processor)`  
  `2. Extract Org ID: Gets organization ID from the dd-internal-edge-org-id header (set by authn_sidecar)`  
  `3. Policy Checks:`  
    `- org-not-vpce: DENY if org ID matches BUT VPC ID is present but doesn't match allowed list`  
    `- vpce-not-org: DENY if VPC ID matches allowed list BUT org ID doesn't match (when VPCENotOrgIdDeny: true)`  
    `- org-public-traffic: DENY if org ID matches BUT client IP is from public internet (when PublicInternetAllowed: false)`  
  `Go Implementation for authn_sidecar`  
  `Here's the complete implementation:`

```go

  package authnsidecar
  import (
  	"context"
  	"fmt"
  	"net"
  	extauthv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
  	"google.golang.org/genproto/googleapis/rpc/code"
  	"google.golang.org/genproto/googleapis/rpc/status"
  	"google.golang.org/grpc/metadata"
  )
  // VPCEConfig holds configuration for VPC Endpoint validation
  type VPCEConfig struct {
  	OrgID                 string   // Organization ID to validate
  	VPCEAllowed           []string // List of allowed VPC Endpoint IDs
  	PublicInternetAllowed bool     // Whether public internet traffic is allowed
  	VPCENotOrgIdDeny      bool     // Whether to deny VPC traffic from non-matching orgs
  }
  // VPCEValidator handles VPC Endpoint validation logic
  type VPCEValidator struct {
  	configs map[string]VPCEConfig // Map of org ID to config
  }
  // NewVPCEValidator creates a new VPC Endpoint validator
  func NewVPCEValidator(configs map[string]VPCEConfig) *VPCEValidator {
  	return &VPCEValidator{
  		configs: configs,
  	}
  }
  // ExtractVPCEndpointID extracts the VPC Endpoint ID from Envoy's dynamic metadata
  // The metadata is passed via the CheckRequest's AttributeContext
  func ExtractVPCEndpointID(req *extauthv3.CheckRequest) (string, bool) {
  	// Access dynamic metadata from the request
  	if req.Attributes == nil || req.Attributes.MetadataContext == nil {
  		return "", false
  	}
  	// Look for the proxy_protocol_tlv_processor metadata namespace
  	metadata := req.Attributes.MetadataContext
  	if proxyProtoMetadata, ok := metadata["envoy.filters.http.proxy_protocol_tlv_processor"]; ok {
  		// Extract the VPC ID from key "234" (TLV type for VPC Endpoint ID)
  		if fields := proxyProtoMetadata.GetFields(); fields != nil {
  			if vpcIDValue, exists := fields["234"]; exists {
  				vpcID := vpcIDValue.GetStringValue()
  				return vpcID, vpcID != ""
  			}
  		}
  	}
  	return "", false
  }
  // ExtractClientIP extracts the client IP from the request headers
  func ExtractClientIP(req *extauthv3.CheckRequest) (string, bool) {
  	if req.Attributes == nil || req.Attributes.Request == nil || req.Attributes.Request.Http == nil {
  		return "", false
  	}
  	headers := req.Attributes.Request.Http.Headers
  	if clientIP, ok := headers["x-client-ip"]; ok && clientIP != "" {
  		return clientIP, true
  	}
  	return "", false
  }
  // ExtractOrgID extracts the organization ID from the request
  // This would typically be set by your authentication logic
  func ExtractOrgID(req *extauthv3.CheckRequest) (string, bool) {
  	if req.Attributes == nil || req.Attributes.Request == nil || req.Attributes.Request.Http == nil {
  		return "", false
  	}
  	headers := req.Attributes.Request.Http.Headers
  	if orgID, ok := headers["dd-internal-edge-org-id"]; ok && orgID != "" {
  		return orgID, true
  	}
  	return "", false
  }
  // isPrivateIP checks if an IP address is in a private range
  func isPrivateIP(ipStr string) bool {
  	ip := net.ParseIP(ipStr)
  	if ip == nil {
  		return false
  	}
  	// Private IPv4 ranges
  	privateIPv4Ranges := []string{
  		"127.0.0.0/8",    // Loopback
  		"10.0.0.0/8",     // Private
  		"172.16.0.0/12",  // Private
  		"192.168.0.0/16", // Private
  	}
  	// Private IPv6 ranges
  	privateIPv6Ranges := []string{
  		"fc00::/7",  // Unique local addresses
  		"fe80::/10", // Link-local addresses
  	}
  	allRanges := append(privateIPv4Ranges, privateIPv6Ranges...)
  	for _, cidr := range allRanges {
  		_, network, err := net.ParseCIDR(cidr)
  		if err != nil {
  			continue
  		}
  		if network.Contains(ip) {
  			return true
  		}
  	}
  	return false
  }
  // ValidateVPCEndpoint validates VPC Endpoint ID against the configuration
  // Returns (allowed bool, reason string, error)
  func (v *VPCEValidator) ValidateVPCEndpoint(
  	orgID string,
  	vpcEndpointID string,
  	clientIP string,
  ) (bool, string, error) {
  	config, exists := v.configs[orgID]
  	if !exists {
  		// No VPC config for this org, allow by default
  		return true, "", nil
  	}
  	// Check 1: org-not-vpce
  	// If org matches and VPC ID is present but not in allowed list, DENY
  	if vpcEndpointID != "" {
  		vpcAllowed := false
  		for _, allowedVPC := range config.VPCEAllowed {
  			if vpcEndpointID == allowedVPC {
  				vpcAllowed = true
  				break
  			}
  		}
  		if !vpcAllowed {
  			return false, fmt.Sprintf(
  				"org %s has VPC endpoint %s which is not in allowed list",
  				orgID, vpcEndpointID,
  			), nil
  		}
  	}
  	// Check 2: vpce-not-org (if enabled)
  	// If VPC ID matches but org doesn't match, DENY
  	if config.VPCENotOrgIdDeny && vpcEndpointID != "" {
  		vpcMatches := false
  		for _, allowedVPC := range config.VPCEAllowed {
  			if vpcEndpointID == allowedVPC {
  				vpcMatches = true
  				break
  			}
  		}
  		if vpcMatches && orgID != config.OrgID {
  			return false, fmt.Sprintf(
  				"VPC endpoint %s is allowed for org %s but request is from org %s",
  				vpcEndpointID, config.OrgID, orgID,
  			), nil
  		}
  	}
  	// Check 3: org-public-traffic
  	// If public internet is not allowed and client IP is public, DENY
  	if !config.PublicInternetAllowed && clientIP != "" {
  		if !isPrivateIP(clientIP) {
  			return false, fmt.Sprintf(
  				"org %s does not allow public internet traffic, client IP %s is public",
  				orgID, clientIP,
  			), nil
  		}
  	}
  	return true, "", nil
  }
  // Check implements the ext_authz Check method with VPC validation
  func (v *VPCEValidator) Check(
  	ctx context.Context,
  	req *extauthv3.CheckRequest,
  ) (*extauthv3.CheckResponse, error) {
  	// Extract VPC Endpoint ID from dynamic metadata
  	vpcEndpointID, hasVPCID := ExtractVPCEndpointID(req)
  	// Extract client IP from headers
  	clientIP, _ := ExtractClientIP(req)
  	// Extract org ID (this should come from your auth logic)
  	orgID, hasOrgID := ExtractOrgID(req)
  	if !hasOrgID {
  		// No org ID, cannot validate - allow or deny based on your policy
  		return &extauthv3.CheckResponse{
  			Status: &status.Status{Code: int32(code.Code_OK)},
  		}, nil
  	}
  	// Validate VPC Endpoint
  	allowed, reason, err := v.ValidateVPCEndpoint(orgID, vpcEndpointID, clientIP)
  	if err != nil {
  		return nil, err
  	}
  	if !allowed {
  		// Deny the request
  		return &extauthv3.CheckResponse{
  			Status: &status.Status{
  				Code:    int32(code.Code_PERMISSION_DENIED),
  				Message: reason,
  			},
  		}, nil
  	}
  	// Allow the request
  	return &extauthv3.CheckResponse{
  		Status: &status.Status{Code: int32(code.Code_OK)},
  	}, nil
  }
  // Example usage in your authn_sidecar service:
  func ExampleUsage() {
  	// Configure VPC validation rules
  	configs := map[string]VPCEConfig{
  		"114022": { // test-org from us1.staging config
  			OrgID: "114022",
  			VPCEAllowed: []string{
  				"vpce-01071732b9998a0fa", // Note: config has "!" prefix meaning NOT allowed
  			},
  			PublicInternetAllowed: false,
  			VPCENotOrgIdDeny:      true,
  		},
  	}
  	validator := NewVPCEValidator(configs)
  	// In your CheckRequest handler:
  	// response, err := validator.Check(ctx, req)
  	_ = validator
  }
```

# Policy Engine brainstorm

## Policy Proto

```
// Policy defines an ingestion policy with a status and a matcher-based rule
message PolicyContext {
    string uuid = 1;
    string name = 2;
    int64 org_id = 3;
    string org_uuid = 4;

    PolicyStatus status = 5;
    repeated Rule rule = 6;

    google.protobuf.Timestamp modified_at = 7;
    string created_by = 8;
    Action default_action = 9;  // by default: allow.
}

// PolicyStatus indicates whether the policy is enforced, in dry-run mode, or disabled
enum PolicyStatus {
    POLICY_STATUS_UNSPECIFIED = 0;
    DRY_RUN = 1;      // Policy is evaluated but not enforced
    ENFORCED = 2;     // Policy is actively enforced
    DISABLED = 3;     // Policy is disabled and not evaluated
}

// Rule defines what to match and what action to take when matched
message Rule {
    Matcher matcher = 1;
    Action action = 2;
}

// Action to take when a rule matches
enum Action {
    ACTION_UNSPECIFIED = 0;
    ALLOW = 1;
    DENY = 2;
}

// Matcher is a recursive structure that can match request attributes
// using logical operators (AND, OR, NOT) and attribute matching
message Matcher {
    oneof matcher_type {
        AttributeMatcher attribute = 1;
        AndMatcher and = 2;
        OrMatcher or = 3;
        NotMatcher not = 4;
    }
}

// AttributeMatcher matches a single attribute from the request context
// Request context is a key-value map where keys can be:
// - "ip": Client IP address
// - "key_uuid": API key UUID
// - "key_fingerprint": API key fingerprint
// - "org_id": Organization ID
// - "product": Product scope (LOGS, METRICS, APM, etc.)
// - Any other custom attribute
message AttributeMatcher {
    // The attribute key from request context
    string key = 1;

    // How to match the attribute value
    MatchType match_type = 2;

    // Values to match against
    // For multiple values: matches if attribute value matches ANY of these values (OR semantics)
    repeated string values = 3;
}

// Match type for attribute matching
enum MatchType {
    MATCH_TYPE_UNSPECIFIED = 0;
    EXACT = 1;        // Exact string match
    PREFIX = 2;       // Attribute value starts with the pattern
    SUFFIX = 3;       // Attribute value ends with the pattern
    REGEX = 4;        // Regular expression match
    CONTAINS = 5;     // Attribute value contains the pattern
}

// AndMatcher matches when ALL child matchers match
message AndMatcher {
    repeated Matcher matchers = 1;
}

// OrMatcher matches when AT LEAST ONE child matcher matches
message OrMatcher {
    repeated Matcher matchers = 1;
}

// NotMatcher inverts the result of the child matcher
message NotMatcher {
    Matcher matcher = 1;
}
```

## Examples

```textproto
 # Example 1: IP Allowlist Policy
 # Only allow requests from specific IP addresses, deny everything else:

  uuid: "11111111-1111-1111-1111-111111111111"
  name: "Production IP Allowlist"
  org_id: 12345
  org_uuid: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
  status: ENFORCED
  policy_version: 1
  modified_at {
    seconds: 1706745600
  }
  created_by: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
  default_action: DENY
  rules {
    matcher {
      attribute {
        key: "ip"
        match_type: EXACT
        values: "10.0.1.100"
        values: "10.0.1.101"
        values: "10.0.1.102"
      }
    }
    action: ALLOW
  }

#  Example 2: IP Range Allowlist (using PREFIX matching)
#  Allow entire subnets:
  uuid: "22222222-2222-2222-2222-222222222222"
  name: "Development IP Range Allowlist"
  org_id: 12345
  org_uuid: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
  status: ENFORCED
  policy_version: 2
  modified_at {
    seconds: 1706745600
  }
  default_action: DENY
  rules {
    matcher {
      or {
        matchers {
          attribute {
            key: "ip"
            match_type: PREFIX
            values: "10.0."
          }
        }
        matchers {
          attribute {
            key: "ip"
            match_type: PREFIX
            values: "192.168."
          }
        }
      }
    }
    action: ALLOW
  }

#  Example 3: Scoped API Key Policy
#  Only specific API keys can access LOGS and METRICS products:
  uuid: "33333333-3333-3333-3333-333333333333"
  name: "Scoped API Key - Logs and Metrics Only"
  org_id: 12345
  org_uuid: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
  status: ENFORCED
  policy_version: 1
  modified_at {
    seconds: 1706745600
  }
  created_by: "cccccccc-cccc-cccc-cccc-cccccccccccc"
  default_action: DENY
  # Rule 1: Allow specific keys for LOGS product
  rules {
    matcher {
      and {
        matchers {
          attribute {
            key: "key_uuid"
            match_type: EXACT
            values: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
            values: "ffffffff-ffff-ffff-ffff-ffffffffffff"
          }
        }
        matchers {
          attribute {
            key: "product"
            match_type: EXACT
            values: "LOGS"
          }
        }
      }
    }
    action: ALLOW
  }
  # Rule 2: Allow specific keys for METRICS product
  rules {
    matcher {
      and {
        matchers {
          attribute {
            key: "key_uuid"
            match_type: EXACT
            values: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"
            values: "gggggggg-gggg-gggg-gggg-gggggggggggg"
          }
        }
        matchers {
          attribute {
            key: "product"
            match_type: EXACT
            values: "METRICS"
          }
        }
      }
    }
    action: ALLOW
  }

```

# Policy Engine (binding based) brainstorm

\#\# Overview

This design uses a \*\*policy binding\*\* model where policies are expressed as bindings between:  
\- \*\*resource\_type\*\*: What resource is being accessed (logs, metrics, API route)  
\- \*\*principal\*\*: Who is making the request (org, team, user \- identity types only)  
\- \*\*relation\*\*: What action to take (allow, deny)  
\- \*\*condition\*\*: Under what circumstances (IP range, key attributes, time restrictions, etc.)

This model is inspired by Google Cloud IAM, Zanzibar, and modern ReBAC systems.

\*\*Important:\*\* Principals represent \*\*identities only\*\* (org, team, user). Attributes like API key UUID or IP address should be expressed in the condition field, not as principal types.

\---

\#\# Design Philosophy

\#\#\# Principal Types vs Request Attributes

\*\*Critical Design Decision:\*\*

\*\*Principals\*\* represent \*\*identities\*\* only:  
\- ✅ \`org:12345\` or \`org:\*\` \- Organization identity  
\- ✅ \`team:platform\` or \`team:\*\` \- Team identity  
\- ✅ \`user:alice@example.com\` or \`user:\*\` \- User identity

\*\*Request Attributes\*\* are matched in \*\*conditions\*\*:  
\- ✅ \`request.key\_uuid\` \- Which API key is being used  
\- ✅ \`request.ip\` \- What IP address the request comes from  
\- ✅ \`request.product\` \- What product is being accessed  
\- ✅ \`request.route\` \- What API route is being called

\*\*Example:\*\*  
\`\`\`json  
{  
  "resource\_type": "logs",  
  "principal": "org:\*",  
  "relation": "ALLOW",  
  "condition": "request.key\_uuid \== 'xxx' && ipInRange(request.ip, '10.0.0.0/8')"  
}  
\`\`\`  
This reads as: "Organization members can ALLOW access to logs if they use specific API key AND come from internal IP range"

\#\#\# Key Concepts

1\. \*\*Resource-Centric\*\*: Policies are defined around resources (intake routes, products)  
2\. \*\*Principal-Based\*\*: Requests are evaluated based on the identity making the request  
3\. \*\*Condition Expression Language\*\*: Flexible condition matching using expressions  
4\. \*\*Multiple Bindings\*\*: One policy can have multiple bindings with different conditions  
5\. \*\*Explicit Relations\*\*: Clear semantic meaning (allow/deny instead of implicit logic)

\#\#\# Evaluation Model

For each request:  
1\. Identify the \*\*resource\_type\*\* being accessed  
2\. Identify the \*\*principal\*\* making the request  
3\. Find all bindings matching (resource\_type \+ principal)  
4\. Evaluate conditions for each binding  
5\. First matching binding determines the action (relation: allow/deny)  
6\. Default action if no bindings match

\---

\#\# Protobuf Definition

\`\`\`protobuf  
syntax \= "proto3";

package acepb;

import "google/protobuf/timestamp.proto";

option go\_package \= "github.com/DataDog/dd-source/domains/aaa/apps/ace-contexts/acepb";

// PolicyContext represents a complete policy for an organization with multiple bindings  
message PolicyContext {  
    string uuid \= 1;  
    string name \= 2;  
    int64 org\_id \= 3;  
    string org\_uuid \= 4;

    PolicyStatus status \= 5;  
    repeated Binding bindings \= 6;

    int64 policy\_version \= 7;  
    google.protobuf.Timestamp modified\_at \= 8;  
    string created\_by \= 9;  
    Action default\_action \= 10; // Default if no bindings match (default: ALLOW)  
}

// PolicyStatus indicates whether the policy is enforced  
enum PolicyStatus {  
    POLICY\_STATUS\_UNSPECIFIED \= 0;  
    DRY\_RUN \= 1;  
    ENFORCED \= 2;  
    DISABLED \= 3;  
}

// Binding represents a policy rule: "principal can perform relation on resource\_type if condition"  
message Binding {  
    // Resource type being accessed (e.g., "logs", "metrics", "/api/v2/logs", "\*" for all)  
    string resource\_type \= 1;

    // Principal identity making the request  
    // Supported formats:  
    //   \- "org:\<org\_id\>" or "org:\*" (organization identity)  
    //   \- "team:\<team\_id\>" or "team:\*" (team identity)  
    //   \- "user:\<user\_id\>" or "user:\*" (user identity)  
    // Note: API keys, IP addresses, etc. should be checked in the condition, not principal  
    string principal \= 2;

    // Relation/action to allow or deny  
    Relation relation \= 3;

    // Condition expression that must evaluate to true  
    // Empty condition means "always match"  
    // Example: "request.key\_uuid \== 'xxx' && request.ip startsWith '10.0.'"  
    string condition \= 4;  
}

// Relation represents the action in a binding  
enum Relation {  
    RELATION\_UNSPECIFIED \= 0;  
    ALLOW \= 1;  
    DENY \= 2;  
}

// Action is kept for backward compatibility with default\_action  
enum Action {  
    ACTION\_UNSPECIFIED \= 0;  
    ALLOW \= 1;  
    DENY \= 2;  
}  
\`\`\`

\---

\#\# Condition Expression Language

Conditions use a simple expression language with these operators:

\#\#\# Comparison Operators  
\- \`==\` \- Equality  
\- \`\!=\` \- Inequality  
\- \`in\` \- Value in list  
\- \`matches\` \- Regex match  
\- \`startsWith\` \- Prefix match  
\- \`endsWith\` \- Suffix match  
\- \`contains\` \- Substring match

\#\#\# Logical Operators  
\- \`&&\` \- AND  
\- \`||\` \- OR  
\- \`\!\` \- NOT  
\- Parentheses \`()\` for grouping

\#\#\# Functions  
\- \`containsAny(list1, list2)\` \- True if any element in list1 is in list2  
\- \`containsAll(list1, list2)\` \- True if all elements in list1 are in list2  
\- \`ipInRange(ip, cidr)\` \- True if IP is in CIDR range  
\- \`len(list)\` \- Length of a list  
\- \`lower(string)\` \- Convert string to lowercase  
\- \`upper(string)\` \- Convert string to uppercase

\#\#\# Variables Available  
\- \`request.ip\` \- Client IP address  
\- \`request.key\_uuid\` \- API key UUID  
\- \`request.key\_fingerprint\` \- API key fingerprint  
\- \`request.product\` \- Product scope (LOGS, METRICS, APM, etc.)  
\- \`request.route\` \- API route path  
\- \`request.org\_id\` \- Organization ID  
\- \`request.team\_id\` \- Team ID (future)  
\- \`request.user\_id\` \- User ID (future)  
\- \`request.hour\` \- Hour of day (0-23, UTC) (if time-based policies needed)  
\- \`request.timestamp\` \- Request timestamp (for temporal conditions)  
\- \`resource.type\` \- Resource type from binding

\#\#\# Example Conditions

\*\*Simple attribute matching:\*\*  
\`\`\`  
request.ip startsWith "10.0."  
request.key\_uuid \== "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"  
request.product in \["LOGS", "METRICS"\]  
\`\`\`

\*\*Combined conditions:\*\*  
\`\`\`  
request.ip startsWith "10.0." && request.product \== "LOGS"  
ipInRange(request.ip, "10.0.0.0/16") || ipInRange(request.ip, "192.168.0.0/16")  
\`\`\`

\*\*Complex logic with grouping:\*\*  
\`\`\`  
(request.key\_uuid in \["key1", "key2"\] && request.product \== "LOGS") ||  
(request.key\_uuid \== "key3" && request.product in \["METRICS", "APM"\])  
\`\`\`

\*\*API key with IP restriction:\*\*  
\`\`\`  
request.key\_uuid \== "xxx" && ipInRange(request.ip, "10.0.0.0/8")  
\`\`\`

\*\*Multiple API keys OR condition:\*\*  
\`\`\`  
request.key\_uuid in \["key1-uuid", "key2-uuid", "key3-uuid"\]  
\`\`\`

\*\*Negative conditions:\*\*  
\`\`\`  
\!ipInRange(request.ip, "192.168.0.0/16")  
request.product \!= "APM"  
\`\`\`

## Use Case Examples

### Example 1: Simple IP Allowlist

\*\*Use Case:\*\* Only allow logs ingestion from specific IP addresses

\`\`\`json  
{  
  "uuid": "11111111-1111-1111-1111-111111111111",  
  "name": "Production IP Allowlist for Logs",  
  "org\_id": 12345,  
  "org\_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",  
  "status": "ENFORCED",  
  "policy\_version": 1,  
  "modified\_at": "2026-01-30T10:00:00Z",  
  "created\_by": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",  
  "default\_action": "DENY",  
  "bindings": \[  
    {  
      "resource\_type": "logs",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "request.ip in \[\\"10.0.1.100\\", \\"10.0.1.101\\", \\"10.0.1.102\\"\]"  
    }  
  \]  
}  
\`\`\`

\*\*Interpretation:\*\*  
\- For resource type "logs"  
\- Any principal from this org (org:\*)  
\- Allow access  
\- If request IP is in the allowed list

\*\*Evaluation Examples:\*\*  
\- Request: \`{resource: "logs", ip: "10.0.1.100"}\` → ALLOW (matches binding)  
\- Request: \`{resource: "logs", ip: "1.2.3.4"}\` → DENY (default\_action)  
\- Request: \`{resource: "metrics", ip: "10.0.1.100"}\` → DENY (no binding for metrics)

\---

### Example 2: IP Range Allowlist (CIDR)

\*\*Use Case:\*\* Allow entire subnets for all products

\`\`\`json  
{  
  "uuid": "22222222-2222-2222-2222-222222222222",  
  "name": "Development IP Range Allowlist",  
  "org\_id": 12345,  
  "org\_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",  
  "status": "ENFORCED",  
  "policy\_version": 2,  
  "modified\_at": "2026-01-30T10:00:00Z",  
  "default\_action": "DENY",  
  "bindings": \[  
    {  
      "resource\_type": "\*",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "ipInRange(request.ip, \\"10.0.0.0/16\\") || ipInRange(request.ip, \\"192.168.0.0/16\\")"  
    }  
  \]  
}  
\`\`\`

\*\*Interpretation:\*\*  
\- For all resource types (\*)  
\- Any principal from this org  
\- Allow access  
\- If IP is in either CIDR range

\*\*Wildcard Support:\*\*  
\- \`resource\_type: "\*"\` matches ALL resources  
\- \`principal: "org:\*"\` matches ANY request from this org

\---

### Example 3: Scoped API Key \- Single Product

\*\*Use Case:\*\* Specific API keys can only access LOGS product

\`\`\`json  
{  
  "uuid": "33333333-3333-3333-3333-333333333333",  
  "name": "Scoped API Key \- Logs Only",  
  "org\_id": 12345,  
  "org\_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",  
  "status": "ENFORCED",  
  "policy\_version": 1,  
  "modified\_at": "2026-01-30T10:00:00Z",  
  "default\_action": "DENY",  
  "bindings": \[  
    {  
      "resource\_type": "logs",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "request.key\_uuid in \[\\"eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee\\", \\"ffffffff-ffff-ffff-ffff-ffffffffffff\\"\]"  
    }  
  \]  
}  
\`\`\`

\*\*Interpretation:\*\*  
\- For resource type "logs"  
\- Any principal from this org  
\- Allow access  
\- If the request's API key UUID is in the allowed list (checked in condition)

\*\*Principal Types (Identity Only):\*\*  
\- \`org:\<org\_id\>\` \- Specific organization (e.g., "org:12345")  
\- \`org:\*\` \- Any request from this org (most common for intake policies)  
\- \`team:\<team\_id\>\` \- Specific team (e.g., "team:5678")  
\- \`team:\*\` \- Any team from this org  
\- \`user:\<user\_id\>\` \- Specific user (e.g., "user:alice@example.com")  
\- \`user:\*\` \- Any user from this org

\*\*Evaluation Examples:\*\*  
\- Request: \`{resource: "logs", key\_uuid: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"}\` → ALLOW  
\- Request: \`{resource: "logs", key\_uuid: "other-key"}\` → DENY  
\- Request: \`{resource: "metrics", key\_uuid: "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"}\` → DENY

\---

### Example 4: Multi-Tier API Key Scoping

\*\*Use Case:\*\* Different keys have different product access  
\- Key1: LOGS \+ METRICS  
\- Key2: APM only

\`\`\`json  
{  
  "uuid": "44444444-4444-4444-4444-444444444444",  
  "name": "Multi-tier API Key Scoping",  
  "org\_id": 12345,  
  "org\_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",  
  "status": "ENFORCED",  
  "policy\_version": 3,  
  "modified\_at": "2026-01-30T10:00:00Z",  
  "default\_action": "DENY",  
  "bindings": \[  
    {  
      "resource\_type": "\*",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "request.key\_uuid \== \\"key1-uuid-uuid-uuid-uuid-uuiduuiduuid\\" && request.product in \[\\"LOGS\\", \\"METRICS\\"\]"  
    },  
    {  
      "resource\_type": "\*",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "request.key\_uuid \== \\"key2-uuid-uuid-uuid-uuid-uuiduuiduuid\\" && request.product \== \\"APM\\""  
    }  
  \]  
}  
\`\`\`

\*\*Interpretation:\*\*  
\- \*\*Binding 1:\*\* For any resource, org principals, ALLOW if using key1 AND product is LOGS or METRICS  
\- \*\*Binding 2:\*\* For any resource, org principals, ALLOW if using key2 AND product is APM

\*\*Alternative: Multiple Bindings per Key (more verbose but clearer)\*\*

\`\`\`json  
{  
  "bindings": \[  
    {  
      "resource\_type": "logs",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "request.key\_uuid \== \\"key1-uuid-uuid-uuid-uuid-uuiduuiduuid\\""  
    },  
    {  
      "resource\_type": "metrics",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "request.key\_uuid \== \\"key1-uuid-uuid-uuid-uuid-uuiduuiduuid\\""  
    },  
    {  
      "resource\_type": "apm",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "request.key\_uuid \== \\"key2-uuid-uuid-uuid-uuid-uuiduuiduuid\\""  
    }  
  \]  
}  
\`\`\`

\*\*Evaluation Examples:\*\*  
\- Request: \`{resource: "logs", key\_uuid: "key1..."}\` → ALLOW (binding 1\)  
\- Request: \`{resource: "metrics", key\_uuid: "key1..."}\` → ALLOW (binding 1\)  
\- Request: \`{resource: "apm", key\_uuid: "key1..."}\` → DENY (no matching binding)  
\- Request: \`{resource: "apm", key\_uuid: "key2..."}\` → ALLOW (binding 2\)

\---

\#\#\# Example 5: Combined IP \+ API Key Policy  
\*\*Use Case:\*\* Allow trusted IPs for all products, OR specific API keys with restrictions

\`\`\`json  
{  
  "uuid": "55555555-5555-5555-5555-555555555555",  
  "name": "Combined IP and API Key Policy",  
  "org\_id": 12345,  
  "org\_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",  
  "status": "ENFORCED",  
  "policy\_version": 1,  
  "modified\_at": "2026-01-30T10:00:00Z",  
  "default\_action": "DENY",  
  "bindings": \[  
    {  
      "resource\_type": "\*",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "request.ip startsWith \\"10.0.0.\\""  
    },  
    {  
      "resource\_type": "logs",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "request.key\_uuid \== \\"restricted-key-uuid-uuid-uuiduuid\\""  
    }  
  \]  
}  
\`\`\`

\*\*Interpretation:\*\*  
\- \*\*Binding 1:\*\* Any resource, org principals, ALLOW if from trusted IP (10.0.0.\*)  
\- \*\*Binding 2:\*\* Logs resource, org principals, ALLOW if using specific API key

\*\*Evaluation Examples:\*\*  
\- Request: \`{resource: "apm", ip: "10.0.0.5", key\_uuid: "any-key"}\` → ALLOW (binding 1\)  
\- Request: \`{resource: "logs", ip: "10.0.0.5", key\_uuid: "any-key"}\` → ALLOW (binding 1, first match)  
\- Request: \`{resource: "logs", ip: "1.2.3.4", key\_uuid: "restricted-key..."}\` → ALLOW (binding 2\)  
\- Request: \`{resource: "metrics", ip: "1.2.3.4", key\_uuid: "restricted-key..."}\` → DENY

\---

\#\#\# Example 6: Deny Specific API Route  
\*\*Use Case:\*\* Block a specific API endpoint for security reasons

\`\`\`json  
{  
  "uuid": "66666666-6666-6666-6666-666666666666",  
  "name": "Block Deprecated API Endpoint",  
  "org\_id": 12345,  
  "org\_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",  
  "status": "ENFORCED",  
  "policy\_version": 1,  
  "modified\_at": "2026-01-30T10:00:00Z",  
  "default\_action": "ALLOW",  
  "bindings": \[  
    {  
      "resource\_type": "/api/v1/logs",  
      "principal": "org:\*",  
      "relation": "DENY",  
      "condition": ""  
    }  
  \]  
}  
\`\`\`

\*\*Interpretation:\*\*  
\- For specific API route \`/api/v1/logs\`  
\- Any principal from this org  
\- DENY access  
\- Always (no condition)

\*\*Note:\*\* First matching binding wins, so DENY bindings can override ALLOW defaults.

\---

\#\#\# Example 7: Team-Based Access (Future Extension)  
\*\*Use Case:\*\* Only specific teams can access certain products

\`\`\`json  
{  
  "uuid": "77777777-7777-7777-7777-777777777777",  
  "name": "Team-Based Product Access",  
  "org\_id": 12345,  
  "org\_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",  
  "status": "ENFORCED",  
  "policy\_version": 1,  
  "modified\_at": "2026-01-30T10:00:00Z",  
  "default\_action": "DENY",  
  "bindings": \[  
    {  
      "resource\_type": "logs",  
      "principal": "team:platform-team",  
      "relation": "ALLOW",  
      "condition": ""  
    },  
    {  
      "resource\_type": "logs",  
      "principal": "team:security-team",  
      "relation": "ALLOW",  
      "condition": ""  
    },  
    {  
      "resource\_type": "apm",  
      "principal": "team:backend-team",  
      "relation": "ALLOW",  
      "condition": ""  
    }  
  \]  
}  
\`\`\`

\*\*Interpretation:\*\*  
\- Logs: Only platform and security teams  
\- APM: Only backend team  
\- All others: DENY (default\_action)

\---

\#\#\# Example 8: Advanced \- Conditional API Key Access  
\*\*Use Case:\*\* API key can access LOGS only during business hours (9am-5pm UTC)

\`\`\`json  
{  
  "uuid": "88888888-8888-8888-8888-888888888888",  
  "name": "Time-Restricted API Key",  
  "org\_id": 12345,  
  "org\_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",  
  "status": "ENFORCED",  
  "policy\_version": 1,  
  "modified\_at": "2026-01-30T10:00:00Z",  
  "default\_action": "DENY",  
  "bindings": \[  
    {  
      "resource\_type": "logs",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "request.key\_uuid \== \\"time-restricted-key-uuid\\" && request.hour \>= 9 && request.hour \< 17"  
    }  
  \]  
}  
\`\`\`

\*\*Interpretation:\*\*  
\- For logs resource  
\- Org principals  
\- ALLOW if using specific API key AND during business hours (9am-5pm UTC)

\*\*Note:\*\* This requires adding \`request.hour\` to the evaluation context.

\---

\#\#\# Example 9: Complex Condition \- IP \+ Product  
\*\*Use Case:\*\* Internal IPs can access all products, external IPs only LOGS

\`\`\`json  
{  
  "uuid": "99999999-9999-9999-9999-999999999999",  
  "name": "IP-Based Product Restrictions",  
  "org\_id": 12345,  
  "org\_uuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",  
  "status": "ENFORCED",  
  "policy\_version": 1,  
  "modified\_at": "2026-01-30T10:00:00Z",  
  "default\_action": "DENY",  
  "bindings": \[  
    {  
      "resource\_type": "\*",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "ipInRange(request.ip, \\"10.0.0.0/8\\")"  
    },  
    {  
      "resource\_type": "logs",  
      "principal": "org:\*",  
      "relation": "ALLOW",  
      "condition": "\!ipInRange(request.ip, \\"10.0.0.0/8\\")"  
    }  
  \]  
}  
\`\`\`

\*\*Interpretation:\*\*  
\- \*\*Binding 1:\*\* Internal IPs (10.0.0.0/8) can access ANY resource  
\- \*\*Binding 2:\*\* External IPs can ONLY access logs  
\- Default: DENY

\*\*Evaluation Examples:\*\*  
\- Request: \`{resource: "metrics", ip: "10.1.2.3"}\` → ALLOW (binding 1\)  
\- Request: \`{resource: "logs", ip: "1.2.3.4"}\` → ALLOW (binding 2\)  
\- Request: \`{resource: "metrics", ip: "1.2.3.4"}\` → DENY (no match)

\---

\#\# Comparison with Matcher-Based Design

\#\#\# Policy Binding Approach (This Design)  
\*\*Pros:\*\*  
\- ✅ More declarative and readable  
\- ✅ Resource-centric model aligns with API design  
\- ✅ Principal-based identity is explicit  
\- ✅ Simpler to express "who can do what on which resource"  
\- ✅ Easier to audit (clear subject-verb-object structure)  
\- ✅ Natural fit for future RBAC/ReBAC extensions

\*\*Cons:\*\*  
\- ❌ Condition expression language needs parser/evaluator  
\- ❌ More complex to implement initially  
\- ❌ Bindings can become verbose for complex policies

\#\#\# Matcher-Based Approach (Previous Design)  
\*\*Pros:\*\*  
\- ✅ More flexible for arbitrary logic  
\- ✅ Composable matchers are powerful  
\- ✅ Easier to implement (just tree traversal)  
\- ✅ No DSL to parse

\*\*Cons:\*\*  
\- ❌ Less intuitive to read  
\- ❌ Harder to audit (need to trace through matcher tree)  
\- ❌ Not resource-centric  
\- ❌ Principal identity is implicit

\---

\#\# Database Schema

\#\#\# Option 1: Single JSON Column  
\`\`\`sql  
CREATE TABLE policy\_context (  
    uuid UUID PRIMARY KEY,  
    name TEXT NOT NULL,  
    org\_id BIGINT NOT NULL,  
    org\_uuid UUID NOT NULL,  
    policy JSONB NOT NULL,  \-- Store entire PolicyContext as JSON  
    policy\_version BIGINT NOT NULL,  
    modified\_at TIMESTAMP NOT NULL,  
    created\_by UUID  
);

CREATE INDEX idx\_policy\_org\_id ON policy\_context(org\_id);  
CREATE INDEX idx\_policy\_org\_uuid ON policy\_context(org\_uuid);  
\`\`\`

\#\#\# Option 2: Normalized Schema  
\`\`\`sql  
CREATE TABLE policy\_context (  
    uuid UUID PRIMARY KEY,  
    name TEXT NOT NULL,  
    org\_id BIGINT NOT NULL,  
    org\_uuid UUID NOT NULL,  
    status TEXT NOT NULL,  
    default\_action TEXT NOT NULL,  
    policy\_version BIGINT NOT NULL,  
    modified\_at TIMESTAMP NOT NULL,  
    created\_by UUID  
);

CREATE TABLE policy\_binding (  
    id SERIAL PRIMARY KEY,  
    policy\_uuid UUID NOT NULL REFERENCES policy\_context(uuid),  
    resource\_type TEXT NOT NULL,  
    principal TEXT NOT NULL,  
    relation TEXT NOT NULL,  
    condition TEXT NOT NULL,  
    binding\_order INT NOT NULL  \-- To preserve evaluation order  
);

CREATE INDEX idx\_binding\_policy ON policy\_binding(policy\_uuid);  
CREATE INDEX idx\_binding\_resource ON policy\_binding(resource\_type);  
CREATE INDEX idx\_binding\_principal ON policy\_binding(principal);  
\`\`\`

\*\*Recommendation:\*\* Start with Option 1 (single JSONB column) for flexibility, migrate to Option 2 if we need to query/filter by resource\_type or principal.

\---

\#\# Implementation Considerations

\#\#\# Condition Evaluator

\`\`\`go  
type ConditionEvaluator struct {  
    // Request context available to expressions  
    context map\[string\]interface{}  
}

func (ce \*ConditionEvaluator) Evaluate(condition string) (bool, error) {  
    if condition \== "" {  
        return true, nil // Empty condition always matches  
    }

    // Parse and evaluate expression  
    expr, err := parseExpression(condition)  
    if err \!= nil {  
        return false, err  
    }

    result, err := expr.Eval(ce.context)  
    if err \!= nil {  
        return false, err  
    }

    return result.(bool), nil  
}  
\`\`\`

\#\#\# Policy Evaluation

\`\`\`go  
func EvaluatePolicy(policy \*PolicyContext, request \*Request) (Relation, error) {  
    if policy.Status \== PolicyStatus\_DISABLED {  
        return Relation\_ALLOW, nil  
    }

    // Build evaluation context  
    ctx := map\[string\]interface{}{  
        "request": map\[string\]interface{}{  
            "ip":              request.IP,  
            "key\_uuid":        request.KeyUUID,  
            "key\_fingerprint": request.KeyFingerprint,  
            "product":         request.Product,  
            "route":           request.Route,  
        },  
    }

    evaluator := \&ConditionEvaluator{context: ctx}

    // Evaluate bindings in order (first match wins)  
    for \_, binding := range policy.Bindings {  
        // Check if resource\_type matches  
        if \!matchesResourceType(binding.ResourceType, request.ResourceType) {  
            continue  
        }

        // Check if principal matches  
        if \!matchesPrincipal(binding.Principal, request) {  
            continue  
        }

        // Evaluate condition  
        matched, err := evaluator.Evaluate(binding.Condition)  
        if err \!= nil {  
            log.Warn("Failed to evaluate condition", err)  
            continue  
        }

        if matched {  
            if policy.Status \== PolicyStatus\_DRY\_RUN {  
                log.Info("DRY\_RUN: Would have taken relation", binding.Relation)  
                continue  
            }  
            return binding.Relation, nil  
        }  
    }

    // No bindings matched, use default action  
    return convertActionToRelation(policy.DefaultAction), nil  
}

func matchesResourceType(bindingResource, requestResource string) bool {  
    if bindingResource \== "\*" {  
        return true  
    }  
    return bindingResource \== requestResource  
}

func matchesPrincipal(principal string, request \*Request) bool {  
    parts := strings.Split(principal, ":")  
    if len(parts) \!= 2 {  
        return false  
    }

    principalType := parts\[0\]  
    principalValue := parts\[1\]

    switch principalType {  
    case "org":  
        // For intake policies, org:\* typically matches any request from this organization  
        // The org\_id matching is implicit (policy is already scoped to org\_id)  
        if principalValue \== "\*" {  
            return true  
        }  
        // Could also support org:\<specific\_org\_id\> for multi-org scenarios  
        return request.OrgID \== principalValue

    case "team":  
        // Team-based matching (future extension)  
        if principalValue \== "\*" {  
            return request.TeamID \!= ""  
        }  
        return request.TeamID \== principalValue

    case "user":  
        // User-based matching (future extension)  
        if principalValue \== "\*" {  
            return request.UserID \!= ""  
        }  
        return request.UserID \== principalValue

    default:  
        return false  
    }  
}

// Note: API key UUID, IP address, and other attributes are checked in the condition expression,  
// not in principal matching. For example:  
//   condition: "request.key\_uuid \== 'xxx' && request.ip startsWith '10.0.'"  
\`\`\`

\---

\#\# Expression Language Libraries

For the condition evaluator, consider using existing libraries:

\#\#\# Go Options  
1\. \*\*expr\*\* (github.com/antonmedv/expr)  
   \- Fast, safe expression evaluator  
   \- Supports custom functions  
   \- Good error messages

2\. \*\*govaluate\*\* (github.com/Knetic/govaluate)  
   \- Simple expression evaluator  
   \- Good for basic conditions

3\. \*\*cel-go\*\* (github.com/google/cel-go)  
   \- Common Expression Language (Google's CEL)  
   \- Very powerful, standardized  
   \- Used by K8s ValidatingAdmissionPolicy

\*\*Recommendation:\*\* Use \*\*cel-go\*\* for production (standardized, secure, powerful) or \*\*expr\*\* for faster development iteration.

# SpiceDB explorations

# SpiceDB Authorization Service \- Innovation Week Implementation

## Goal

Build an **intake traffic access control layer** powered by SpiceDB that allows blocking/allowing logs/metrics/traces based on source IP address.

**Innovation Week Demo:**

1. Send intake request → 202 OK  
2. Detect anomaly, create block policy via gRPC  
3. Policy is stored in SpiceDB  
4. Resend request → AuthN sidecar calls CheckIPAllowed → 403 Forbidden

## Service Overview

**Name:** `authz-inno` (or `test-authz` \- innovation week prototype) **Domain:** `aaa` (Authentication, Authorization, Accounting) **Path:** `domains/aaa/apps/apis/authz-inno` **Namespace:** `rapid-aaa`

**Why generic name?** This service is designed to be a general-purpose authorization platform. Starting with intake IP policies, with the potential to expand to other authorization use cases (dashboards, monitors, workflows, etc.) \- providing an option to migrate from existing systems like zoltron in the future.

## Architecture

```
┌─────────────────── Edge / Data Plane ─────────────────────┐
│                                                            │
│  Envoy → AuthN Sidecar → Logs/Metrics Intake             │
│          │                                                 │
│          └─ Calls authz.CheckIPAllowed(ip, api_key)      │
│             Returns 403 if blocked                        │
│                                                            │
└────────────────────────┬───────────────────────────────────┘
                         │ gRPC call
                         ↓
┌──────────────────── Control Plane ────────────────────────┐
│                                                            │
│  ┌──────────────────┐        ┌──────────────┐            │
│  │ SpiceDB Authz    │───────▶│   SpiceDB    │            │
│  │ Service (Rapid)  │        │ (PostgreSQL) │            │
│  │                  │        │              │            │
│  │ - CheckIPAllowed │        │              │            │
│  │ - Manage         │        │              │            │
│  │   IP policies    │        │              │            │
│  └──────────────────┘        └──────────────┘            │
│         ▲                                                  │
│         │                                                  │
│  ┌──────┴──────┐    ┌──────────┐                         │
│  │   gRPC      │    │    UI    │                         │
│  │   Client    │    │ (future) │                         │
│  └─────────────┘    └──────────┘                         │
│                                                            │
└────────────────────────────────────────────────────────────┘
```

**Key Points:**

- **AuthN sidecar** \- Calls authz service to check IPs on intake requests  
- **SpiceDB manages policies** \- CRUD via gRPC  
- **Native IP/CIDR matching** \- Using SpiceDB caveats  
- **Efficient storage** \- One relationship per CIDR block

## SpiceDB Schema

### Innovation Week Scope (Using IP Caveats)

SpiceDB has **native IP address support** in caveats with built-in CIDR matching\!

```
// IP address caveats for native CIDR matching
caveat ip_in_allowlist(user_ip ipaddress, allowed_cidr string) {
  user_ip.in_cidr(allowed_cidr)
}

caveat ip_not_blocked(user_ip ipaddress, blocked_cidr string) {
  !user_ip.in_cidr(blocked_cidr)
}

// Core identity types
definition user {}

definition organization {
    relation member: user
    relation admin: user
}

// Intake IP access control
definition api_key {
    relation org: organization
    relation owner: user

    // IP access control with caveats (native CIDR support)
    relation allowed_ip_range: user with ip_in_allowlist
    relation blocked_ip_range: user with ip_not_blocked

    // Permissions
    permission use_from_ip = allowed_ip_range + blocked_ip_range
    permission manage = owner + org->admin
}
```

### Example Relationships (With IP Caveats)

```
// Org 2 has API key
api_key:key-123#org@organization:org-2

// Block entire subnet (native CIDR support!)
api_key:key-123#blocked_ip_range@user:*[ip_not_blocked]{blocked_cidr:"1.2.3.0/24"}

// Block single IP
api_key:key-123#blocked_ip_range@user:*[ip_not_blocked]{blocked_cidr:"1.2.3.4/32"}

// Allow traffic from corporate network (optional)
api_key:key-123#allowed_ip_range@user:*[ip_in_allowlist]{allowed_cidr:"10.0.0.0/8"}

// Check: Can IP 1.2.3.4 use key-123?
// Pass actual IP as context for caveat evaluation
Check: api_key:key-123#use_from_ip@user:*
  Context: {user_ip: "1.2.3.4"}
Result: DENIED (matches blocked CIDR 1.2.3.0/24)
```

**Benefits of IP Caveats:**

- ✅ Native CIDR matching (no custom parsing)  
- ✅ One relationship per CIDR block (efficient)  
- ✅ Supports both single IPs (/32) and ranges (/24, /16, etc.)  
- ✅ Built-in `in_cidr()` function

### Future Expansion (Post-Innovation Week)

If expanded to handle resource authorization:

```
// Example: Resource authorization (dashboards, monitors, etc.)
definition dashboard {
    relation viewer: user | team#member
    relation editor: user | team#member
    permission view = viewer + editor
    permission edit = editor
}

// Similar patterns could be added for: monitor, workflow, notebook, slo, etc.
```

## gRPC API

### Innovation Week RPCs

```protobuf
syntax = "proto3";
package authz;

service AuthzService {
    // ========== Innovation Week Scope ==========

    // Manage IP blocklist/allowlist
    rpc AddBlockedIP(AddBlockedIPRequest) returns (AddBlockedIPResponse);
    rpc RemoveBlockedIP(RemoveBlockedIPRequest) returns (RemoveBlockedIPResponse);
    rpc AddAllowedIP(AddAllowedIPRequest) returns (AddAllowedIPResponse);
    rpc RemoveAllowedIP(RemoveAllowedIPRequest) returns (RemoveAllowedIPResponse);

    // Query policies
    rpc GetIPPolicy(GetIPPolicyRequest) returns (GetIPPolicyResponse);
    rpc ListAllPolicies(ListAllPoliciesRequest) returns (ListAllPoliciesResponse);

    // Check if IP is allowed (for testing/validation)
    rpc CheckIPAllowed(CheckIPAllowedRequest) returns (CheckIPAllowedResponse);

    // ========== Future: Generic Authorization ==========
    // rpc CheckPermission(...)
    // rpc WriteRelationships(...)
    // rpc LookupResources(...)
}

// ========== Innovation Week Messages ==========

message AddBlockedIPRequest {
    string org_uuid = 1;
    string api_key_id = 2;          // Optional: scope to specific key
    string cidr = 3;                // CIDR notation: "1.2.3.4/32" or "1.2.3.0/24"
    string reason = 4;              // Why blocked (audit trail)
    string created_by_user = 5;    // Who created this rule
    int64 ttl_seconds = 6;          // Optional: auto-expire (can combine with expiration caveat)
}

message AddBlockedIPResponse {
    string policy_id = 1;           // Unique ID for this rule
    int64 created_at = 2;           // Unix timestamp
}

message RemoveBlockedIPRequest {
    string org_uuid = 1;
    string api_key_id = 2;
    string cidr = 3;                // Must match exactly what was added
}

message RemoveBlockedIPResponse {
    bool success = 1;
}

message AddAllowedIPRequest {
    string org_uuid = 1;
    string api_key_id = 2;
    string cidr = 3;                // CIDR notation
    string created_by_user = 4;
}

message AddAllowedIPResponse {
    string policy_id = 1;
    int64 created_at = 2;
}

message GetIPPolicyRequest {
    string org_uuid = 1;
    string api_key_id = 2;          // Optional: get for specific key
}

message IPPolicyRule {
    string cidr = 1;                // CIDR notation
    bool is_blocked = 2;            // true = blocklist, false = allowlist
    string reason = 3;
    string created_by = 4;
    int64 created_at = 5;
    int64 expires_at = 6;           // 0 = never expires
}

message GetIPPolicyResponse {
    repeated IPPolicyRule rules = 1;
}

message ListAllPoliciesRequest {
    string org_uuid = 1;            // Optional: filter by org
}

message ListAllPoliciesResponse {
    repeated IPPolicyRule rules = 1;
}

message CheckIPAllowedRequest {
    string org_uuid = 1;
    string api_key_id = 2;
    string source_ip = 3;           // Actual client IP (passed as caveat context)
}

message CheckIPAllowedResponse {
    bool allowed = 1;
    string reason = 2;              // Why blocked/allowed
    string matched_cidr = 3;        // Which CIDR block matched
}
```

## Implementation Plan \- Innovation Week

### Day 1: Service Setup & Foundation ✅ COMPLETED

**Goal:** Running service skeleton with SpiceDB connection

- [x] Run `rapid create -d aaa -s authz-inno` to scaffold service (innovation week prototype)  
- [x] Set up local SpiceDB (docker-compose with healthcheck)  
- [x] Define SpiceDB schema (`schema/authz.zed`) with IP caveats  
- [x] Implement SpiceDB client wrapper (custom bearer token auth)  
- [x] Define all 7 gRPC RPCs in protobuf  
- [x] Generate protobuf code with Bazel  
- [x] Implement stub service handlers  
- [x] Test with grpcurl (CheckIPAllowed, AddBlockedIP working)

**Deliverable:** ✅ Service running on port 8080, connected to SpiceDB, responding to gRPC calls

**Key Implementation Details:**

- **SpiceDB**: Running in Docker on localhost:50051 with PostgreSQL backend  
- **Dependencies**: Used `authzed-go` client, avoided grpcutil to stay on Go 1.24.10  
- **Authentication**: Implemented custom bearer token auth (15 lines) instead of grpcutil  
- **Service Structure**:  
  - `authzpb/authz.proto` \- Full service definition (7 RPCs)  
  - `internal/spicedb/client.go` \- SpiceDB client wrapper  
  - `internal/service/authz.go` \- Stub implementations with logging  
  - `main.go` \- Rapid server with SpiceDB initialization  
- **Status**: Service healthy, SpiceDB connected, stub methods returning test responses

### Day 2: Core IP Policy APIs

**Goal:** Functional CRUD APIs for IP policies using caveats

- [ ] Implement `AddBlockedIP` RPC  
      - Validate CIDR format  
      - Write relationship with IP caveat to SpiceDB  
      - Return policy ID  
- [ ] Implement `RemoveBlockedIP` RPC  
- [ ] Implement `GetIPPolicy` RPC (read relationships with caveats)  
- [ ] Implement `CheckIPAllowed` RPC (pass IP as context)  
- [ ] Test with grpcurl (pass caveat context)

**Deliverable:** Can add/remove/query IP policies via gRPC, SpiceDB handles CIDR matching

### Day 3: Additional Policy Management

**Goal:** Complete CRUD operations and listing

- [ ] Implement `AddAllowedIP` RPC (for allowlist support)  
- [ ] Implement `RemoveAllowedIP` RPC  
- [ ] Implement `ListAllPolicies` RPC (see all policies across keys/orgs)  
- [ ] Add policy metadata tracking (creation time, created\_by, reason)  
- [ ] Test bulk operations  
- [ ] Add metrics/logging

**Deliverable:** Full policy management suite working

### Day 4: AuthN Sidecar Integration

**Goal:** AuthN sidecar calls authz service to block IPs

- [ ] Update AuthN sidecar code  
      - Add authz service gRPC client  
      - Call CheckIPAllowed for each intake request  
      - Return 403 if blocked  
- [ ] Handle authz service failures gracefully  
      - Timeout configuration  
      - Fallback behavior (fail open vs fail closed?)  
      - Circuit breaker pattern  
- [ ] Add metrics  
      - Blocked request count  
      - authz service latency  
      - Error rates  
- [ ] End-to-end testing with real intake requests

**Deliverable:** Intake requests blocked based on SpiceDB policies

### Day 5: Testing, Performance & Demo Prep

**Goal:** Production-ready and demo-ready

- [ ] Performance testing  
      - CheckIPAllowed latency (target: \< 10ms)  
      - Load testing (concurrent requests)  
      - Large CIDR list performance  
- [ ] Edge cases & error handling  
      - Invalid CIDR formats  
      - Overlapping CIDRs  
      - AuthN sidecar failure scenarios  
- [ ] Deploy to staging  
- [ ] Demo script preparation  
      - Block malicious IP → verify 403  
      - Allow corporate network  
      - Show policy management  
- [ ] Documentation  
      - API documentation  
      - Setup guide  
      - AuthN sidecar integration guide  
- [ ] (Optional) HTTP endpoints  
- [ ] Presentation materials

**Deliverable:** Full end-to-end demo working, deployed to staging

## Service Structure (Actual)

```
domains/aaa/apps/apis/authz-inno/
├── main.go                         # Service entrypoint (Rapid setup)
├── BUILD.bazel                     # Bazel build config
├── rapid.json                      # Rapid config
├── service.datadog.yaml           # Service metadata
│
├── authzpb/
│   ├── authz.proto                 # Protobuf definitions (all 7 RPCs)
│   ├── BUILD.bazel                 # Protobuf build rules
│   └── (generated .pb.go files)    # Generated by Bazel
│
├── internal/
│   ├── spicedb/
│   │   ├── client.go               # SpiceDB client wrapper
│   │   │                           # - Custom bearer token auth
│   │   │                           # - Wraps authzed-go client
│   │   └── BUILD.bazel
│   │
│   └── service/
│       ├── authz.go                # gRPC service implementation
│       │                           # - All 7 RPC handlers (stubs for Day 1)
│       │                           # - Structured logging
│       └── BUILD.bazel
│
├── schema/
│   └── authz.zed                   # SpiceDB schema with IP caveats
│
├── config/                         # Rapid config directory
│
└── docker-compose.yml              # Local SpiceDB + PostgreSQL
```

## Local Development Setup

### SpiceDB docker-compose.yml

```
version: '3.8'

services:
  postgres:
    image: postgres:15
    environment:
      POSTGRES_USER: spicedb
      POSTGRES_PASSWORD: spicedb
      POSTGRES_DB: spicedb
    ports:
      - "5432:5432"
    volumes:
      - spicedb-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U spicedb"]
      interval: 5s
      timeout: 5s
      retries: 5

  spicedb:
    image: authzed/spicedb:latest
    command: serve
    environment:
      SPICEDB_GRPC_PRESHARED_KEY: "devkey"
      SPICEDB_DATASTORE_ENGINE: "postgres"
      SPICEDB_DATASTORE_CONN_URI: "postgresql://spicedb:spicedb@postgres:5432/spicedb?sslmode=disable"
    ports:
      - "50051:50051"  # gRPC
      - "8443:8443"    # HTTP
    depends_on:
      postgres:
        condition: service_healthy  # Wait for postgres to be ready

volumes:
  spicedb-data:
```

**Note:** The healthcheck ensures SpiceDB waits for PostgreSQL to be ready before starting.

### Running Locally

```shell
# 1. Start SpiceDB (from authz-inno directory)
cd /Users/erica.zhong/go/src/github.com/DataDog/dd-source/domains/aaa/apps/apis/authz-inno
docker-compose up -d

# Verify containers are running
docker-compose ps
# Should show both postgres (healthy) and spicedb (up)

# 2. Run the service (from dd-source root)
cd /Users/erica.zhong/go/src/github.com/DataDog/dd-source
rapid run -d aaa -s authz-inno -v

# Service should start on localhost:8080
# Look for: "Connected to SpiceDB endpoint=localhost:50051"
#           "starting server ... addr=127.0.0.1:8080"

# 3. Test with grpcurl
# Block a CIDR range
grpcurl --plaintext \
  -d '{
    "org_uuid": "org-123",
    "api_key_id": "key-456",
    "cidr": "1.2.3.0/24",
    "reason": "Malicious activity detected"
  }' \
  localhost:8080 authzpb.AuthzService/AddBlockedIP

# Response: {"policyId": "test-policy-id"}

# Check if specific IP is allowed (Day 1: returns stub response)
grpcurl --plaintext \
  -d '{
    "org_uuid": "org-123",
    "api_key_id": "key-456",
    "source_ip": "1.2.3.4"
  }' \
  localhost:8080 authzpb.AuthzService/CheckIPAllowed

# Response: {"allowed": true, "reason": "Not implemented yet"}
```

**Day 1 Status:** Both RPCs return stub responses. Day 2 will implement actual SpiceDB integration.

## AuthN Sidecar Integration

### How It Works

The AuthN sidecar is a Go service that runs alongside intake services and handles authentication. We'll add IP access control by calling the authz service.

```go
// In AuthN sidecar
func (s *AuthNSidecar) ValidateIntakeRequest(ctx context.Context, req *IntakeRequest) error {
    // 1. Existing authentication logic
    apiKey, err := s.authenticateAPIKey(req.APIKey)
    if err != nil {
        return err
    }

    // 2. NEW: Check IP access control
    ipCheckResult, err := s.authzClient.CheckIPAllowed(ctx, &authzpb.CheckIPAllowedRequest{
        OrgUuid:   apiKey.OrgUUID,
        ApiKeyId:  apiKey.ID,
        SourceIp:  req.ClientIP, // From Envoy headers
    })

    if err != nil {
        // Handle authz service failure
        // Option 1: Fail open (allow request, log error)
        // Option 2: Fail closed (block request)
        log.Error("authz service error", "error", err)
        // For MVP: fail open with metric
        s.metrics.IncrementAuthzServiceErrors()
        return nil // Allow request
    }

    if !ipCheckResult.Allowed {
        s.metrics.IncrementBlockedRequests(apiKey.OrgUUID, req.ClientIP)
        return &ForbiddenError{
            StatusCode: 403,
            Message:    ipCheckResult.Reason,
            IP:         req.ClientIP,
        }
    }

    // 3. Continue with request
    return nil
}
```

### AuthN Sidecar Changes

**Files to modify:**

- `domains/aaa/apps/authenticator/internal/intake/handler.go` \- Add CheckIPAllowed call  
- `domains/aaa/apps/authenticator/internal/authz/client.go` \- New authz gRPC client  
- `domains/aaa/apps/authenticator/cmd/main.go` \- Initialize authz client

**Configuration:**

```
# authenticator config
authz:
  enabled: true
  endpoint: "authz.rapid-aaa.svc.cluster.local:8080"
  timeout: "50ms"
  fail_open: true  # Allow requests if authz service is down
```

## Implementation Examples

### Adding a Blocked IP with Caveat

```go
func (s *AuthzService) AddBlockedIP(ctx context.Context, req *AddBlockedIPRequest) (*AddBlockedIPResponse, error) {
    // Validate CIDR format
    _, _, err := net.ParseCIDR(req.Cidr)
    if err != nil {
        return nil, status.Errorf(codes.InvalidArgument, "invalid CIDR: %v", err)
    }

    // Write relationship with IP caveat
    _, err = s.spicedbClient.WriteRelationships(ctx, &v1.WriteRelationshipsRequest{
        Updates: []*v1.RelationshipUpdate{{
            Operation: v1.RelationshipUpdate_OPERATION_CREATE,
            Relationship: &v1.Relationship{
                Resource: &v1.ObjectReference{
                    ObjectType: "api_key",
                    ObjectId:   req.ApiKeyId,
                },
                Relation: "blocked_ip_range",
                Subject: &v1.SubjectReference{
                    Object: &v1.ObjectReference{
                        ObjectType: "user",
                        ObjectId:   "*",
                    },
                },
                OptionalCaveat: &v1.ContextualizedCaveat{
                    CaveatName: "ip_not_blocked",
                    Context: &structpb.Struct{
                        Fields: map[string]*structpb.Value{
                            "blocked_cidr": structpb.NewStringValue(req.Cidr),
                        },
                    },
                },
            },
        }},
    })

    if err != nil {
        return nil, err
    }

    return &AddBlockedIPResponse{
        PolicyId:  uuid.New().String(),
        CreatedAt: time.Now().Unix(),
    }, nil
}
```

### Checking IP with Caveat Evaluation

```go
func (s *AuthzService) CheckIPAllowed(ctx context.Context, req *CheckIPAllowedRequest) (*CheckIPAllowedResponse, error) {
    result, err := s.spicedbClient.CheckPermission(ctx, &v1.CheckPermissionRequest{
        Resource: &v1.ObjectReference{
            ObjectType: "api_key",
            ObjectId:   req.ApiKeyId,
        },
        Permission: "use_from_ip",
        Subject: &v1.SubjectReference{
            Object: &v1.ObjectReference{
                ObjectType: "user",
                ObjectId:   "*",
            },
        },
        Context: &structpb.Struct{
            Fields: map[string]*structpb.Value{
                "user_ip": structpb.NewStringValue(req.SourceIp), // Pass actual IP
            },
        },
    })

    if err != nil {
        return nil, err
    }

    return &CheckIPAllowedResponse{
        Allowed: result.Permissionship == v1.CheckPermissionResponse_PERMISSIONSHIP_HAS_PERMISSION,
    }, nil
}
```

## Key Decisions for Innovation Week

### 1\. Default Policy Behavior

**Decision:** Default allow, explicit block

- No allowlist configured → all IPs allowed  
- Blocklist takes precedence over allowlist

**Rationale:** Easier rollout, doesn't break existing traffic

### 2\. Policy Scope

**Decision:** Per API key (optional) or per org

- Can block IP for entire org: `org:org-2#blocked_ip@ip:1.2.3.4`  
- Or for specific key: `api_key:key-123#blocked_ip@ip:1.2.3.4`

**Rationale:** Flexibility for different use cases

### 3\. HTTP Endpoints

**Decision:** gRPC only for innovation week, add HTTP if time permits

**Rationale:** Focus on core functionality first

## Future Phases (Brief Overview)

### Phase 2: Resource Authorization (Post-Innovation Week) \- Optional Migration Path

If we choose to expand beyond intake policies:

- Extend schema for resource types (dashboard, monitor, workflow, etc.)  
- Implement generic `CheckPermission` API  
- Option to build data migration tool (e.g., from zoltron if desired)  
- Could run in shadow mode to validate behavior  
- Gradual adoption as needed

### Phase 3: Advanced Features

- Datasets and product filtering  
- Time-based access (caveats)  
- Rate limiting based on relationships  
- Audit logging and policy versioning  
- GraphQL API for frontend

### Phase 4: Performance Optimization

- Caching layer (AuthN sidecar local cache)  
- Bulk policy operations  
- Policy change notifications  
- Read replicas for CheckIPAllowed

## Success Metrics for Innovation Week

- [ ] gRPC authz service deployed and running  
- [ ] Can add/remove/query IP policies  
- [ ] SpiceDB caveat-based CIDR matching working  
- [ ] `CheckIPAllowed` API functional (\< 10ms P99)  
- [ ] AuthN sidecar integrated and calling authz service  
- [ ] End-to-end demo: block IP → 403 on intake request  
- [ ] Service deployed to staging  
- [ ] gRPC APIs tested and documented  
- [ ] Demo scenarios prepared  
- [ ] (Bonus) HTTP endpoints working  
- [ ] (Bonus) Basic UI for policy management

## Questions to Resolve

1. **Default policy** \- org-level or per-API-key?  
2. **TTL support** \- needed for MVP?  
3. **Which org/API keys to test with?** \- staging org 2?  
4. **IPv6 support** \- needed for demo?  
5. **Failure mode** \- fail open (allow) or fail closed (block) if authz service is down?  
6. **Latency target** \- acceptable P99 for CheckIPAllowed? (suggest \< 10ms)  
7. **AuthN sidecar deployment** \- how to deploy changes to staging?

## Day 1 Completed\! 🚀

### Next: Day 2 Implementation

- Implement actual SpiceDB relationship creation in `AddBlockedIP`  
- Implement actual permission check in `CheckIPAllowed`  
- Test with real CIDR matching using IP caveats  
- Verify SpiceDB's native `in_cidr()` function works correctly

# Policy Engine exploration

# IP-Based Restriction Policies \- Innovation Week Implementation

## Goal

Build an **IP-based access control system** using CEL (Common Expression Language) that works for:

1. **Intake traffic access control** (IP blocking/allowlisting \- PRIMARY)  
2. **Future: GRACE resource authorization** (can extend to other attributes easily)

## Architecture Decision: CEL Evaluator

**Chosen Approach**: CEL (Common Expression Language) for attribute-based access control

**Why CEL?**

- **Future-proof**: Can extend to country, user-agent, time-based rules without rewrites  
- **Flexible**: Users can express complex attribute logic  
- **Standard**: Industry-proven (Kubernetes, Envoy, Google Cloud)  
- **Fast enough**: \~20μs evaluation (still 10x under 200μs budget)  
- **No migration needed**: Start with IP, easily add more attributes later

**Why not hand-rolled or SpiceDB?**

- Hand-rolled would be 15μs faster but require rewrites when users want more attributes  
- SpiceDB is for relationships (user→team→resource), not attributes (IP, country, etc.)

**Key Insight:** Zoltron restriction policies **already stream to FRAMES** \- we just need to store CEL expressions in RelationTuples and evaluate them\!

**Innovation Week Demo:**

1. Create IP block policy via Zoltron API (CEL expression)  
2. Policy stored as RelationTuples → automatically streams to FRAMES  
3. AuthN sidecar evaluates with CEL engine (\~20μs)  
4. Blocked request → 403 Forbidden

**Critical Performance Requirement:**

- **Traffic volume:** 7M requests/second  
- **Latency budget:** 200μs P99 (CEL achieves \~20μs \- 10x under budget\!)  
- **Architecture:** Zoltron → FRAMES → CEL evaluation (flexible, fast enough)

## Architecture

![][image3]

**Key Points:**

- **Zoltron** \- Already streams restriction policies to FRAMES ✅  
- **FRAMES** \- Already distributes to all pods ✅  
- **We just need** \- Store CEL expressions in RelationTuples \+ add CEL evaluator in AuthN sidecar

## Reusing Existing Zoltron Infrastructure

**Key Insight**: Zoltron already has everything we need\! No new protos required.

### Existing Proto (Already in Zoltron)

```protobuf
// This already exists in Zoltron!
message RelationTuple {
    string subject_type = 1;  // "api_key"
    string subject_id = 2;    // "key-123"
    string relation = 3;      // "access_policy"
    string object_type = 4;   // "cel_expression"
    string object_id = 5;     // "expr-uuid"
    string condition = 6;     // CEL expression: "!ip(request.source_ip).in_cidr('192.168.1.0/24')"
}
```

**That's it\!** This tuple format stores CEL expressions:

- ✅ Subject: Which API key  
- ✅ Relation: "access\_policy"  
- ✅ Condition: CEL expression to evaluate

### Example Data

**Stored in Zoltron database:**

```sql
subject_type | subject_id | relation      | object_type     | object_id | condition
-------------|------------|---------------|-----------------|-----------|------------------------------------------
api_key      | key-123    | access_policy | cel_expression  | expr-1    | !ip(request.source_ip).in_cidr('192.168.1.0/24')
api_key      | key-456    | access_policy | cel_expression  | expr-2    | request.country != 'CN' && !ip(request.source_ip).in_cidr('1.2.3.0/24')
```

**Flows to FRAMES:** Same format, already streaming\!

**Parsed by authenticator-intake:**

```go
// Read RelationTuple from FRAMES
tuple := &RelationTuple{
    SubjectType: "api_key",
    SubjectID:   "key-123",
    Relation:    "access_policy",
    ObjectType:  "cel_expression",
    ObjectID:    "expr-1",
    Condition:   "!ip(request.source_ip).in_cidr('192.168.1.0/24')",
}

// Compile CEL expression
ast, _ := celEnv.Compile(tuple.Condition)
prg, _ := celEnv.Program(ast)

// Store compiled program
evaluator.programs[tuple.SubjectID] = prg
```

**No new protos needed\!** ✅

## How Org ID Resolution Works

### authenticator-intake Already Has api\_key → org Mapping\!

**Key Discovery:** The authenticator-intake already resolves API keys to org IDs as part of normal authentication flow.

**From `dd-go/model/api_key.go`:**

```go
type EdgeAuthResult struct {
    OrgID          int32   // ✅ Org ID available here!
    Fingerprint    string
    UUID           string
    Status         APIKeyAuthenticationStatus
    Type           CredentialTypeEnum
    LastModifiedAt *time.Time
}
```

**Evaluation Flow:**

```go
func (s *AuthNSidecar) ValidateIntakeRequest(req *IntakeRequest) error {
    // Step 1: Resolve API key (existing authentication flow)
    authResult := s.credentialResolver.Resolve(ctx, req.APIKey)
    orgID := authResult.OrgID          // ✅ Org ID from existing auth!
    apiKeyUUID := authResult.UUID

    // Step 2: Load policies from FRAMES using org context
    // FRAMES is keyed by: RestrictionPolicyKey{OrgUUID, ResourceType, ResourceID}
    ctx := RequestContext{
        SourceIP: req.ClientIP,
    }

    // Step 3: CEL evaluator checks both org-wide and key-specific
    // The evaluator internally looks up:
    //   - (orgID, "api_key", "*")      → org-wide policy
    //   - (orgID, "api_key", apiKeyID) → key-specific policy
    decision, err := s.celEvaluator.CheckAccess(orgID, apiKeyUUID, &ctx)

    if !decision.Allowed {
        return &ForbiddenError{StatusCode: 403, Message: decision.Reason}
    }
    return nil
}
```

**FRAMES Context Structure:**

```go
RestrictionPolicyKey {
    OrgUUID:      orgID,        // From EdgeAuthResult
    ResourceType: "api_key",
    ResourceID:   "*" or "key-456"
}
```

**Benefits:**

- ✅ **No extra lookups needed** \- org ID comes from existing auth flow  
- ✅ **Zero additional latency** \- already resolved before policy check  
- ✅ **Natural integration** \- fits perfectly with current architecture  
- ✅ **Efficient FRAMES lookup** \- can query policies by org context

## Implementation Plan \- Innovation Week

### Day 1: Extend Existing Model for API Keys

**Goal:** Add "api-key" resource type and new API endpoint with explicit condition support

- [x] Research existing Zoltron implementation (COMPLETED)  
- [x] Choose architecture approach (Reuse existing model) (COMPLETED)  
- [x] Add "api-key" as valid resource type (COMPLETED)  
      - Created `domains/aaa/libs/access/namespace/yaml/api-key.yaml`  
      - Defined relations: `allowed_ip` (whitelist) and `blocked_ip` (blacklist)  
      - Updated `domains/aaa/libs/access/namespace/BUILD.bazel` to include new YAML  
- [x] Build and verify changes compile (COMPLETED)  
      - `bazel build //domains/aaa/libs/access/namespace:go_default_library` ✅  
- [ ] Create new HTTP endpoint with explicit condition support  
      - New endpoint: `POST /api/v2/restriction_policy/{resourceID}` (v2 for new format)  
      - New request structs supporting `conditions` field  
      - Translation layer: convert conditions → principals for storage  
- [ ] Implement backend translation logic  
      - Input: `{expression: "...", reason: "..."}`  
      - Output: `"condition_rule:generated-id:expression"` principal  
- [ ] Test with sample API key policy  
- [ ] Verify policy appears in FRAMES  
      - Check FRAMES inspector: [https://logs-admin.us1.staging.dog/web/\#/context/inspector/ZOLTRON\_RESTRICTION\_POLICIES\_CONTEXT](https://logs-admin.us1.staging.dog/web/#/context/inspector/ZOLTRON_RESTRICTION_POLICIES_CONTEXT)

**Deliverable:** Clean API for creating API key policies with explicit CEL conditions

### Day 2: CEL Evaluator in AuthN Sidecar

**Goal:** Evaluate IP policies with CEL expressions

- [ ] Create CEL evaluator (300 lines)  
      - Initialize CEL environment with custom IP functions  
      - Map of API key → compiled CEL program \+ metadata  
      - Load and compile expressions from FRAMES  
- [ ] Load RelationTuples from FRAMES (libcontext)  
- [ ] Parse RelationTuples and compile CEL expressions  
- [ ] Parse mode from object\_id (disabled/dry\_run/enforced)  
- [ ] Implement evaluation logic  
      - Build request context (source IP, etc.)  
      - Evaluate CEL expression  
      - Handle three policy modes (disabled/dry\_run/enforced)  
      - Return AccessDecision with dry\_run metadata  
- [ ] Add metrics for policy evaluation (by mode)  
- [ ] Test with various CEL expressions  
- [ ] Test all three modes (disabled/dry\_run/enforced)

**Deliverable:** AuthN sidecar can evaluate IP policies in \~20μs with CEL flexibility and three-state policy modes

### Day 3: Intake Use Cases & Integration

**Goal:** Implement IP blocking with CEL evaluator

- [ ] Create IP block policies in Zoltron (generates CEL expressions)  
- [ ] Test CEL expressions  
      - Simple IP blocking: `!ip(request.source_ip).in_cidr('1.2.3.0/24')`  
      - Multiple CIDRs: `!(ip(request.source_ip).in_cidr('1.2.3.0/24') || ip(request.source_ip).in_cidr('10.0.0.0/8'))`  
      - Complex rules (demo future capabilities)  
- [ ] Test three policy modes  
      - Create policy with `mode: "disabled"` → verify no evaluation  
      - Update to `mode: "dry_run"` → verify evaluates but doesn't block  
      - Check logs show "\[DRY\_RUN\] Would have BLOCKED"  
      - Verify metrics track by mode  
      - Update to `mode: "enforced"` → verify blocks  
- [ ] Integration with authenticator-intake  
      - Load policies from FRAMES on startup  
      - Watch for incremental updates  
      - Wire up in request handler with AccessDecision  
- [ ] Performance testing (verify \~20μs across all modes)  
- [ ] Test mode transitions (disabled → dry\_run → enforced)

**Deliverable:** IP-based access control working end-to-end with CEL flexibility and three-state policy modes

### Day 4: Production Rollout & Testing

**Goal:** Enable in production with three-state policy modes

- [ ] Deploy to production with initial policies in dry run mode  
      - Create production IP policies with `mode: "dry_run"`  
      - Run IP checks but don't enforce (per-policy)  
      - Log results and metrics  
      - Validate no false positives  
- [ ] Gradual rollout  
      - Deploy to 1% of pods → validate no errors  
      - Deploy to 10% of pods → validate performance  
      - Deploy to 100% of pods → full validation  
      - Monitor dry run metrics to see what would be blocked  
- [ ] Promote tested policies to enforcement  
      - Update `mode: "enforced"` for validated policies  
      - Monitor blocked request rates  
      - Rollback capability (disabled → dry\_run → enforced transitions)  
- [ ] Test temporary disable functionality  
      - Disable problematic policy with `mode: "disabled"`  
      - Fix issue, re-enable via dry\_run, then enforce  
- [ ] Create policy management UI (optional)  
- [ ] Monitoring and alerting setup  
      - Policy evaluation latency by mode  
      - Dry run "would block" rates by policy  
      - Actual blocked request rates by policy  
      - Mode distribution metrics  
      - Error rates

**Deliverable:** Three-state policy modes running at scale, safe state transitions validated

### Day 5: Load Testing & Demo

**Goal:** Validate at scale and demo

- [ ] Load testing at 7M req/s  
- [ ] Verify \~20μs P99 with CEL evaluation (10x under 200μs budget\!)  
- [ ] Test policy updates (propagation speed \~5s)  
- [ ] Edge case testing  
      - Invalid CEL expressions (handle gracefully)  
      - Missing policies (default allow)  
      - Complex expressions  
- [ ] Demo preparation  
      - Create IP block policy via Zoltron API (generates CEL)  
      - Show policy appears in FRAMES  
      - Show AuthN sidecar blocking IP  
      - Demo flexibility: easily add country/user-agent rules  
      - Live dashboard with metrics  
- [ ] Documentation and runbook

**Deliverable:** Production-ready IP blocking system with CEL flexibility and demo

## Simplified API Implementation

### Domain-Specific Endpoint (Clean UX)

Instead of generic restriction policy format, create a simple IP policy endpoint that generates CEL expressions:

```go
// New endpoint in Zoltron
POST /v1/api-keys/{key_id}/ip-policies

// Request body (simple!)
{
  "blocked_cidrs": ["192.168.1.0/24", "10.0.0.0/8"],
  "allowed_cidrs": ["8.8.8.0/24"],
  "mode": "enforced"  // Optional: "disabled" | "dry_run" | "enforced" (default: "enforced")
}
```

### Translation to RelationTuples with CEL (Backend)

```go
func (s *PolicyService) CreateIPPolicy(apiKeyID string, req *IPPolicyRequest) error {
    // Generate CEL expression from CIDRs
    var conditions []string

    // Block conditions
    for _, cidr := range req.BlockedCIDRs {
        conditions = append(conditions, fmt.Sprintf("ip(request.source_ip).in_cidr('%s')", cidr))
    }

    // Build final expression
    var celExpr string
    if len(conditions) > 0 {
        // Block if IP matches any blocked CIDR
        celExpr = fmt.Sprintf("!(%s)", strings.Join(conditions, " || "))
    }

    // Generate object_id with mode metadata embedded
    // Format: "expr-{uuid}-{mode}" where mode is: disabled | dryrun | enforced
    baseID := fmt.Sprintf("expr-%s", uuid.New().String())
    objectID := fmt.Sprintf("%s-%s", baseID, req.Mode)

    // Create RelationTuple with CEL expression
    tuple := RelationTuple{
        SubjectType: "api_key",
        SubjectID:   apiKeyID,
        Relation:    "access_policy",
        ObjectType:  "cel_expression",
        ObjectID:    objectID,  // Dry run metadata encoded here
        Condition:   celExpr,
    }

    // Store using existing RelationTuple service
    return s.tupleService.CreateTuple(ctx, tuple)
}
```

**Benefits:**

- ✅ Clean, domain-specific API for users  
- ✅ Stores as RelationTuples (existing table) with CEL in condition field  
- ✅ Flows through existing FRAMES provider  
- ✅ No new infrastructure needed\!  
- ✅ Can easily extend to other attributes later (just modify CEL generation)

## How to Create IP Policies

### Two Endpoints for Different Scopes

**Org-wide policy** (applies to all API keys):

```
POST /v1/orgs/{org_uuid}/ip-policies
```

Creates `api_key:*` policy \- affects all API keys in the org

**Key-specific policy** (applies to one API key):

```
POST /v1/api-keys/{key_id}/ip-policies
```

Creates `api_key:{key_id}` policy \- affects only that specific key

**When to use which:**

- Use **org-wide** for: blocking malicious IPs/ranges for entire org, enforcing corporate network requirements  
- Use **key-specific** for: special exceptions, different requirements per service/team

### Request Format (Simple JSON)

```json
{
  "blocked_cidrs": [
    "192.168.1.0/24",
    "10.0.0.0/8"
  ],
  "allowed_cidrs": [
    "8.8.8.0/24"
  ],
  "dry_run": false
}
```

**Fields:**

- `blocked_cidrs`: List of CIDR blocks to block  
- `allowed_cidrs`: List of CIDR blocks to allow (optional)  
- `mode`: Policy enforcement mode (optional, default: `"enforced"`)  
  - `"disabled"` \- Policy doesn't evaluate at all (dormant)  
  - `"dry_run"` \- Policy evaluates but never blocks (testing/shadow mode)  
  - `"enforced"` \- Policy evaluates and blocks (full enforcement)

**That's it\!** Just list the CIDRs.

**What happens behind the scenes:**

1. API receives simple JSON  
2. Backend generates CEL expression:

```javascript
!(ip(request.source_ip).in_cidr('192.168.1.0/24') ||
  ip(request.source_ip).in_cidr('10.0.0.0/8'))
```

3. Stores in RelationTuple condition field  
4. FRAMES streams to all pods  
5. AuthN sidecar compiles and evaluates CEL

**Benefits:**

- ✅ Extremely simple \- just a list of CIDRs  
- ✅ Backend handles CEL generation automatically  
- ✅ Automatic FRAMES streaming  
- ✅ Type-safe (validates CIDR format)  
- ✅ Future-proof (easy to extend to other attributes)

### Example 1: Org-Wide Block (All API Keys)

Block a malicious IP range for the entire organization:

```shell
curl -X POST http://localhost:8080/v1/orgs/org-123/ip-policies \
  -H "Content-Type: application/json" \
  -H "DD-API-KEY: {org_api_key}" \
  -H "DD-APPLICATION-KEY: {app_key}" \
  -d '{
    "blocked_cidrs": ["1.2.3.0/24"],
    "mode": "enforced"
  }'
```

**Creates:** `api_key:*` policy (applies to ALL keys in org-123)

**Generated CEL expression:**

```javascript
!ip(request.source_ip).in_cidr('1.2.3.0/24')
```

### Example 2: Key-Specific Block (Single API Key)

Block IPs for one specific API key:

```shell
curl -X POST http://localhost:8080/v1/api-keys/key-456/ip-policies \
  -H "Content-Type: application/json" \
  -d '{
    "blocked_cidrs": ["10.0.0.0/8"],
    "mode": "enforced"
  }'
```

**Creates:** `api_key:key-456` policy (applies only to key-456)

**Generated CEL expression:**

```javascript
!ip(request.source_ip).in_cidr('10.0.0.0/8')
```

### Example 3: Org-Wide Allowlist (Corporate Network Only)

Only allow requests from corporate network (all API keys):

```shell
curl -X POST http://localhost:8080/v1/orgs/org-123/ip-policies \
  -H "Content-Type: application/json" \
  -d '{
    "allowed_cidrs": [
      "10.0.0.0/8",
      "172.16.0.0/12"
    ],
    "mode": "enforced"
  }'
```

**Creates:** `api_key:*` policy

**Generated CEL expression:**

```javascript
ip(request.source_ip).in_cidr('10.0.0.0/8') ||
ip(request.source_ip).in_cidr('172.16.0.0/12')
```

### Example 4: Combined Allowlist \+ Blocklist

Allow corporate network but block specific problem subnet:

```shell
curl -X POST http://localhost:8080/v1/orgs/org-123/ip-policies \
  -H "Content-Type: application/json" \
  -d '{
    "allowed_cidrs": ["10.0.0.0/8"],
    "blocked_cidrs": ["10.0.1.0/24"],
    "mode": "enforced"
  }'
```

**Logic**: Allow 10.0.0.0/8 EXCEPT 10.0.1.0/24 (blocked takes precedence)

**Generated CEL expression:**

```javascript
ip(request.source_ip).in_cidr('10.0.0.0/8') &&
!ip(request.source_ip).in_cidr('10.0.1.0/24')
```

### Example 5: Hierarchical \- Org-Wide \+ Key-Specific

**Scenario:** Org blocks 192.168.0.0/16 for all keys, but key-789 has additional restrictions

**Step 1: Org-wide policy**

```shell
POST /v1/orgs/org-123/ip-policies
{
  "blocked_cidrs": ["192.168.0.0/16"],
  "mode": "enforced"
}
```

→ Creates `api_key:*` \- blocks 192.168.0.0/16 for ALL keys

**Step 2: Key-specific additional block**

```shell
POST /v1/api-keys/key-789/ip-policies
{
  "blocked_cidrs": ["172.16.0.0/12"],
  "mode": "enforced"
}
```

→ Creates `api_key:key-789` \- blocks 172.16.0.0/12 for only key-789

**Result for key-789:** Both 192.168.0.0/16 (org) AND 172.16.0.0/12 (key) are blocked **Result for other keys:** Only 192.168.0.0/16 (org) is blocked

## Policy Enforcement Modes

### Three Enforcement States

Each policy has a `mode` that controls how it's evaluated:

| Mode | Evaluates? | Blocks? | Use Case |
| :---- | :---- | :---- | :---- |
| **`disabled`** | ❌ No | ❌ No | Temporarily turn off policy without deleting |
| **`dry_run`** | ✅ Yes | ❌ No | Test policy, see what would be blocked |
| **`enforced`** | ✅ Yes | ✅ Yes | Full enforcement |

**Benefits:**

✅ **Clear state transitions** \- disabled → dry\_run → enforced ✅ **Temporary disable** \- Turn off policy without losing configuration ✅ **Testing without risk** \- Validate policies before enforcement ✅ **Gradual rollout** \- Some policies enforced, others in testing ✅ **Full observability** \- Logs and metrics for each mode

### How It Works

The `mode` is embedded in the RelationTuple's `object_id`:

- **Disabled**: `object_id = "expr-{uuid}-disabled"`  
- **Dry run**: `object_id = "expr-{uuid}-dryrun"`  
- **Enforced**: `object_id = "expr-{uuid}-enforced"`

No proto changes needed\! The CEL evaluator parses the suffix to determine mode.

### Example: Create Policy in Dry Run Mode

```shell
curl -X POST http://localhost:8080/v1/api-keys/my-api-key-123/ip-policies \
  -H "Content-Type: application/json" \
  -d '{
    "blocked_cidrs": ["192.168.1.0/24"],
    "mode": "dry_run"
  }'
```

**What happens:**

1. Policy created with `object_id = "expr-abc123-dryrun"`  
2. Streams to FRAMES → all pods receive it  
3. CEL evaluator compiles it as a dry run policy  
4. Requests matching 192.168.1.0/24 are evaluated but **NOT blocked**  
5. Logs show: `[DRY_RUN] Would have BLOCKED by policy expr-abc123-dryrun`  
6. Metrics track: `policy_evaluations{mode="dry_run", would_block="true"}`

**Policy Lifecycle (disabled → dry\_run → enforced):**

```shell
# Step 1: Create disabled policy
POST /v1/api-keys/key-123/ip-policies {"blocked_cidrs": ["192.168.1.0/24"], "mode": "disabled"}

# Step 2: Test in dry run
PATCH /v1/api-keys/key-123/ip-policies/expr-abc123 {"mode": "dry_run"}

# Step 3: Promote to enforcement
PATCH /v1/api-keys/key-123/ip-policies/expr-abc123 {"mode": "enforced"}

# Step 4: Temporarily disable
PATCH /v1/api-keys/key-123/ip-policies/expr-abc123 {"mode": "disabled"}
```

### Metrics by Mode

```
# Policy evaluations by mode and result
policy_evaluations_total{api_key="key-123", policy_id="expr-abc", mode="disabled"} 0
policy_evaluations_total{api_key="key-123", policy_id="expr-abc", mode="dry_run", would_block="true"} 42
policy_evaluations_total{api_key="key-123", policy_id="expr-abc", mode="dry_run", would_block="false"} 158
policy_evaluations_total{api_key="key-123", policy_id="expr-abc", mode="enforced", blocked="true"} 38
policy_evaluations_total{api_key="key-123", policy_id="expr-abc", mode="enforced", blocked="false"} 162

# Policy evaluation time by mode
policy_evaluation_duration_us{api_key="key-123", mode="dry_run"} 18
policy_evaluation_duration_us{api_key="key-123", mode="enforced"} 18
```

### Logs by Mode

```json
// Dry run mode
{"level": "info", "mode": "dry_run", "would_block": true, "reason": "[DRY_RUN] Would have BLOCKED"}

// Enforced mode (blocked)
{"level": "warn", "mode": "enforced", "blocked": true, "reason": "Blocked by policy"}

// Disabled mode: no logs (not evaluated)
```

## AuthN Sidecar Implementation

### CEL Evaluator

```go
package authcheck

import (
    "fmt"
    "net"
    "sync"
    "github.com/google/cel-go/cel"
    "github.com/google/cel-go/common/types"
    "github.com/google/cel-go/common/types/ref"
    "github.com/DataDog/dd-source/domains/context-platform/libs/go/libcontext"
)

type PolicyMode string

const (
    PolicyModeDisabled PolicyMode = "disabled"
    PolicyModeDryRun   PolicyMode = "dry_run"
    PolicyModeEnforced PolicyMode = "enforced"
)

type PolicyProgram struct {
    Program  cel.Program
    Mode     PolicyMode  // Per-policy enforcement mode
    PolicyID string      // For logging and metrics
}

type CELEvaluator struct {
    mu       sync.RWMutex
    env      *cel.Env
    policies map[string]*PolicyProgram  // Map of subject ID → compiled program
                                         // "*" = org-wide, "key-123" = key-specific
    metrics  *Metrics
}

type RequestContext struct {
    SourceIP  string
    Country   string  // Future extension
    UserAgent string  // Future extension
}

func NewCELEvaluator() (*CELEvaluator, error) {
    // Create CEL environment with custom IP functions
    env, err := cel.NewEnv(
        // Define request context type
        cel.Variable("request", cel.MapType(cel.StringType, cel.AnyType)),

        // Add custom IP helper function
        cel.Function("ip",
            cel.Overload("string_to_ip",
                []*cel.Type{cel.StringType},
                cel.ObjectType("IP"),
                cel.UnaryBinding(func(val ref.Val) ref.Val {
                    ipStr := val.Value().(string)
                    return &ipValue{ip: net.ParseIP(ipStr)}
                }),
            ),
        ),
    )
    if err != nil {
        return nil, fmt.Errorf("failed to create CEL environment: %w", err)
    }

    return &CELEvaluator{
        env:      env,
        programs: make(map[string]cel.Program),
    }, nil
}

// Custom IP type for CEL with in_cidr method
type ipValue struct {
    ip net.IP
}

func (i *ipValue) ConvertToNative(typeDesc reflect.Type) (interface{}, error) {
    return i.ip, nil
}

func (i *ipValue) ConvertToType(typeVal ref.Type) ref.Val {
    return i
}

func (i *ipValue) Equal(other ref.Val) ref.Val {
    if otherIP, ok := other.(*ipValue); ok {
        return types.Bool(i.ip.Equal(otherIP.ip))
    }
    return types.Bool(false)
}

func (i *ipValue) Type() ref.Type {
    return types.NewObjectType("IP")
}

func (i *ipValue) Value() interface{} {
    return i.ip
}

func (i *ipValue) InCIDR(cidr string) bool {
    _, ipNet, err := net.ParseCIDR(cidr)
    if err != nil {
        return false
    }
    return ipNet.Contains(i.ip)
}

// LoadPolicies loads RelationTuples from FRAMES and compiles CEL expressions
// Note: FRAMES contexts are keyed by (orgID, resourceType, resourceID)
// The authenticator-intake knows the orgID from EdgeAuthResult and loads
// the appropriate policies for that org from FRAMES at startup.
func (e *CELEvaluator) LoadPolicies(tuples []*RelationTuple) error {
    e.mu.Lock()
    defer e.mu.Unlock()

    policies := make(map[string]*PolicyProgram)

    for _, tuple := range tuples {
        if tuple.SubjectType != "api_key" {
            continue
        }
        if tuple.Relation != "access_policy" {
            continue
        }

        // SubjectID can be:
        // - "*" for org-wide policies (applies to all keys in org)
        // - "key-123" for key-specific policies
        subjectID := tuple.SubjectID
        expression := tuple.Condition

        // Parse mode from object_id
        // Format: "expr-{uuid}-{mode}" where mode is: disabled | dryrun | enforced
        mode := parsePolicyMode(tuple.ObjectID)

        // Compile CEL expression
        ast, issues := e.env.Compile(expression)
        if issues != nil && issues.Err() != nil {
            return fmt.Errorf("failed to compile expression for api_key:%s: %w", subjectID, issues.Err())
        }

        // Create executable program
        prg, err := e.env.Program(ast)
        if err != nil {
            return fmt.Errorf("failed to create program for api_key:%s: %w", subjectID, err)
        }

        policies[subjectID] = &PolicyProgram{
            Program:  prg,
            Mode:     mode,
            PolicyID: tuple.ObjectID,
        }
    }

    e.policies = policies
    return nil
}

// parsePolicyMode extracts mode from object_id
// Format: "expr-{uuid}-{mode}" → "disabled" | "dry_run" | "enforced"
func parsePolicyMode(objectID string) PolicyMode {
    if strings.HasSuffix(objectID, "-disabled") {
        return PolicyModeDisabled
    }
    if strings.HasSuffix(objectID, "-dryrun") {
        return PolicyModeDryRun
    }
    if strings.HasSuffix(objectID, "-enforced") {
        return PolicyModeEnforced
    }
    // Default to enforced if no suffix (backward compatibility)
    return PolicyModeEnforced
}

type AccessDecision struct {
    Allowed        bool
    Reason         string
    PolicyID       string
    PolicyScope    string        // "*" (org-wide) or specific key ID
    Mode           PolicyMode
    WouldBlock     bool          // For dry_run mode: would this have blocked?
    EvaluationTime time.Duration
}

// CheckAccess evaluates CEL expression for API key
// Checks both org-wide (*) and key-specific policies
func (e *CELEvaluator) CheckAccess(apiKeyID string, ctx *RequestContext) (*AccessDecision, error) {
    e.mu.RLock()
    defer e.mu.RUnlock()

    startTime := time.Now()

    // Check org-wide policy first (api_key:*)
    if orgPolicy, exists := e.policies["*"]; exists {
        decision, err := e.evaluatePolicy(orgPolicy, "*", ctx)
        if err != nil {
            return nil, err
        }
        if !decision.Allowed && decision.Mode == PolicyModeEnforced {
            // Org-wide policy blocked in enforcement mode
            decision.Reason = fmt.Sprintf("[ORG-WIDE] %s", decision.Reason)
            decision.PolicyScope = "*"
            decision.EvaluationTime = time.Since(startTime)
            return decision, nil
        }
        // Track dry_run blocks even if allowed
        if decision.WouldBlock && decision.Mode == PolicyModeDryRun {
            e.metrics.RecordEvaluation("*", orgPolicy.PolicyID, orgPolicy.Mode, true, false)
        }
    }

    // Check API-key-specific policy
    keyPolicy, exists := e.policies[apiKeyID]
    if !exists {
        // No key-specific policy, and org-wide passed (or doesn't exist) = allow
        return &AccessDecision{
            Allowed:        true,
            EvaluationTime: time.Since(startTime),
        }, nil
    }

    decision, err := e.evaluatePolicy(keyPolicy, apiKeyID, ctx)
    if err != nil {
        return nil, err
    }

    decision.Reason = fmt.Sprintf("[API_KEY] %s", decision.Reason)
    decision.PolicyScope = apiKeyID
    decision.EvaluationTime = time.Since(startTime)
    return decision, nil
}

// evaluatePolicy evaluates a single policy
func (e *CELEvaluator) evaluatePolicy(policy *PolicyProgram, subjectID string, ctx *RequestContext) (*AccessDecision, error) {
    decision := &AccessDecision{
        PolicyID: policy.PolicyID,
        Mode:     policy.Mode,
    }

    // Skip evaluation if policy is disabled
    if policy.Mode == PolicyModeDisabled {
        decision.Allowed = true
        decision.Reason = "Policy disabled"
        return decision, nil
    }

    // Build evaluation context
    evalCtx := map[string]interface{}{
        "request": map[string]interface{}{
            "source_ip":  ctx.SourceIP,
            "country":    ctx.Country,
            "user_agent": ctx.UserAgent,
        },
    }

    // Evaluate CEL expression
    out, _, err := policy.Program.Eval(evalCtx)
    if err != nil {
        decision.Allowed = true  // Fail open on error
        decision.Reason = "CEL evaluation error"
        return decision, err
    }

    // CEL expression returns true = ALLOW, false = DENY
    wouldAllow, ok := out.Value().(bool)
    if !ok {
        decision.Allowed = true
        decision.Reason = "CEL returned non-boolean"
        return decision, fmt.Errorf("unexpected return type")
    }

    // Handle different modes
    switch policy.Mode {
    case PolicyModeDryRun:
        // Dry run: always allow but log what would have happened
        decision.Allowed = true           // Always allow in dry run
        decision.WouldBlock = !wouldAllow // Track what would have happened
        if !wouldAllow {
            decision.Reason = fmt.Sprintf("[DRY_RUN] Would have BLOCKED by policy %s", policy.PolicyID)
        } else {
            decision.Reason = fmt.Sprintf("[DRY_RUN] Would have ALLOWED by policy %s", policy.PolicyID)
        }
        return decision, nil

    case PolicyModeEnforced:
        // Enforced: evaluate and block if needed
        if !wouldAllow {
            decision.Allowed = false
            decision.Reason = fmt.Sprintf("Blocked by policy %s", policy.PolicyID)
        } else {
            decision.Allowed = true
        }
        return decision, nil

    default:
        // Should not reach here (disabled handled above)
        decision.Allowed = true
        return decision, nil
    }
}

// AddPolicy adds or updates a single policy (for incremental FRAMES updates)
func (e *CELEvaluator) AddPolicy(tuple *RelationTuple) error {
    e.mu.Lock()
    defer e.mu.Unlock()

    if tuple.SubjectType != "api_key" {
        return nil
    }

    subjectID := tuple.SubjectID  // Can be "*" or specific key ID
    expression := tuple.Condition

    // Parse mode from object_id
    mode := parsePolicyMode(tuple.ObjectID)

    // Compile CEL expression
    ast, issues := e.env.Compile(expression)
    if issues != nil && issues.Err() != nil {
        return issues.Err()
    }

    prg, err := e.env.Program(ast)
    if err != nil {
        return err
    }

    e.policies[subjectID] = &PolicyProgram{
        Program:  prg,
        Mode:     mode,
        PolicyID: tuple.ObjectID,
    }
    return nil
}
```

### Integration in AuthN Handler

```go
func (s *AuthNSidecar) ValidateIntakeRequest(req *IntakeRequest) error {
    // Step 1: Authenticate API key (existing flow)
    authResult := s.credentialResolver.Resolve(ctx, req.APIKey)
    if authResult.Status != model.AuthenticatedAPIKey {
        return &UnauthorizedError{StatusCode: 401}
    }

    // Extract org ID from auth result (already available!)
    orgID := authResult.OrgID  // ✅ From EdgeAuthResult
    apiKeyID := req.APIKey.ID

    // Step 2: Extract request context
    ctx := &RequestContext{
        SourceIP:  req.ClientIP,
        Country:   req.GeoIP.Country,    // Future extension
        UserAgent: req.Headers.UserAgent, // Future extension
    }

    // Step 3: Evaluate CEL policy (checks both org-wide and key-specific)
    // Note: The evaluator internally uses orgID to look up policies from FRAMES:
    //   - (orgID, "api_key", "*")      → org-wide policy
    //   - (orgID, "api_key", apiKeyID) → key-specific policy
    decision, err := s.celEvaluator.CheckAccess(apiKeyID, ctx)

    if err != nil {
        // Log error, fail open for availability
        s.metrics.IncrementPolicyEvalErrors()
        log.Warn("CEL policy evaluation error",
            log.String("api_key", apiKeyID),
            log.String("ip", ctx.SourceIP),
            log.ErrorField(err))
        return nil // Fail open
    }

    // Log evaluation results based on mode
    if decision.Mode == PolicyModeDryRun {
        log.Info("Policy evaluation",
            log.String("api_key", apiKeyID),
            log.String("policy_id", decision.PolicyID),
            log.String("mode", string(decision.Mode)),
            log.String("ip", ctx.SourceIP),
            log.Bool("would_block", decision.WouldBlock),
            log.String("reason", decision.Reason),
            log.Duration("eval_time_us", decision.EvaluationTime))
    } else if decision.Mode == PolicyModeDisabled {
        // Don't log disabled policies (no evaluation)
    }

    if !decision.Allowed {
        s.metrics.IncrementBlockedRequests(apiKeyID, ctx.SourceIP)
        log.Info("Request blocked by policy",
            log.String("api_key", apiKeyID),
            log.String("policy_id", decision.PolicyID),
            log.String("ip", ctx.SourceIP),
            log.String("reason", decision.Reason),
            log.Duration("eval_time_us", decision.EvaluationTime))
        return &ForbiddenError{
            StatusCode: 403,
            Message:    decision.Reason,
            IP:         ctx.SourceIP,
        }
    }

    return nil
}
```

**Performance:**

- Map lookup: \~1μs  
- CEL evaluation: \~15μs  
- Context building: \~2μs  
- **Total: \~20μs** (10x under budget\!)

**Flexibility:**

- ✅ Add country blocking: just change CEL expression  
- ✅ Add time-based rules: just change CEL expression  
- ✅ Add user-agent blocking: just change CEL expression  
- ✅ **Zero code changes needed\!**

## 

| Aspect | CEL | Hand-Rolled | SpiceDB |
| :---- | :---- | :---- | :---- |
| **Code complexity** | ✅ 300 lines | 200 lines | 800 lines |
| **Performance** | ✅ 20μs | 5μs | 40μs |
| **Dependencies** | cel-go lib | ✅ stdlib only | SpiceDB libs |
| **Memory** | 80MB | ✅ 50MB | 120MB |
| **Learning curve** | Medium | ✅ None | High |
| **Flexibility** | ✅ Unlimited attributes | Limited to IP | ✅ Relationships |
| **No rewrites** | ✅ Add attributes via expressions | ❌ Code changes needed | N/A (different use case) |
| **IP blocking** | ✅ Perfect | ✅ Perfect | Overkill |
| **Implementation time** | ✅ 1.5 days | 1 day | 2-3 days |
| **Future extension** | ✅ Trivial | ❌ Requires migration | ✅ Different use case |

**Recommendation**: Use CEL for Innovation Week \- fast enough, flexible, no future rewrites needed

1. ✅ **CEL evaluator** over hand-rolled/SpiceDB  
     
   - Flexible (extend to any attribute without rewrites)  
   - Fast enough (\~20μs, 10x under budget)  
   - Standard industry solution

   

2. ✅ **Reuse Zoltron RelationTuples** for storage  
     
   - Store CEL expressions in condition field  
   - No new database tables  
   - Existing FRAMES provider works

   

3. ✅ **Domain-specific API** for better UX  
     
   - POST /v1/api-keys/{key}/ip-policies  
   - Simple JSON: {blocked\_cidrs, allowed\_cidrs}  
   - Backend generates CEL expressions

   

4. ✅ **Shadow mode first**  
     
   - Validate before enforcing  
   - Safe rollout

## Implementation Status

**Current Phase:** Day 1 Complete ✅ **Next:** Day 2 \- Zoltron API \+ CEL Evaluator **Started:** Innovation Week 2026

## Future Extension Benefits (CEL Advantage)

**Week 2 \- Add Country Blocking:**

```javascript
// Just change the expression - zero code changes!
!(ip(request.source_ip).in_cidr('1.2.3.0/24') || request.country == 'CN')
```

**Week 3 \- Add Time-Based Rules:**

```javascript
// Still no code changes!
!(ip(request.source_ip).in_cidr('1.2.3.0/24')) &&
timestamp(request.timestamp).getHours() >= 9
```

**Week 4 \- Complex Combination:**

```javascript
// All attributes work together seamlessly
(request.country == 'US' || ip(request.source_ip).in_cidr('10.0.0.0/8')) &&
!request.user_agent.contains('bot')
```

**This is why CEL wins:** No rewrites, no migrations, just update expressions\!  


[image1]: <data:image/png;base64,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>

[image2]: <data:image/png;base64,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>

[image3]: <data:image/png;base64,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>

## Comments

> **Haopeng Liu** (2026-02-02, open):
> Naive question: how to add new legit fields into `request`?
> 
> If we want to use CEL to express the scoped product feature, it might be something like: "request.product == 'logs'". How to add `product` or `route` as legit fields that are part of request.
> 
> Is it just key/value without any validation?
> @erica.zhong@datadoghq.com
>
> **Erica Zhong** (2026-02-02):
> hm we would have to extract that from the request in the authn sidecar I think?
>
> **Erica Zhong** (2026-02-02):
> we currently don't do any authz in zoltron based on request metadata
>
> **Haopeng Liu** (2026-02-02):
> yeah, the value of those fields come from request. But do we have a definition for all legit fields that we could use in the rule, like a schema defined for the request fields?
> Maybe it is not a big issue that we need to worry in the innovation week

> **Haopeng Liu** (2026-02-02, open):
> Thanks! I think this high level architecture aligns with my mental model as well. We can work on some details. I will comment below.

> **Haopeng Liu** (2026-02-02, open):
> We could focus on first define the data structure of this context. Then we could do things in parallel:
> - someone add new logic in sidecar to build request context
> - someone build the CEL evaluation library to consume the context and return the evaluation result.

> **Haopeng Liu** (2026-02-02, open):
> This assume that a policy needs to be associated with an api key explicitly, right?
> 
> In reality, all policies are stored in the FRAME, are they keyed by api-key ids, so that we could use a simple key-value lookup to find all relevant policies?

> **Haopeng Liu** (2026-02-02, open):
> Can the SubjectType also be a org-id instead of api key? I am sure that some access control policies are applied at the org level
>
> **Erica Zhong** (2026-02-02):
> we could have the subjectType be api_key:* to indicate that it applies to all api keys in the org (relation tuples are scoped by org)
>
> **Haopeng Liu** (2026-02-02):
> Maybe I missed something, where do we define the orgs in the policy proto?
> (Part of the context key instead of value?)
>
> **Drew Tempelmeyer** (2026-02-02):
> There is an org_id column for a relation_tuple record. It doesn't appear to be represented here, though.
> 
> For Zoltron Restriction Policies + FRAMES, they are keyed by Org UUID + subject type + subject ID.

> **Haopeng Liu** (2026-02-02, open):
> can I suggest to make it an enum?
> 
> - Disabled
> - Dry-run
> - Enforced
> 
> During the dry-run mode, we still evaluate the policy, and give customer visibility around permission control result, but we don't actually return 403
>
> **Erica Zhong** (2026-02-02):
> yeah makes sense, do we want to add that in right now?
>
> **Haopeng Liu** (2026-02-02):
> No strong feelings to add it for innovation week. But it is definitely required if we want to make it a product since dry-run a policy and evaluate the impact of that policy is critical, otherwise customer intake data might be lost due to an incorrect policy

> **Haopeng Liu** (2026-02-02, open):
> I would advocate for using a new frame context, just to isolate between zoltron and intake control plane.
> 
> It is probably fine to reuse the same context during the innovation week.
>
> **Erica Zhong** (2026-02-02):
> sounds good, I think long term zoltron relation tuples might not be the ideal way to store this data since zoltron's model works better for relationships rather than attributes...but I think we can make it work for innovation week since the data store/frames is already set up

> **Haopeng Liu** (2026-02-02, open):
> https://github.com/DataDog/dd-source/blob/ca36289cd76da89095507425f37f3c1c3e0fdabe/domains/aaa/apps/zoltron/internal/frames/proto/restriction_policy.proto#L18
> 
> This looks very different from the existing proto? Do we want to create a new policy proto here or reuse existing proto?
>
> **Erica Zhong** (2026-02-02):
> I haven't reviewed this thoroughly yet! Just wanted to align on general approach

> **Haopeng Liu** (2026-01-31, open):
> Performance/latency is the key metrics for intake traffic volume. This checks might be running for the entire 7M req/s, and our current prod authn check P99 latency is around 200us. https://app.datadoghq.com/s/yB5yjZ/asp-x6j-n7f
> 
> There is no way we could call the gRPC externally during the intake path. That is why frame is used. 
> 
> I've ran a benchmark comparison between the spiceDB and customized golang solution, https://github.com/hopen528/policy-engine-benchmark/blob/main/EXPECTED_RESULTS.md, which shows that SpiceDB solution is 1000x slower than customized solution (1us vs. 1ms).
>
> **Haopeng Liu** (2026-01-31):
> Is it an option that we define a policy proto that include the CEL rules that can eventually cover both intake and GRACE use cases? The build a customized solution on it, which can gradually grow into a polished solution after inno week.
>
> **Erica Zhong** (2026-02-02):
> oh I see! In that case I think we can see what we can do with zoltron since it's already streaming restriction policies with FRAMES
>
> **Haopeng Liu** (2026-02-02):
> Thanks! Do you think the current zoltron restriction policy apply to the use cases in the intake world? If so, can you come up with some examples for intake rules (e.g. IP allowlist. scoped product or other types of restrictions) described with current policy proto?
>
> **Erica Zhong** (2026-02-02):
> yes! just did some preliminary brainstorming (with claude) linked in new tab, but will review more thoroughly in the afternoon

> **Haopeng Liu** (2026-01-29, open):
> There are some difficulties to pass the VPC ids from Envoy to sidecar based on the discussion with Fabric team. We could limit the scope to public ips only.

> **Haopeng Liu** (2026-01-29, open):
> @erica.zhong@datadoghq.com 
> Do u mind to add some of your ideas here?
>
> **Haopeng Liu** (2026-01-30):
> I've added some ideas of proto definition here, feel free to comment and critique, https://docs.google.com/document/d/1w-9Q-uSdmaUF5YR3py9d6cenphkX8mH1gspO6Be-DF4/edit?tab=t.fqtf19oh79e9
>
> **Erica Zhong** (2026-01-30):
> ok! I've also added my explorations with setting up a policy engine through spiceDB in a new service, I think it might be easier to work with than trying to use zoltron (also i'm not sure that zoltron is prepared for intake levels of traffic)
