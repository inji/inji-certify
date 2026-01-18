# JSON-LD Context Loader 

This module provides a Spring Boot–managed JSON-LD `DocumentLoader` used to resolve JSON-LD `@context` IRIs during VC/VP processing. It supports:

- **Configured context registry** (map context IRI → resource)
- Loading contexts from **classpath / file / http(s)**
- Optional remote resolution for **unknown** context IRIs
- Optional **host allowlist** for remote fetching
- **Startup preload** of configured contexts
- In-memory **cache** with TTL + max entry limit

---

## Feature Design

### Problem
JSON-LD processing frequently requires fetching remote `@context` documents (e.g., W3C VC contexts). Fetching contexts at runtime introduces:

- latency and dependency on external services
- reliability issues (external downtime, DNS, network)
- security risk (untrusted remote contexts → outbound calls / SSRF-style risks)

### Design Goals
1. Prefer **local (classpath) contexts** for standard well-known IRIs.
2. Allow **explicit opt-in** for remote contexts.
3. Support **unknown context IRIs** only when explicitly enabled.
4. Provide **host allowlisting** for remote access in production.
5. Improve runtime performance via **preload + caching**.
6. Avoid startup failure if preload fails (warn + continue).

### Resolution Flow (High-level)
When JSON-LD asks for a context IRI:

1. **Cache lookup** (if cache enabled)
2. If IRI is present in `mosip.certify.jsonld.contexts`:
    - load its configured `resource`
    - cache it if enabled
3. Otherwise (**unknown context IRI**):
    - if `remote.enabled=false` OR `remote.allowUnknown=false` → **fail**
    - else load remotely (subject to allowlist policy)
    - cache if `remote.cacheUnknown=true`

---

## Configuration

All configuration is under:

`mosip.certify.jsonld.*`

### Cache

| Property | Default | Description |
|---|---:|---|
| `mosip.certify.jsonld.cache.enabled` | `true` | Enable in-memory cache |
| `mosip.certify.jsonld.cache.maxEntries` | `256` | Max cached entries (0 = unlimited) |
| `mosip.certify.jsonld.cache.ttl` | `24h` | Cache TTL (0 = never expires) |

Example:
```properties
mosip.certify.jsonld.cache.enabled=true
mosip.certify.jsonld.cache.maxEntries=512
mosip.certify.jsonld.cache.ttl=24h
```

### Remote fetching

| Property | Default | Description |
|---|---:|---|
| `mosip.certify.jsonld.remote.enabled` | `true` | Enable HTTP(S) remote fetching |
| `mosip.certify.jsonld.remote.allowUnknown` | `false` | Allow unknown context IRIs (not in registry) |
| `mosip.certify.jsonld.remote.cacheUnknown` | `true` | Cache unknown remote contexts |
| `mosip.certify.jsonld.remote.enforceAllowedHosts` | `true` | Enable allowlist enforcement. When false, host filtering is disabled. |

### Host allowlist (recommended for production)
The allowlist defines which remote hosts may be called.

| Property | Default | Description |
|---|---:|---|
| `mosip.certify.jsonld.remote.allowedHosts[...]` | empty | Allowed remote hosts. If empty: no restriction (open mode). |

Example:
```properties
mosip.certify.jsonld.remote.allowedHosts[0]=www.w3.org
mosip.certify.jsonld.remote.allowedHosts[1]=w3id.org
```

> **Important:** Host allowlisting is strongly recommended for production systems.  
> If you keep the list empty, any host is allowed (open mode).

---

## Context Registry (`contexts[]`)

Each configured context maps an IRI to:

- `resource` (classpath/file/http(s))
- `preload` (load at startup)
- `cache` (per-entry cache enable)

Example:
```properties
# VC Data Model context (local)
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].resource=classpath:/contexts/credentials-v1.jsonld
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].preload=true
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].cache=true

# Ed25519Signature2020 context (local)
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].resource=classpath:/contexts/security-v1.jsonld
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].preload=true
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].cache=true

# Custom context (remote)
mosip.certify.jsonld.contexts[https\://piyush7034.github.io/my-files/farmer.json].resource=https://piyush7034.github.io/my-files/farmer.json
mosip.certify.jsonld.contexts[https\://piyush7034.github.io/my-files/farmer.json].preload=false
mosip.certify.jsonld.contexts[https\://piyush7034.github.io/my-files/farmer.json].cache=true
```

---

## Behavior (Detailed)

### Preload
- Any context entry with `preload=true` is loaded at startup.
- Preload errors are logged at WARN and do **not** stop application startup.

### Caching
Caching occurs only if:
- `cache.enabled=true` AND
- entry has `cache=true` (or unknown remote has `remote.cacheUnknown=true`)

Cache TTL behavior:
- `ttl=0` ⇒ no expiry
- `ttl>0` ⇒ expires after TTL, and will reload on next request

Cache maxEntries behavior:
- If `maxEntries > 0` and cache is full, new IRIs are **not added** (existing cached IRIs still served)

### Remote unknown contexts
If a VC references a context IRI not present in `contexts[]`:
- `remote.allowUnknown=false` ⇒ fail fast
- `remote.allowUnknown=true` ⇒ fetch remotely (subject to allowHosts list if configured)

---

## Edge Cases and Notes

### 1) IRI exact match required
The loader matches context IRI keys exactly as strings (after `URI.normalize()`).
If you see unexpected "No configured mapping", check:
- trailing slash differences
- fragment (`#`) presence
- http vs https

> If needed, implement canonicalization (strip fragment, trailing slash normalization).

### 2) Remote allowlist behavior
- If `allowedHosts` list is **non-empty**, only listed hosts are allowed.
- If `allowedHosts` list is **empty**, any host is allowed (open mode).

### 3) Remote resource in `contexts[]`
If a configured context uses a remote `resource=https://...`, it will still be subject to `remote.enabled` and allowlist constraints.

---

## Production Guide

### Recommended production setup (secure + stable)

1) Prefer local copies of well-known contexts:
- `https://www.w3.org/2018/credentials/v1`
- `https://w3id.org/security/suites/ed25519-2020/v1`

2) Keep unknown contexts disabled unless necessary:
```properties
mosip.certify.jsonld.remote.allowUnknown=false
```

3) If unknown contexts must be enabled (partner credentials):
- enable allowUnknown
- use strict allowlist
```properties
mosip.certify.jsonld.remote.enabled=true
mosip.certify.jsonld.remote.allowUnknown=true
mosip.certify.jsonld.remote.allowedHosts[0]=www.w3.org
mosip.certify.jsonld.remote.allowedHosts[1]=w3id.org
mosip.certify.jsonld.remote.allowedHosts[2]=<partner-domain>
```

4) Cache + preload critical contexts:
```properties
mosip.certify.jsonld.cache.enabled=true
mosip.certify.jsonld.cache.ttl=24h

mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].preload=true
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].preload=true
```

### Security considerations
Allowing unknown remote contexts from arbitrary domains can enable:
- outbound request abuse (SSRF-style patterns)
- performance degradation due to large/slow responses
- external dependency fragility

**Always prefer allowlisted hosts** and explicit registry entries.

### Observability
- Preload failures log at WARN
- Cache-full events log at DEBUG

---

## Testing

Unit tests cover:
- configured local contexts
- configured remote contexts
- unknown context resolution allowed/blocked
- allowlist allow/deny behavior
- caching: hit/miss/TTL/maxEntries
- preload success/failure
- invalid JSON, missing resources, IO exceptions

Run:
```bash
mvn test
```

---

## Example Full Configuration (Reference)

```properties
# Cache
mosip.certify.jsonld.cache.enabled=true
mosip.certify.jsonld.cache.maxEntries=512
mosip.certify.jsonld.cache.ttl=24h

# Remote context resolution
mosip.certify.jsonld.remote.enabled=true
mosip.certify.jsonld.remote.allowUnknown=true
mosip.certify.jsonld.remote.allowedHosts[0]=www.w3.org
mosip.certify.jsonld.remote.allowedHosts[1]=w3id.org
mosip.certify.jsonld.remote.allowedHosts[2]=piyush7034.github.io
mosip.certify.jsonld.remote.cacheUnknown=true

# Context registry
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].resource=classpath:/contexts/credentials-v1.jsonld
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].preload=true
mosip.certify.jsonld.contexts[https\://www.w3.org/2018/credentials/v1].cache=true

mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].resource=classpath:/contexts/security-v1.jsonld
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].preload=true
mosip.certify.jsonld.contexts[https\://w3id.org/security/suites/ed25519-2020/v1].cache=true

mosip.certify.jsonld.contexts[https\://piyush7034.github.io/my-files/farmer.json].resource=https://piyush7034.github.io/my-files/farmer.json
mosip.certify.jsonld.contexts[https\://piyush7034.github.io/my-files/farmer.json].preload=false
mosip.certify.jsonld.contexts[https\://piyush7034.github.io/my-files/farmer.json].cache=true
```
