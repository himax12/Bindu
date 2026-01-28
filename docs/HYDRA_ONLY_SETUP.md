# Hydra-Only Authentication Setup

This document describes the simplified authentication setup using **only Ory Hydra** for OAuth2/OIDC authentication.


## Current Authentication Flow

### How It Works

```
User/Agent → OAuth2 Client Credentials → Hydra → Access Token → API Request
```

1. **Client Registration**: Create OAuth2 client in Hydra
2. **Token Acquisition**: Get access token using client credentials
3. **API Authentication**: Use Bearer token in Authorization header
4. **Token Validation**: Hydra introspects token to verify validity

## Environment Configuration

Add these to your `.env` file:

```bash
# Hydra OAuth2 Configuration
AUTH__ENABLED=true
AUTH__PROVIDER=hydra

# Hydra API endpoints
HYDRA__ADMIN_URL=https://hydra-admin.getbindu.com
HYDRA__PUBLIC_URL=https://hydra.getbindu.com

# Connection settings (optional, defaults shown)
HYDRA__TIMEOUT=10
HYDRA__VERIFY_SSL=true
HYDRA__MAX_RETRIES=3

# Token cache settings (optional)
HYDRA__CACHE_TTL=300
HYDRA__MAX_CACHE_SIZE=1000

# Auto-registration for agents (optional)
HYDRA__AUTO_REGISTER_AGENTS=true
HYDRA__AGENT_CLIENT_PREFIX=agent-
```

## Usage Examples

### 1. Create OAuth2 Client

```bash
curl -X POST https://hydra-admin.getbindu.com/admin/clients \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my-app",
    "client_secret": "my-secret-keep-this-safe",
    "grant_types": ["client_credentials", "authorization_code", "refresh_token"],
    "response_types": ["code", "token"],
    "scope": "openid offline email profile agent:read agent:write"
  }'
```

### 2. Get Access Token (Client Credentials)

```bash
curl -X POST https://hydra.getbindu.com/oauth2/token \
  -u "my-app:my-secret-keep-this-safe" \
  -d "grant_type=client_credentials" \
  -d "scope=openid agent:read agent:write"
```

**Response:**
```json
{
  "access_token": "ory_at_xxxxxxxxxxxxx",
  "token_type": "bearer",
  "expires_in": 3599,
  "scope": "openid agent:read agent:write"
}
```

### 3. Use Access Token in API Requests

```bash
# Connect OAuth provider
curl -X GET https://api.getbindu.com/oauth/connect/notion \
  -H "Authorization: Bearer ory_at_xxxxxxxxxxxxx"

# Any other authenticated endpoint
curl -X GET https://api.getbindu.com/api/v1/agents \
  -H "Authorization: Bearer ory_at_xxxxxxxxxxxxx"
```

### 4. Introspect Token (Verify)

```bash
curl -X POST https://hydra.getbindu.com/oauth2/introspect \
  -u "my-app:my-secret-keep-this-safe" \
  -d "token=ory_at_xxxxxxxxxxxxx"
```

**Response:**
```json
{
  "active": true,
  "scope": "openid agent:read agent:write",
  "client_id": "my-app",
  "sub": "user-id-or-client-id",
  "exp": 1737907200,
  "iat": 1737903600,
  "iss": "https://hydra.getbindu.com"
}
```

## API Changes

### After (Hydra)

```python
# New: Bearer token in Authorization header
GET /oauth/connect/notion
Authorization: Bearer ACCESS_TOKEN
```

## Code Changes

### Authentication Function

**After:**
```python
async def get_user_from_session(request: Request) -> str:
    """Extract user_id from Hydra OAuth2 token."""
    auth_header = request.headers.get("Authorization")
    access_token = auth_header.replace("Bearer ", "")
    
    async with HydraClient(...) as hydra:
        token_info = await hydra.introspect_token(access_token)
        return token_info.get("sub")
```

## Benefits of Hydra-Only Approach

1. **Simpler Architecture**: One authentication system instead of two
2. **Standard OAuth2**: Industry-standard authentication flow
3. **Better for APIs**: Token-based auth is ideal for API-to-API communication
4. **Easier Integration**: Most clients already support OAuth2
5. **Stateless**: No session management needed
6. **Scalable**: Tokens can be validated without database lookups (with caching)


## Testing

```bash
# 1. Create a test client
curl -X POST https://hydra-admin.getbindu.com/admin/clients \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "test-client",
    "client_secret": "test-secret-123",
    "grant_types": ["client_credentials"],
    "scope": "openid"
  }'

# 2. Get token
TOKEN=$(curl -s -X POST https://hydra.getbindu.com/oauth2/token \
  -u "test-client:test-secret-123" \
  -d "grant_type=client_credentials" \
  -d "scope=openid" | jq -r '.access_token')

# 3. Use token
curl -X GET https://api.getbindu.com/health \
  -H "Authorization: Bearer $TOKEN"

# 4. Verify token
curl -X POST https://hydra.getbindu.com/oauth2/introspect \
  -u "test-client:test-secret-123" \
  -d "token=$TOKEN"
```
