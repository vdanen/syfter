# RHSSO (Keycloak) Integration for Syfter

## Overview

Hybrid authentication:
- **Browser/interactive** (port 4443): RHSSO via OAuth proxy — SSO with corporate identities
- **CLI/scanner** (port 8080): API keys via nginx gateway — one key per team

## RHSSO Realm Setup

### 1. Create a Client in your RHSSO realm

| Setting | Value |
|---------|-------|
| Client ID | `syfter-api` |
| Client Protocol | `openid-connect` |
| Access Type | `confidential` |
| Standard Flow Enabled | `ON` |
| Valid Redirect URIs | `https://syfter-api-syfter.__CLUSTER_DOMAIN__/oauth2/callback` |
| Web Origins | `https://syfter-api-syfter.__CLUSTER_DOMAIN__` |

### 2. Get the client secret

After creating the client, go to the **Credentials** tab and copy the secret.

### 3. Update the OpenShift Secret

```bash
# Update the oauth-proxy secret with RHSSO client secret
oc create secret generic syfter-oauth-proxy \
  --from-literal=cookie-secret=$(openssl rand -hex 16) \
  --from-literal=client-secret=<RHSSO_CLIENT_SECRET> \
  -n syfter --dry-run=client -o yaml | oc apply -f -
```

### 4. Apply the deployment

Update the OAuth proxy args in `deployment.yaml` (see the RHSSO args below),
then apply:

```bash
oc apply -f manifests/api/deployment.yaml
```

### 5. Verify

Visit `https://syfter-api-syfter.__CLUSTER_DOMAIN__` in a browser.
You should be redirected to the RHSSO login page.

## OAuth Proxy Args (RHSSO mode)

Replace the oauth-proxy container args in `deployment.yaml` with:

```yaml
args:
  - --https-address=:4443
  - --provider=oidc
  - --oidc-issuer-url=https://sso.example.com/auth/realms/<REALM>
  - --client-id=syfter-api
  - --client-secret-file=/etc/oauth-proxy/client-secret
  - --upstream=http://localhost:8000
  - --tls-cert=/etc/tls/private/tls.crt
  - --tls-key=/etc/tls/private/tls.key
  - --cookie-secret-file=/etc/oauth-proxy/cookie-secret
  - --cookie-secure=true
  - --pass-basic-auth=false
  - --pass-access-token=true
  - --skip-auth-regex=^/health$
  - --email-domain=redhat.com
```

## What Changes

| Component | Before (OpenShift OAuth) | After (RHSSO) |
|-----------|-------------------------|---------------|
| OAuth proxy `--provider` | `openshift` | `oidc` |
| Auth source | OpenShift user accounts | RHSSO / corporate SSO |
| User provisioning | Need OCP account + namespace access | Any RHSSO user (filtered by email-domain) |
| API gateway (port 8080) | No change | No change — still API keys |
| Service Account | Required for OCP OAuth | Not required for OIDC |

## Restricting Access

To limit access to specific RHSSO groups or roles:

```yaml
# Allow only users in a specific group
- --allowed-group=syfter-users

# Or allow only specific email domains
- --email-domain=redhat.com
```
