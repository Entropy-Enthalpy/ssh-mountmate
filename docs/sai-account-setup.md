# SAI account setup adapter

**Status: client implementation against a proposed service contract.** The APIs below are
not yet deployed. MountMate checks capability before starting login; unsupported services
show an explanation and keep manual SAI setup available. Server work is tracked in
[Identity #115](https://github.com/AI4SAI/sai-identity/issues/115) and
[Portal #564](https://github.com/AI4SAI/sai-portal/issues/564).

## Client boundary

`mountmate-sai` owns discovery, device authorization, permitted connections and public-key
registration. The app's `sai_setup.rs` owns temporary editor state. Only after the selected
site reports `applied` does the adapter fill an ordinary `ConnectionDraft`. Existing validation,
save, host-key review and mount handling remain responsible for the connection. No core
mount code or saved connection schema changes are needed.

The first version uses Native SFTP and a dedicated local Ed25519 key, without writing SSH
config entries or requiring an SSH CA. Keys live under the app data directory at
`sai-keys/<local hash>/id_ed25519`, using existing Unix permissions (0700 directory, 0600 file)
and Windows ACL helpers. Account/site identifiers never become literal filenames. Private
keys are never uploaded or downloaded. Access tokens stay in memory during setup and are
dropped on completion, cancellation or leaving the editor. No offline access, refresh-token
cache or credential sharing with another client is used. Expired authorization requires a
new sign-in. Ordinary subsequent mounts use the SSH key.

Cancelling an HTTP request cannot undo a registration already accepted by the service.
Deleting a connection also does not revoke the remote public key: use the SAI console to
remove it. Local keys remain available for retry and connections that reference them.

Production trust roots are Portal `https://www.open-sai.com` and Identity issuer
`https://id.open-sai.com/realms/sai`. There is no production HTTP/issuer override. HTTP keeps
normal system proxy behavior, TLS validation, no redirects, 10-second connect and 20-second
request timeouts, and a 128 KiB response limit. Discovery issuer must match exactly;
token/device/verification URLs must share the trusted issuer origin, without URL credentials
or fragments. Errors exclude response bodies and OAuth secrets. The browser receives the
plain verification URL; users enter the displayed code there.

## Proposed Identity registration

Register public client `ssh-mountmate` for standard Device Authorization (RFC 8628), without
client secret or password grant. Browser login, MFA, consent and sensitive-action policy
belong to Identity. Requested scopes are `openid sai.ssh.read sai.ssh.keys.write`; resource
and audience are `sai-portal`. Do not grant unrelated billing, compute/storage or offline scopes.

Agree on a Portal-compatible subject sector and explicit authorized-party allowlist. Portal
binds the verified `(iss, sub)` to its account; MountMate does not derive Unix usernames from
email, nickname or subject. Send `client_id` and `resource` to device and token endpoints,
and scopes to the device endpoint. The OAuth library handles pending and `slow_down`; login
is bounded by the advertised expiry and 15 minutes. Granted scopes, when supplied, must
contain the requested scopes. Tokens must be Bearer with positive `expires_in`. Portal owns
signature, issuer, audience, azp, expiry, scope and account-binding verification.

## Proposed Portal v1 contract

Paths are relative to the fixed Portal origin. All responses use JSON; additive fields are
allowed. No response supplies executable commands, private keys or credential forwarding URLs.

### Public capability

`GET /v1/auth/config?client=ssh-mountmate`, without token:

```json
{
  "schema_version": "ssh-mountmate.connection/v1",
  "identity_issuer": "https://id.open-sai.com/realms/sai",
  "oidc_client_id": "ssh-mountmate",
  "oidc_resource": "sai-portal",
  "ssh_access": "public-key/v1"
}
```

Publish only after client registration, APIs and site application are ready. 400/404/501/503
mean unavailable; mismatched or malformed configuration stops before login.

### Allowed connections

`GET /v1/account/ssh/connections`, Bearer token with `sai.ssh.read`:

```json
{
  "schema_version": "ssh.connections/v1",
  "account_id": "opaque-stable-portal-account-id",
  "connections": [
    {"site_id": "example-site", "name": "Example cluster", "host": "ssh.example.org", "port": 12022, "username": "example_user"}
  ]
}
```

Return at most 100 sites with current SSH access for this actor. Empty lists are valid.
`account_id` is stable and opaque, scoped to this Portal, used for local key reuse (1–255
UTF-8 bytes, nonblank, no control characters). Site IDs are unique; `site_id`/`username` are
1–128 ASCII letters/digits/underscore/hyphen/dot without a leading hyphen. Host is a DNS name
or IP address; port is 1–65535; name is 1–128 UTF-8 bytes, nonblank, without controls. Do not
substitute query-gateway metadata. Recheck access when registering a key.

### Register this device

`POST /v1/account/ssh/keys`, Bearer token with `sai.ssh.keys.write`:

```json
{
  "request_id": "64-lowercase-hex-digits",
  "site_id": "example-site",
  "public_key": "ssh-ed25519 <OpenSSH public key base64>",
  "label": "SSH MountMate"
}
```

`request_id` is a SHA-256 digest of local account/site context and the public key. It is an
idempotency identifier, not authorization. Bind it to the verified actor, site and exact key;
repeated identical requests return the original operation, conflicting content is rejected.
Preserve deduplication while the key/operation is active. All reads/writes are actor-bound.
Reuse the canonical SSH-key writer and asynchronous site provisioning path.

POST (200/201/202) and `GET /v1/account/ssh/keys/{request_id}` (requiring `sai.ssh.read`)
return the same structure:

```json
{
  "request_id": "64-lowercase-hex-digits",
  "site_id": "example-site",
  "public_key_fingerprint": "SHA256:<OpenSSH SHA-256 fingerprint>",
  "state": "pending"
}
```

States are `pending`, `applied`, `failed`. `applied` must reflect the selected site's current
confirmation for this actor/key; queuing a task is only `pending`. The client polls every two
seconds for at most two minutes and verifies request/site/fingerprint every time. Pending,
failed, mismatched or unknown states never produce a connection. Timeout/network failure
retains the local key; explicit retry repeats the same request, also after restart and sign-in
to the same account. Expired authorization requires sign-in again.

Return 401 for invalid/expired authorization, 403 for missing permission or required account
action. Preserve existing sensitive-action and abuse-prevention controls. If another browser
step is necessary, agree on a versioned extension before advertising capability. First-version
revocation uses the existing SAI console rather than a new client API.

## Validation and rollout

Local HTTP fixtures exercise login through ordinary draft validation, polling/denial/expiry,
cancellation, issuer/endpoint mismatch, redirects, response limits, credential destinations,
site application states, durable retry and private-key protection. Editor generations reject
late results; save is disabled during setup and existing mounted/source/saving guards apply.

Before enabling the service, separately verify client registration, consent/scopes/audience/
subject binding, cross-account denial, permission revocation, deduplication, real site
callbacks, remote key removal, Windows/macOS file protection and actual SFTP mounting.
Fixture tests and a network-failure GUI check do not establish live authorization.
