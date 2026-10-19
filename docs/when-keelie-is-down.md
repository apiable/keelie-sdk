# When keelie is down

**You keep serving until the token expires. Then you refuse.**

Your API traffic never passes through keelie. The SDK checks each token inside your process, with
keys it already holds. When keelie or its issuer is down, a Consumer whose token is still valid
gets every call. A Consumer whose token expires cannot get a new one, so their next call is
refused.

This page lists each failure, and what the SDK does in it.

## How long a token lives

keelie sets the lifetime of each token when the Consumer mints it, from the Consumer's balance and
plan. A healthy balance gives the full lifetime of the plan. A low balance gives a shorter token,
down to a minimum that keelie sets.

So the time a Consumer keeps working during an outage is the time left on their token:

| Consumer | During an outage |
|---|---|
| Large balance | Every call succeeds while their token lives. |
| Balance reaches zero during the outage | Calls succeed, then stop when the token expires. |
| Delinquent before the outage | Their token is short. Every call is refused once it expires. |
| Never seen | Every call is refused. They have no token. |

The SDK holds no balance and no count. Every copy of your application reads the same token, and
reports usage after the call. keelie limits what a Consumer can spend past their balance through
the token lifetime and the 5-second report interval.

## The issuer is down

| The SDK holds | What happens |
|---|---|
| The key set, from an earlier token | The keys in hand go on verifying. A valid token passes. The SDK does not ask the issuer, unless a token names a key it does not know. |
| No key set: the process started during the outage | Every token is refused with `401`, even a valid one. The log says `apiable.keys_unavailable`. The next request tries the issuer again. |

> **Caution:** a copy of your application that starts during an outage refuses every call until
> the issuer is back. Do not restart or scale out all copies at once while keelie is down.

`verifier.status()` is `offline` in the second row. In the first row it stays as it was, because the
SDK does not poll the issuer. It changes to `degraded` only when a fetch fails: for a key it does
not know. `claims.expires_at` tells you how long each Consumer keeps working.

A token signed with a new key needs that key. The SDK fetches the key set again on the first
token that names an unknown key, at most once a minute. A rotated key works within a minute,
with no restart.

## keelie's API is down

Nothing on the request path changes. Only the background work waits.

- **Usage reports.** The SDK keeps each failed batch in memory, and sends it again every 5 seconds
  with the same idempotency key. keelie keeps each event once. The buffer holds 10,000 events.
  When it is full, the oldest event goes, with the log line `apiable.usage_dropped`.
- **The AI Catalog.** The SDK serves its copy for 60 seconds at most. After that, the catalog
  address answers `503` with `Retry-After: 10`, until keelie answers again.

The SDK writes nothing to disk. Events that wait in memory are lost if the process stops before
keelie is back. `aclose()` tries to send them once at shutdown.

## A token does not verify

The answer is `401`, with `WWW-Authenticate: Bearer error="invalid_token"` and an empty body. The
answer is the same for every reason, so a caller learns nothing from it. The reason goes to your
log, in `apiable.token_rejected reason=...`.

## A token does not carry the scope

`ScopeMap.check` raises `InsufficientScope`. Answer `403`. `McpGuard` answers `403` with a JSON-RPC
error for you.

## A caller with no token

The answer is `401`, with `WWW-Authenticate: Bearer resource_metadata="..."`. An agent follows that
address to your metadata, and from there to your issuer, to get a token.

## keelie refuses a usage event

keelie refuses an event it cannot keep, such as an event older than the start of the previous
month, or one that would take a counter past its largest value. The SDK drops the batch with a log
line, because a retry gets the same answer. A refused report never stops a request.
