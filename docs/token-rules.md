# The keelie token rules

This page is for a Provider who checks a Consumer's token in their own API. Use the keelie SDK,
or use the JWT library or the gateway that you already have. Every way follows these rules.

A token is a signed JWT (RFC 7519). The token carries the decision. You do not call keelie to
check a token.

## Where the token comes from

- Each Provider has its own realm on the keelie issuer. Its Consumers get their tokens there.
- `GET /orgs/{orgId}` gives the `issuer` of the realm. It is the exact `iss` of every token of
  your Consumers. Only a switch of your own auth domain changes it, and only when you start it
  (see below).
- A Consumer mints a token with the OAuth 2.0 `client_credentials` grant (RFC 6749 §4.4), at
  the token endpoint of the realm. The discovery document of the issuer names the endpoint.
- The discovery documents are at `{issuer}/.well-known/openid-configuration` and at the RFC
  8414 address of the issuer. Both name `jwks_uri`, the key set that signs the tokens.

## Your own auth domain (Growth and above)

On Growth and above, your realm can run on your own domain, such as `auth.portal-labs.example`.
Your Consumers then sign in, consent and mint there, under your logo and colours. The domain moves
the issuer. Read this section before you switch.

1. Point a CNAME from your domain to the issuer host.
2. Publish the TXT record that `GET /orgs/{orgId}` shows in `domain_proof`, at
   `_keelie-challenge.<your domain>`.
3. Call `POST /orgs/{orgId}:verify-auth-domain` with the domain. `GET /orgs/{orgId}` then shows
   the issuer on your domain in `next_issuer`.
4. Make every verifier accept both values: `issuer` and `next_issuer`. Do this in your SDK
   configuration and in your gateway.
5. Call `POST /orgs/{orgId}:activate-auth-domain`. keelie first asks your realm's discovery
   document over your domain. If it does not answer over TLS, the realm stays where it is (`422`).
6. 31 minutes after the switch, remove the old value from every verifier. That is the longest
   token lifetime, 30 minutes, and the 30 seconds of clock difference.

The way back is the same. `POST /orgs/{orgId}:deactivate-auth-domain` moves the realm back to the
issuer host and to Keelie's brand. Before you call it, accept both values again: `next_issuer` then
shows the issuer host. Call it before you move to PAYG.

What a switch does, in both directions:

- Every new token carries the new `iss`. The token endpoint and `jwks_uri` move with it.
- A token minted before the switch keeps the old `iss`. It works until it expires.
- The key set stays the same. The keys do not change.
- **The switch ends every consent session of your realm.** The issuer refuses a refresh token
  with the old `iss`. Each end user signs in once more. You pick the moment of the switch.
- If your Consumers sign in through your own identity provider, register the new redirect URI
  there before you switch. It is on your domain.

## Your server address: the audience

- Set the address of your server with `PATCH /orgs/{orgId}` and the member `resource`. keelie
  issues no Consumer credential before you set it (`409`).
- The address uses `https` and has a host. It has no user, no query and no fragment. It has no
  final slash after a path. Write the scheme and the host in lowercase.
- Every Consumer token carries this address in `aud`, exactly as you set it.
- When you change the address, the next token carries the new one. A token that is already
  minted keeps the old address until it expires.

### The `resource` parameter (RFC 8707)

A Consumer can send one `resource` parameter with the mint. A client that reads your RFC 9728
metadata sends the `resource` that it names, exactly. That is your server address.

- No `resource`: the token is minted. It carries your address in `aud` all the same.
- One `resource` that names your address: the token is minted. keelie compares the scheme and
  the host in lowercase, and the rest exactly.
- Another address, an empty value, or more than one `resource`: no token. The answer is `400`
  with `{"error": "invalid_target"}`. The description does not tell your address.
- A request that is not a readable form: no token. The answer is `400` with
  `{"error": "invalid_request"}`. Send exactly one `Content-Type` header, with the value
  `application/x-www-form-urlencoded`. A `charset` parameter is allowed.

## The header

| Member | Rule |
|---|---|
| `alg` | Must be `RS256`. Refuse every other value before you look up a key. Do not let the header choose the algorithm. |
| `kid` | Must be present. It names the key in the key set of the realm. |
| `typ` | `JWT`. You do not need to check it. Check the `typ` claim. |

## The claims

| Claim | Value | Your check |
|---|---|---|
| `iss` | The `issuer` of your realm, from `GET /orgs/{orgId}`. | Must be equal. The `issuer` of the discovery document must be equal too. |
| `aud` | Your server address, the `resource` of your org. | Must contain your address. |
| `typ` | `Bearer` | Must be equal. |
| `exp` | Seconds since the epoch. | Required. Allow 30 seconds of clock difference. |
| `nbf`, `iat` | Seconds since the epoch. | Check them when they are present, with the same 30 seconds. |
| `azp` | The client id of the Consumer's credential. On a token for a person, the agent's client. | Required. It tells you which credential or agent sent the call. |
| `org_id` | Your org id, a UUID. It is the `id` of `GET /orgs/{orgId}`. | Required. Must be your org id. A token with another `org_id` belongs to another Provider. |
| `scope` | Space-separated scopes, from the Consumer's plan. | Split on a space. Allow a call only when the token has the scope that the call needs. |
| `jti` | The token id. | Log it. Never log the token. |
| `sub` | On a credential's token, not the credential. On a token for a person, the person. | On a credential's token, ignore it and use `azp`. On a token for a person, see below. |
| `consumer_id` | Only on a token for a person: the id of the Consumer. | See below. |

A claim that this table does not name is not part of these rules. Ignore it.

## The lifetime

- A token lives 30 minutes or less. The plan of the Consumer sets the longest lifetime.
- When the Consumer's credits balance runs down, the next token of a credential is shorter. keelie calculates the
  lifetime from the balance and the recent use, when it mints. A token is never shorter than a
  fixed minimum.
- keelie can refuse the next token, for example at the Consumer's spend cap. The answer is `400`
  with `{"error": "unauthorized_client"}`.
- So `exp` is the bound. A verifier checks `exp` and needs nothing else for the balance.

## A token for a person

An agent, such as Claude, can act for a person. The person signs in, sees the capabilities that
the agent asks for, and agrees. The agent then gets a token for that person, and a refresh
token. Each refresh token works once.

- `azp` is the agent's client. One agent's client serves every person.
- `sub` is the person, as an opaque id. It is the same for the same person each time. keelie
  stores no name and no email for the person.
- `consumer_id` is the Consumer whose plan and credits the person uses. Use it where you use
  `azp` for a credential's token.
- The other claims follow the rules above.

The person's Consumer is set before the person signs in. Your own identity provider sends it
when the person signs in through it, or an operator sets it. A person with no Consumer, or
with a Consumer that has no live subscription, gets no token. Neither does a person whose agent
asks for a capability that the Consumer's plan does not grant. The answer is `400` with
`{"error": "unauthorized_client"}`.

When you report use for a token for a person, send `consumer_id` with each event, beside `azp`
as `client_id`. The call then burns the credits of that Consumer. The SDK reads `consumer_id`
from the verified token and sends it. Rules:

- For a token for a person, `consumer_id` is required. For a credential's token, do not send it.
  The credential names its Consumer.
- The Consumer must have exactly one live subscription, as when the token was minted. If it has
  none, or more than one, keelie refuses the whole batch with `422` and the type
  `consumer-unknown`. A Consumer of another Provider gets the same answer.
- A subscription that is canceled after the call and before the report also refuses the batch.
  That window is the life of the token, at most 30 minutes, plus the time the SDK holds the event.
- keelie trusts the `consumer_id` that you send, as it trusts `client_id`. Use only the value from
  the verified token. Reported use burns a Consumer's balance. It is never an invoice line.

A token for a person always lives the shortest token lifetime of your own keelie subscription. keelie checks the
Consumer's credits and spend cap at each refresh. A refused refresh also ends the person's
session, so the person connects the agent again.

## The order of the checks

1. Parse the header. If it is not a JWT, refuse.
2. If `alg` is not `RS256`, refuse. Do not fetch a key for such a token.
3. If `kid` is missing, refuse.
4. Look up the key (below). If the key is unknown, refuse.
5. Verify the signature, `exp`, `nbf`, `iat`, `iss` and `aud`, with `RS256` only.
6. Check `typ`, `azp` and `org_id`.
7. Check the scope that the call needs.

Give the same answer for every refusal: `401` with
`WWW-Authenticate: Bearer error="invalid_token"` (RFC 6750 §3). Do not tell the caller the
reason. Write the reason in your own log. A token without the scope gets `403` with
`error="insufficient_scope"`.

## The key set

- Get `jwks_uri` from the discovery document. Fetch the key set once, and keep it in memory.
- Use only RSA keys that have a `kid`, with `use` equal to `sig` or no `use`, and `alg` equal to
  `RS256` or no `alg`. The key set can also hold an encryption key. Do not use it to verify.
  Skip a key that you cannot load, and load the others.
- For a `kid` that you do not have, fetch the key set one more time. If the key is still not
  there, refuse. Never fetch in a loop.
- Fetch at most once a minute, for any number of unknown `kid` values. A new signing key is then
  accepted within one minute.
- If a fetch fails and you have no keys, refuse the token and try again on the next request.
- If a fetch fails and you have keys, keep them and refuse only the unknown `kid`.
