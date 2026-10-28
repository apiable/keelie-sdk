# keelie webhooks

This page is for a Provider who receives events from keelie. keelie sends each event as an HTTP
`POST` to an endpoint that you register. Each message is signed. The signature follows the
[Standard Webhooks](https://www.standardwebhooks.com/) specification.

A webhook is a notification. It is not an invoice, and it moves no money.

## Register an endpoint

- Send `POST /webhook-endpoints` with `url` and `event_types`. Your credential needs the scope
  `webhooks:write`.
- The URL uses `https` on port 443 and has a host name. It has no user and no fragment. The
  address must be on the public internet.
- The answer holds `secret`, which starts with `whsec_`. **keelie shows the secret once.** Store
  it now. keelie cannot show it again.
- You can register at most 10 endpoints.
- `GET /webhook-endpoints` lists your endpoints. `PATCH` and `DELETE` on
  `/webhook-endpoints/{webhookEndpointId}` change or remove one. Reads need `webhooks:read`.
- To get a new secret, delete the endpoint and register it again.

## The events

| Event | When keelie sends it |
|---|---|
| `usage.threshold` | The spend of a Consumer in this UTC month reached the alert level of its limit. |
| `subscription.created` | You subscribed a Consumer to a plan. |
| `subscription.updated` | You changed a subscription, for example its spend cap. Also when the state of its automatic top-up changes. |
| `credential.revoked` | A credential was revoked. It mints no new token. |

Each body is JSON with three members:

```json
{
  "type": "credential.revoked",
  "timestamp": "2026-10-20T09:41:00.123456Z",
  "data": {
    "id": "01a01e21-6f52-71ff-b46c-fd247e435c0e",
    "client_id": "01a0c35ea80371e6af8c18efc3c768f4",
    "subscription_id": "01a01e21-6f52-71ff-b46c-fd229f3f6b29",
    "revoked_at": "2026-10-20T09:41:00.123456Z"
  }
}
```

- `data` holds ids and the change. It never holds a secret.
- Credits are decimal strings, such as `"10.5"`.
- Read the current state with the API when you need more than the ids.

The `data` of each event:

- `usage.threshold`: `subscription_id`, `spent`, `limit`, `limit_applied` (`spend_cap` or
  `cost_ceiling`) and `percent`.
- `subscription.created` and `subscription.updated`: `id`, `subject_id`, `plan_id`, `status`,
  `spend_cap` (`null` when there is none), `spend_alert_percent`, `auto_reload` (`threshold` and
  `pack`, or `null` when it is off) and `auto_reload_state`. When `auto_reload_state` is `failed`
  or `action_required`, the bank refused a charge, and keelie charges nothing more. Ask the
  Consumer to top up and save a card, or send their new consent in `auto_reload`.
- `credential.revoked`: `id`, `client_id`, `subscription_id` and `revoked_at`.

## Check the signature

Each message carries three headers:

| Header | Value |
|---|---|
| `webhook-id` | The message id, for example `msg_01a01e216f5271ffb46cfd3b7d1e8c42`. It is the same on every try. |
| `webhook-timestamp` | The time of this try, in seconds since 1970-01-01 UTC. |
| `webhook-signature` | One or more signatures, separated by a space. Each one is `v1,` and base64. |

Do these steps for each message:

1. Read the body as raw bytes. Do not parse it and serialize it again before the check.
2. Remove `whsec_` from your secret. Decode the rest with standard base64. The result is the key.
3. Make the signed content: `{webhook-id}.{webhook-timestamp}.{body}`.
4. Compute HMAC-SHA256 of the signed content with the key. Encode the result with standard
   base64.
5. Compare your value with each `v1,` signature in the header. Use a constant-time compare.
   Accept the message if one of them is equal.
6. Refuse a message whose timestamp is more than 5 minutes from your clock.

You can use a Standard Webhooks library instead of these steps. It does the same check:

```python
from standardwebhooks.webhooks import Webhook

payload = Webhook(secret).verify(raw_body, headers)
```

Libraries for other languages are at
[github.com/standard-webhooks/standard-webhooks](https://github.com/standard-webhooks/standard-webhooks/tree/main/libraries).

## Answer, and the retries

- Answer with a `2xx` status code within 15 seconds. keelie does not read your answer's body.
- Any other answer, a time-out or a connection error is a failure. A `3xx` is a failure too:
  keelie follows no redirect. Change the URL instead.
- keelie tries a failed message again after 5 seconds, 5 minutes, 30 minutes, 2 hours, 5 hours,
  10 hours, 14 hours, 20 hours and 24 hours. That is 10 tries in about 75 hours. Each wait can
  move by up to 10 percent.
- When you answer with `Retry-After`, keelie waits at least that long, up to 24 hours.
- A message can arrive more than once. Use `webhook-id` to find a repeat.
- Messages can arrive out of order. Use `timestamp` in the body to order them.

## A disabled endpoint

keelie disables an endpoint in two cases:

- A message failed all 10 tries. `disabled_reason` is `retries_exhausted`.
- The endpoint answered `410 Gone`. `disabled_reason` is `gone`.

A disabled endpoint receives nothing. keelie does not keep the events that happen while it is
disabled.

- `GET /webhook-endpoints/{webhookEndpointId}` shows `status` and `disabled_reason`.
- `GET /webhook-endpoints/{webhookEndpointId}/deliveries` shows each message, how many tries
  keelie made, the next try, the last status code and the reason the last try failed.
- To turn the endpoint on again, send `PATCH` with `{"status": "active"}`.
