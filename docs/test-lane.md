# The test lane

This page is for a Provider who wants to try its paid plans before it charges anyone. Your test
lane is a second org, linked to your live org. It charges in Stripe's test mode. Your Consumers
pay there with Stripe's test cards, and no money moves.

## Open the test lane

- Send `POST /orgs/{orgId}:open-test-lane` with the admin credential of your live org. The
  credential needs the scope `orgs:write`.
- The answer is `201`. It holds the test org, its admin credential and its SDK credential.
  **keelie shows the two secrets once.** Store them now.
- The test org's slug is your slug with `-test` at the end. Its name ends with `(test)`. Its
  `live_org_id` is the id of your live org.
- A live org has one test lane. A second call answers `409`, and the answer names the test org.
- The test org is an org of its own. Its products, plans, Consumers, credentials, balances and
  webhook endpoints are its own. Nothing moves between the two orgs.
- To give your staff the console of the test org, add each person with
  `PUT /orgs/{testOrgId}/members/{userId}`, with the test org's admin credential.

## Test your paid path

1. Send `POST /orgs/{testOrgId}:connect-stripe` with the test org's admin credential. Stripe
   makes an account in test mode. Complete Stripe's page with test data.
2. Make your products and plans in the test org, and publish the plans.
3. Subscribe a test Consumer, and issue its credential.
4. Pay with a Stripe test card, for example `4242 4242 4242 4242`. The page of a payment gets
   a publishable key of Stripe's test mode.
5. Mint a token with the Consumer's credential, and call your API with it.

The test org mints tokens for 10 new Consumer credentials each month. A credential that already
got a token this month keeps getting them. The 11th new credential gets no token until the first
of the next month. The test lane is for tests, not for real traffic.

## What a test token reaches

keelie is never in the path of a call to your API. Your SDK checks each token. A token of the
test org has the test org's `iss` and the test org's `org_id`.

- An SDK set up for your live org refuses a test token.
- An SDK set up for your test org refuses a live token.

To test, run a second setup of the SDK with the test org's values: its `issuer`, its `id` and
its SDK credential. Run it on a staging copy of your API, or beside your live setup. You decide
what a test token reaches.

## Go live

There is no switch. A test plan never becomes a live plan, so a test balance never becomes a
real one.

1. Connect your Stripe account in the live org: `POST /orgs/{orgId}:connect-stripe`.
2. Make the same products and plans in the live org, with the same calls you used in the test
   org, and publish them.
3. Subscribe your real Consumers in the live org.

The test lane stays open. Use it again to try a new plan before you publish it in the live org.
