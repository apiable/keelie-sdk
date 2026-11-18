# The keelie client secrets

This page is for a Provider who wants to find a keelie client secret in a commit, a log or a
paste. Add the rule below to your secret scanner. A scanner then reports a leaked secret before
someone else uses it.

## The form of a secret

A credential is a client ID and a client secret. keelie shows the client secret once, when it
makes the credential. Each new client secret starts with a fixed prefix:

| Prefix | Where the secret comes from |
|---|---|
| `keelie_live_` | Production. |
| `keelie_test_` | Every other environment. |

After the prefix come 43 characters from the URL-safe alphabet: `A` to `Z`, `a` to `z`, `0` to
`9`, `-` and `_`.

The prefix is a label for scanners. It has no other function. Do not read it in your code to
make a decision.

**A secret made before the prefix has no prefix.** It keeps working, and a scanner cannot find
it. To get a secret that a scanner can find for a credential of a Consumer, make a new
credential and revoke the old one.

## A rule for gitleaks

Add this rule to your `.gitleaks.toml`:

```toml
[[rules]]
id = "keelie-client-secret"
description = "keelie client secret"
regex = '''keelie_(live|test)_[A-Za-z0-9_-]{43}'''
keywords = ["keelie_live_", "keelie_test_"]
```

Other scanners take the same regular expression.

## If a secret leaks

These steps are for a credential that you issued to a Consumer. If the secret of your own admin
or SDK credential leaks, contact Apiable at once.

1. Revoke the credential at once: `POST /credentials/{credentialId}:revoke`. The credential then
   mints no new token.
2. Make a new credential, and put its secret in the place of the old one.
3. Remove the secret from the commit history, or treat it as public for ever.

A token minted before the revoke lives until it expires. The answer to the revoke says when, in
`tokens_expire_by`.
