# Contributing

Thank you for helping. The SDK is in its first months, so open an issue before a large change,
and we agree the shape first.

## The Developer Certificate of Origin

Every commit must carry a `Signed-off-by` line. With it, you certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org/): that you wrote the change,
or have the right to submit it under the licence of this repository, and that the contribution and
your sign-off are public.

Add the line with `git commit -s`:

```
Signed-off-by: Your Name <you@example.com>
```

Use your real name. A check on every pull request refuses a commit without the line.

## Licence of contributions

This repository is licensed under the Apache License 2.0. Under section 5 of that licence, a
contribution you submit is licensed under the same terms.

## Rules

- Keep each pull request to one change.
- The SDK is never in the path of the API call, and nothing it reports is billed. A change that
  breaks either rule is not merged.
- Report a vulnerability privately, never in an issue. See [SECURITY.md](SECURITY.md).
