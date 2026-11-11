# keelie

**In development. The Keelie SDK for Ruby, by Apiable, is not released yet.** The gem is not on
RubyGems.

## What it is

The Ruby gem of the Keelie SDK: Rack middleware for Rails, Sinatra, Hanami and any other Rack app,
with a scope check for Rails controllers and a guard for an MCP server. Like the Python package, it:

- verifies tokens **inside your own process**, against a key set it fetches and caches, so there is
  no call to Apiable on the request path;
- enforces scopes per route, and per tool on an MCP server;
- reports usage back in batches **after** the response, from a background thread, and never blocks
  a request if that report fails.

A failed usage report does not stop a call. A failed token check does. That check is local.

```ruby
# config/initializers/keelie.rb
Rails.application.config.middleware.use Keelie::Rack::TokenGuard, verifier: verifier, metadata: metadata

# app/controllers/orders_controller.rb
class OrdersController < ActionController::API
  include Keelie::Rails::ScopeCheck
  keelie_scope_check KEELIE_SCOPES, KEELIE_METADATA
end
```

## Status

In development. Ruby 3.2 or later. No dependencies beyond Ruby itself.

Documentation: the [quickstart](https://github.com/apiable/keelie-sdk/blob/main/docs/quickstart.md)
for signup, and the [Ruby reference](https://github.com/apiable/keelie-sdk/blob/main/docs/ruby.md).

Source: <https://github.com/apiable/keelie-sdk>. Progress and early access: <https://apiable.io>.

## Develop

```bash
bundle config set --local path vendor/bundle
bundle install
bundle exec rake test   # no network
```

The tests run against Rails (Action Pack), against Puma, and against the official MCP Ruby SDK,
whose own client calls a guarded server.
