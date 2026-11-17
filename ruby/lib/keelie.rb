# frozen_string_literal: true

# The Keelie SDK, by Apiable. In development, not released.
#
# Source: https://github.com/apiable/keelie-sdk
#
# It verifies tokens inside your own process, against the issuer's key set, which it
# fetches and caches, and checks their scope against the route. It reports usage in
# batches, in a background thread. It does not sit in the request path. It serves the
# RFC 9728 metadata that tells an agent where to get a token, and your AI Catalog,
# which keelie builds from your published plans.
#
# The core has no framework in it. {Keelie::Rack} holds the Rack middleware, for a
# REST API and for an MCP server, and {Keelie::Rails::ScopeCheck} the scope check for
# a Rails controller. None of them loads Rack or Rails: they need only what your app
# already runs.
module Keelie
  # A mistake in how the SDK is set up or called, such as a scope check with no token
  # guard before it, or a token endpoint that refuses the SDK credential.
  class Error < StandardError; end
end

require_relative "keelie/version"
require_relative "keelie/log"
require_relative "keelie/uuid"
require_relative "keelie/json"
require_relative "keelie/http"
require_relative "keelie/keys"
require_relative "keelie/tokens"
require_relative "keelie/scopes"
require_relative "keelie/discovery"
require_relative "keelie/credential"
require_relative "keelie/catalog"
require_relative "keelie/usage"
require_relative "keelie/rack"
require_relative "keelie/rails"
