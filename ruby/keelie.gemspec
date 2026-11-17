# frozen_string_literal: true

require_relative "lib/keelie/version"

Gem::Specification.new do |spec|
  spec.name = "keelie"
  spec.version = Keelie::VERSION
  spec.authors = ["Apiable Oy"]
  spec.email = ["hello@apiable.io"]
  spec.summary = "The Keelie SDK, by Apiable. In development, not released."
  spec.description = "Token checks, scopes and usage reports for your API, inside your own " \
                     "process and off the request path. Rack middleware, a Rails scope check, " \
                     "and a guard for an MCP server."
  spec.homepage = "https://github.com/apiable/keelie-sdk/tree/main/ruby#readme"
  spec.license = "Apache-2.0"
  spec.required_ruby_version = ">= 3.2"
  spec.metadata = {
    "source_code_uri" => "https://github.com/apiable/keelie-sdk",
    "bug_tracker_uri" => "https://github.com/apiable/keelie-sdk/issues",
    "documentation_uri" => "https://github.com/apiable/keelie-sdk/blob/main/docs/ruby.md",
    "rubygems_mfa_required" => "true"
  }
  spec.files = Dir["lib/**/*.rb"] + %w[LICENSE NOTICE README.md]
  spec.require_paths = ["lib"]

  # No runtime dependencies: OpenSSL, Net::HTTP and JSON come with Ruby.
end
