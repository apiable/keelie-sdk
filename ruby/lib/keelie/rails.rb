# frozen_string_literal: true

module Keelie
  # The scope check for a Rails controller (Rails 7.1 or later).
  #
  #   class OrdersController < ActionController::API
  #     include Keelie::Rails::ScopeCheck
  #     keelie_scope_check KEELIE_SCOPES, KEELIE_METADATA
  #   end
  #
  # It runs before each action, and checks the route Rails matched: the request's
  # method and the route's path as you wrote it in +config/routes.rb+, scopes
  # included, without +(.:format)+. That is the template +bin/rails routes+ shows,
  # such as +GET /v1/orders/:order_id+. A refused token gets 403,
  # +WWW-Authenticate: Bearer error="insufficient_scope", resource_metadata="..."+ and
  # an empty body.
  #
  # The method is the one the request was routed by. Rails serves a HEAD request with
  # a GET route, and the check is then for +HEAD /v1/...+, which the map must name.
  #
  # {Rack::TokenGuard} must run first, as middleware. Without its claims the action
  # raises {Keelie::Error}, so that the mistake shows as a 500.
  #
  # A route inside a mounted engine shows the engine's own path, without the path it
  # is mounted at. There, call +KEELIE_SCOPES.check(keelie_claims, request.request_method, template)+
  # in the action.
  module Rails
    module ScopeCheck
      def self.included(base)
        base.extend(ClassMethods)
      end

      module ClassMethods
        # Check the scope before each action, or before those that +options+ name, as
        # for +before_action+ (+only:+, +except:+).
        def keelie_scope_check(scopes, metadata, **options)
          refusal = metadata.challenge("insufficient_scope")
          before_action(**options) { keelie_check_scope(scopes, refusal) }
        end
      end

      # The claims of the request's token, from {Rack::TokenGuard}, or nil.
      def keelie_claims = request.get_header(Keelie::Rack::CLAIMS_KEY)

      # The route Rails matched, as the scope map names it, such as
      # +"GET /v1/orders/:order_id"+. nil if no route matched.
      def keelie_route
        pattern = request.route_uri_pattern
        pattern && "#{request.request_method} #{pattern.delete_suffix("(.:format)")}"
      end

      private

      def keelie_check_scope(scopes, refusal)
        claims = keelie_claims
        raise Keelie::Error, "keelie: the scope check needs Keelie::Rack::TokenGuard to run before it" if claims.nil?

        pattern = request.route_uri_pattern
        # A route with no plain path is in no map.
        template = pattern ? pattern.delete_suffix("(.:format)") : "\u0000"
        scopes.check(claims, request.request_method, template)
      rescue InsufficientScope
        response.headers["WWW-Authenticate"] = refusal
        head :forbidden
      end
    end
  end
end
