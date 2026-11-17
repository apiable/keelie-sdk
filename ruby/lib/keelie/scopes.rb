# frozen_string_literal: true

module Keelie
  # The token does not carry the scope the route requires. Answer it with 403, not
  # 401: the token is good, it does not allow this call.
  class InsufficientScope < StandardError
    attr_reader :method, :route

    def initialize(method, route)
      super("#{method} #{route}")
      @method = method
      @route = route
    end
  end

  # The scope that each route requires.
  #
  # You give the SDK one map: for each route, the scope a token must carry. A route
  # is the HTTP method and the path template your framework matched, such as
  # +"GET /v1/orders/:order_id"+. Give the template, not the path of the request, so
  # that one entry covers every order.
  #
  # The check is strict:
  #
  # - A scope matches only itself. +orders:read+ does not grant +orders+, and
  #   +orders+ does not grant +orders:read+.
  # - A route matches only itself. There is no prefix and no wildcard.
  # - A route that is not in the map is refused. Add every route that a token may call.
  class ScopeMap
    # +routes+ maps each route to its one scope. A route is +"METHOD /template"+,
    # split at the first space, or a pair +[method, template]+. Raises ArgumentError
    # when a route is neither, a value is not exactly one scope, or a route is given
    # twice.
    def initialize(routes)
      @routes = {}
      routes.each do |route, scope|
        method, template = split(route)
        add(method, template, scope)
      end
      @routes.freeze
    end

    # @api private
    # A map from pairs that are already split, such as +["tools/call", tool_name]+.
    def self.from_pairs(pairs)
      new([]).tap do |map|
        map.instance_variable_set(:@routes, {})
        pairs.each { |method, template, scope| map.send(:add, method, template, scope) }
        map.instance_variable_get(:@routes).freeze
      end
    end

    # One scope, by the rule that splits the token's scope claim.
    def self.one_scope?(scope)
      scope.is_a?(String) && scope.valid_encoding? && scope.split(TokenVerifier::WHITESPACE) == [scope]
    end

    # Return if the token may call the route, else raise {InsufficientScope}.
    def check(claims, method, route)
      method = method.to_s.upcase
      required = @routes[[method, route]]
      return if required && claims.scopes.include?(required)

      # A route that is not in the map can come from the request, such as an MCP tool
      # name, and stays out of the log.
      Log.info("apiable.scope_refused reason=#{required ? "scope" : "unmapped"} client=#{claims.azp} " \
               "method=#{method} route=#{required ? route : "-"}")
      raise InsufficientScope.new(method, route)
    end

    private

    def split(route)
      if route.is_a?(Array) && route.size == 2 && route.all?(String)
        route
      elsif route.is_a?(String) && (at = route.index(" ")) && at.positive? && at < route.size - 1
        [route[0...at], route[(at + 1)..]]
      else
        raise ArgumentError, "not \"METHOD /route\": #{route.inspect}"
      end
    end

    def add(method, template, scope)
      raise ArgumentError, "not one scope: #{scope.inspect} for #{method} #{template}" unless ScopeMap.one_scope?(scope)

      key = [method.upcase, template].freeze
      raise ArgumentError, "route given twice: #{method} #{template}" if @routes.key?(key)

      @routes[key] = scope.dup.freeze
    end
  end
end
