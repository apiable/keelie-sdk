# frozen_string_literal: true

require "set"
require "stringio"

module Keelie
  # The Rack adapters. They work under any Rack app: Rails, Sinatra, Hanami, Roda.
  #
  # Every adapter checks a token through one core, {Guard}, and through nothing else.
  # Every adapter refuses a token in the same way: 401, an empty body, and
  # +WWW-Authenticate: Bearer error="invalid_token", resource_metadata="..."+. The
  # answer is the same for every reason. The reason goes to your log only.
  #
  # - {TokenGuard}, for a REST API. It checks the token and puts the claims in
  #   +env["keelie.claims"]+.
  # - {McpGuard}, for a Streamable HTTP MCP server. It checks the token, the scope of
  #   each tool call, and reports each tool call.
  # - {AiCatalog}, which serves your AI Catalog with no token.
  #
  # Each guard also serves the RFC 9728 metadata at +metadata.path+, with no token,
  # and refuses a request with no token with 401 and
  # +WWW-Authenticate: Bearer resource_metadata="..."+, so an agent can find your
  # issuer. Paths outside +resource+ and a CORS preflight (+OPTIONS+) pass untouched.
  #
  # Rack has no routes, so the scope of a REST route is checked in the route: see
  # {Keelie::Rails::ScopeCheck}, or call {ScopeMap#check} yourself.
  module Rack
    # Where the guards put the claims of a verified token.
    CLAIMS_KEY = "keelie.claims"

    # The part every adapter shares. An adapter adds only what it does with the claims.
    #
    # The verifier's audience must be the +resource+ of the metadata, or the guard does
    # not start. An agent asks keelie for a token with that +resource+ (RFC 8707), and
    # keelie writes your org's +resource+ into +aud+. A verifier for another audience
    # would refuse every such token, or accept a token for another server. Set your
    # org's +resource+ in keelie to the same value.
    #
    # The path compared is the path the client sent, as Rack gives it: +SCRIPT_NAME+
    # then +PATH_INFO+. It is compared in every form a Rack router could route it by:
    # as sent, with its escapes read, its dot segments resolved and its doubled slashes
    # folded, without a format extension such as +.json+, and without case. A request
    # that is under +resource+ in any of these forms is guarded. The guard can only
    # guard more than your router serves, never less.
    class Guard
      def initialize(app, verifier:, metadata:)
        if verifier.audience != metadata.resource
          raise ArgumentError, "the verifier's audience #{verifier.audience.inspect} is not the resource " \
                               "#{metadata.resource.inspect}: give both the same value"
        end

        @app = app
        @verifier = verifier
        @metadata = metadata
        @challenge = metadata.challenge
        @refusal = metadata.challenge("invalid_token")
      end

      def call(env)
        method = env["REQUEST_METHOD"]
        path = Rack.path(env)
        if path == @metadata.path && %w[GET HEAD].include?(method)
          # Before the token check: with a resource at the root, the metadata is under
          # it, and the agent reads it with no token.
          return Rack.respond(200, { "content-type" => "application/json" }, @metadata.document,
                              head: method == "HEAD")
        end
        return @app.call(env) unless Rack.guarded?(method, path, @metadata)

        token = Keelie.bearer_token(env["HTTP_AUTHORIZATION"])
        return Rack.respond(401, { "www-authenticate" => @challenge }) if token.nil?

        begin
          claims = @verifier.verify(token)
        rescue TokenRejected
          return Rack.respond(401, { "www-authenticate" => @refusal })
        end
        env[CLAIMS_KEY] = claims
        handle(claims, env)
      end

      private

      # Serve a request whose token verified.
      def handle(_claims, env) = @app.call(env)
    end

    # The REST adapter: checks the token, and gives the claims to your routes in
    # +env["keelie.claims"]+.
    #
    #   use Keelie::Rack::TokenGuard, verifier: verifier, metadata: metadata
    #
    # It does not check the scope. Middleware runs before the router, so it cannot see
    # the route template. Check the scope in each route, with
    # {Keelie::Rails::ScopeCheck} or {ScopeMap#check}. A route without it is
    # authenticated, but it has no scope check.
    class TokenGuard < Guard; end

    # Checks the token and the tool's scope, and reports each tool call.
    #
    #   use Keelie::Rack::McpGuard, verifier: verifier, metadata: metadata,
    #                               tools: { "classify" => "classify:run" }, reporter: reporter
    #
    # Give the MCP endpoint itself as the +resource+ of +metadata+: every POST under it
    # is read as JSON-RPC.
    #
    # What it checks on a request whose token verified:
    #
    # - A POST body is read in full, up to +max_body_bytes+, and handed on to your
    #   server unchanged, in a new +rack.input+. The method and the tool name come from
    #   the body only, never from the +Mcp-Method+ or +Mcp-Name+ header.
    # - A +tools/call+ needs the scope you mapped to its tool. A tool that is not in the
    #   map is refused. Add every tool that a token may call.
    # - Every other method passes with no scope check: +initialize+,
    #   +notifications/*+, +ping+, +tools/list+, and also +resources/*+ and
    #   +prompts/*+. Apiable sells tools, not resources or prompts.
    # - GET, HEAD and DELETE pass, and so does a CORS preflight (OPTIONS). Every other
    #   method gets 405, with +Allow: GET, POST, DELETE+.
    #
    # Every refusal is a JSON-RPC error:
    #
    # - 400, -32700: the body is not UTF-8 JSON, or it is nested too deeply.
    # - 400, -32600: the body is an array, is not an object, has a key twice, or is a
    #   +tools/call+ with no +id+. A batch is refused on purpose: MCP removed batches in
    #   2025-06-18, so a 2025-03-26 client that batches is cut.
    # - 400, -32602: a +tools/call+ whose +params.name+ is not a string.
    # - 413, -32600: the body is larger than +max_body_bytes+.
    # - 403, -31001, with +WWW-Authenticate: Bearer error="insufficient_scope"+: the
    #   token does not carry the tool's scope. The answer does not name the scope, on
    #   purpose: an unmapped tool and an unscoped tool look the same, so the answer does
    #   not show the map.
    #
    # The usage event is recorded when your server returns a 2xx status, before its
    # body is sent, so a +text/event-stream+ reply streams through unbuffered. The event
    # carries no +credits+.
    class McpGuard < Guard
      # The method of a tool call. It is also the method half of each key in the
      # adapter's ScopeMap: +["tools/call", tool_name]+.
      TOOLS_CALL = "tools/call"
      MAX_BODY_BYTES = 4 * 1024 * 1024
      # The methods that carry no tool call. They pass after the token check.
      PASS_METHODS = %w[GET HEAD DELETE].freeze
      PARSE_ERROR = -32_700
      INVALID_REQUEST = -32_600
      INVALID_PARAMS = -32_602
      # An application code: MCP keeps -32000 to -32099 for itself.
      INSUFFICIENT_SCOPE = -31_001

      # +tools+ maps each tool name to the one scope it requires, such as
      # +{ "get_order" => "orders:read" }+. +reporter+ is the process's one {UsageReporter}.
      def initialize(app, verifier:, metadata:, tools:, reporter:, max_body_bytes: MAX_BODY_BYTES)
        super(app, verifier: verifier, metadata: metadata)
        @scopes = ScopeMap.from_pairs(tools.map { |name, scope| [TOOLS_CALL, name.to_s, scope] })
        @reporter = reporter
        @max_body_bytes = max_body_bytes
        @scope_refusal = metadata.challenge("insufficient_scope")
      end

      private

      def handle(claims, env)
        method = env["REQUEST_METHOD"]
        return @app.call(env) if PASS_METHODS.include?(method)
        # A body under any other method could carry a tool call: refuse it.
        return Rack.respond(405, { "allow" => "GET, POST, DELETE" }) unless method == "POST"

        body = read(env["rack.input"])
        return error(413, nil, INVALID_REQUEST, "Request body too large") if body.nil?

        begin
          request = StrictJSON.strict(body)
        rescue StrictJSON::DuplicateKey
          return error(400, nil, INVALID_REQUEST, "Invalid Request")
        rescue JSON::ParserError
          return error(400, nil, PARSE_ERROR, "Parse error")
        end
        return error(400, nil, INVALID_REQUEST, "Invalid Request") unless request.is_a?(Hash)

        tool = nil
        if request["method"] == TOOLS_CALL
          id = request["id"]
          return error(400, nil, INVALID_REQUEST, "Invalid Request") unless id.is_a?(String) || id.is_a?(Integer)

          params = request["params"]
          name = params["name"] if params.is_a?(Hash)
          return error(400, id, INVALID_PARAMS, "Invalid params") unless name.is_a?(String)

          begin
            @scopes.check(claims, TOOLS_CALL, name)
          rescue InsufficientScope
            return error(403, id, INSUFFICIENT_SCOPE, "Insufficient scope", "www-authenticate" => @scope_refusal)
          end
          tool = name
        end

        # The server reads the very bytes that were checked.
        env["rack.input"] = StringIO.new(body)
        env["CONTENT_LENGTH"] = body.bytesize.to_s
        status, headers, response_body = @app.call(env)
        if tool && status.to_i.between?(200, 299)
          @reporter.record(claims.azp, tool, unit: "tool_call", consumer_id: claims.consumer_id)
        end
        [status, headers, response_body]
      end

      # The body, read in full, or nil if it is larger than the limit.
      def read(input)
        body = +"".b
        return body if input.nil?

        chunk = +""
        while input.read(16_384, chunk)
          body << chunk
          return nil if body.bytesize > @max_body_bytes
        end
        body
      end

      def error(status, id, code, message, headers = {})
        Log.info("apiable.mcp_refused status=#{status} code=#{code}")
        body = JSON.generate({ "jsonrpc" => "2.0", "id" => id, "error" => { "code" => code, "message" => message } })
        Rack.respond(status, headers.merge("content-type" => "application/json"), body)
      end
    end

    # Serves your AI Catalog at +/.well-known/ard.json+ and +/.well-known/ai-catalog.json+,
    # with no token. Other requests pass untouched.
    #
    #   use Keelie::Rack::AiCatalog, catalog: Keelie::AiCatalog.new(keelie, metadata)
    #
    # The order beside the token guards does not matter: once the catalog is made with
    # +metadata+, the guards let a GET or a HEAD of its two paths pass.
    class AiCatalog
      def initialize(app, catalog:)
        @app = app
        @catalog = catalog
      end

      def call(env)
        method = env["REQUEST_METHOD"]
        answer = @catalog.answer(Rack.path(env)) if %w[GET HEAD].include?(method)
        return @app.call(env) if answer.nil?

        status, headers, body = answer
        [status, headers, method == "HEAD" ? [] : body]
      end
    end

    # The most forms of one path the guard compares, besides the fully normalized one.
    MAX_FORMS = 128

    class << self
      # @api private
      # The path of the request as the client sent it, without the query.
      def path(env)
        "#{env["SCRIPT_NAME"]}#{env["PATH_INFO"]}"
      end

      # @api private
      # True for a request under +resource+ that must carry a token.
      #
      # A CORS preflight (OPTIONS) and every path outside +resource+ pass. So does a GET
      # or a HEAD of the metadata, and of the AI Catalog at either of its paths when the
      # catalog serves it. Any other method on those paths needs a token.
      def guarded?(method, path, metadata)
        return false if method == "OPTIONS"
        if %w[GET HEAD].include?(method) &&
           (path == metadata.path || (metadata.ai_catalog && CATALOG_MEDIA_TYPES.key?(path)))
          return false
        end

        prefixes = [metadata.prefix, unescape(metadata.prefix)].map { _1.downcase(:ascii) }.uniq
        return true if prefixes.include?("")

        forms(path).any? do |form|
          form = form.downcase(:ascii)
          prefixes.any? { |prefix| form == prefix || form.start_with?("#{prefix}/") }
        end
      end

      # @api private
      # The forms of +path+ a Rack router could route by, as binary Strings: each step of
      # each normalization a router makes, alone and in turn, and the path with all of
      # them made until nothing changes.
      def forms(path)
        path = path.to_s.b
        seen = Set[path]
        queue = [path]
        until queue.empty? || seen.size >= MAX_FORMS
          steps(queue.shift).each { |form| queue << form if seen.add?(form) }
        end
        seen.to_a + normalized(path)
      end

      # @api private
      # One normalization each: a leading slash, escapes read, backslashes as slashes,
      # dot segments resolved, doubled slashes folded, and a format extension dropped.
      def steps(form)
        [
          form.start_with?("/") ? form : "/#{form}",
          unescape(form),
          form.tr("\\", "/"),
          resolve_dots(form),
          form.squeeze("/"),
          form.sub(%r{\.[^/]*\z}, "")
        ]
      end

      # @api private
      # Every step made, over and over, until nothing changes: with and without the
      # format extension dropped.
      def normalized(path)
        form = path
        8.times do
          next_form = "/#{resolve_dots(unescape(form).tr("\\", "/"))}".squeeze("/")
          break if next_form == form

          form = next_form
        end
        [form, form.sub(%r{\.[^/]*\z}, "")]
      end

      # @api private
      def unescape(text)
        text.b.gsub(/%[0-9a-fA-F]{2}/) { [_1[1, 2]].pack("H2") }
      end

      # @api private
      # The path with its "." and ".." segments resolved (RFC 3986, section 5.2.4).
      def resolve_dots(path)
        output = []
        segments = path.split("/", -1)
        segments.each_with_index do |segment, index|
          last = index == segments.size - 1
          case segment
          when "." then output << "" if last
          when ".."
            output.pop if output.size > 1
            output << "" if last
          else output << segment
          end
        end
        output.join("/")
      end

      # @api private
      def respond(status, headers, body = "", head: false)
        [status, headers.merge("content-length" => body.bytesize.to_s), head ? [] : [body]]
      end
    end
  end
end
