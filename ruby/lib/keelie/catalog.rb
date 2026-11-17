# frozen_string_literal: true

module Keelie
  # Your AI Catalog, fetched from keelie and kept for 60 seconds.
  #
  # The catalog is served at +/.well-known/ard.json+, where ARD v0.91 looks for it, and
  # at +/.well-known/ai-catalog.json+, where the ai-catalog specification looks and an
  # MCP proposal points. Both paths serve the same body, from the same copy.
  #
  # keelie builds the catalog from your published plans. A plan you publish shows here
  # within 60 seconds, and within up to 120 seconds at a client that caches the answer.
  #
  # The SDK does not change the document. It keeps no copy past 60 seconds: if keelie
  # does not answer when the copy is old, the answer is 503, not an old catalog. After
  # a failure, it asks keelie again after 10 seconds, not on each request. One fetch
  # serves every request that arrives while it runs.
  #
  # Serve it with the Rack middleware {Rack::AiCatalog}, or call {#answer} from any
  # other server.
  class AiCatalog
    # The one place that names keelie's catalog endpoint.
    KEELIE_PATH = "/ai-catalog"
    CACHE_SECONDS = 60.0
    RETRY_SECONDS = 10.0

    # +keelie+ sends a request to keelie with the auth of a credential that may read
    # products, as for the usage reporter: a {SdkCredential}. +metadata+ is the one your
    # token guard uses. Making it with +metadata+ tells the token guards to let a GET or
    # a HEAD of the two catalog paths pass with no token. Without it, they guard the
    # paths like any other.
    def initialize(keelie, metadata, clock: nil)
      @keelie = keelie
      metadata.ai_catalog = true
      @clock = clock || -> { Process.clock_gettime(Process::CLOCK_MONOTONIC) }
      @body = nil
      @fetched_at = 0.0
      @failed_at = nil
      @lock = Mutex.new
    end

    # The answer for +path+ as a Rack triple +[status, headers, [body]]+, or nil if
    # +path+ is not a catalog path.
    def answer(path)
      media_type = CATALOG_MEDIA_TYPES[path]
      return nil if media_type.nil?

      body = catalog
      if body.nil?
        return [503, { "retry-after" => "10", "cache-control" => "no-store", "content-length" => "0" }, []]
      end

      [200, { "content-type" => media_type, "cache-control" => "max-age=60",
              "content-length" => body.bytesize.to_s }, [body]]
    end

    private

    # The catalog, fetched again when the copy is 60 seconds old. nil if keelie fails.
    def catalog
      return @body if settled?

      @lock.synchronize do
        # One fetch for many requests at once: the others read what it got, or its failure.
        return @body if settled?

        @body = nil
        begin
          response = @keelie.call("GET", KEELIE_PATH)
        rescue StandardError => e
          Log.warn("apiable.catalog_fetch_failed error=#{e.class.name}")
          @failed_at = @clock.call
          return nil
        end
        if response.status != 200
          Log.warn("apiable.catalog_fetch_failed status=#{response.status}")
          @failed_at = @clock.call
          return nil
        end
        @fetched_at = @clock.call
        @failed_at = nil
        @body = response.body.b.freeze
      end
    end

    # True while the copy is fresh, or while a failure is recent: no fetch is due.
    def settled?
      now = @clock.call
      return now - @failed_at < RETRY_SECONDS if @failed_at

      !@body.nil? && now - @fetched_at < CACHE_SECONDS
    end
  end
end
