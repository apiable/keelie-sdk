<?php

declare(strict_types=1);

namespace Keelie\Middleware;

use Keelie\Claims;
use Keelie\InsufficientScope;
use Keelie\Internal\DuplicateKey;
use Keelie\Internal\Json;
use Keelie\Internal\JsonError;
use Keelie\Internal\JsonObject;
use Keelie\Internal\Responses;
use Keelie\Log;
use Keelie\ProtectedResourceMetadata;
use Keelie\ScopeMap;
use Keelie\TokenVerifier;
use Keelie\UsageReporter;
use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamFactoryInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The guard for a Streamable HTTP MCP server. It checks the token and the tool's
 * scope, and reports each tool call.
 *
 * Give the MCP endpoint itself as the `resource` of the metadata: every POST under
 * it is read as JSON-RPC.
 *
 * What it checks on a request whose token verified:
 *
 * - A POST body is read in full, up to `$maxBodyBytes`, and handed on to your
 *   server unchanged, in a new stream. The method and the tool name come from the
 *   body only, never from the `Mcp-Method` or `Mcp-Name` header.
 * - A `tools/call` needs the scope you mapped to its tool. A tool that is not in
 *   the map is refused. Add every tool that a token may call.
 * - Every other method passes with no scope check: `initialize`,
 *   `notifications/*`, `ping`, `tools/list`, and also `resources/*` and
 *   `prompts/*`. Apiable sells tools, not resources or prompts.
 * - GET, HEAD and DELETE pass, and so does a CORS preflight (OPTIONS). Every
 *   other method gets 405, with `Allow: GET, POST, DELETE`.
 *
 * Every refusal is a JSON-RPC error:
 *
 * - 400, -32700: the body is not UTF-8 JSON, or it is nested too deeply.
 * - 400, -32600: the body is an array, is not an object, has a key twice, or is
 *   a `tools/call` with no `id`. A batch is refused on purpose: MCP removed
 *   batches in 2025-06-18.
 * - 400, -32602: a `tools/call` whose `params.name` is not a string.
 * - 413, -32600: the body is larger than `$maxBodyBytes`.
 * - 403, -31001, with `WWW-Authenticate: Bearer error="insufficient_scope"`: the
 *   token does not carry the tool's scope. The answer does not name the scope, on
 *   purpose: an unmapped tool and an unscoped tool look the same.
 *
 * One `tool_call` event is recorded when your server returns a 2xx response. The
 * event carries no credits.
 */
final class McpGuard extends Guard
{
    /** The method of a tool call. It is also the method half of each key in the guard's ScopeMap. */
    public const TOOLS_CALL = 'tools/call';
    public const MAX_BODY_BYTES = 4 * 1024 * 1024;
    /** The methods that carry no tool call. They pass after the token check. */
    private const PASS_METHODS = ['GET', 'HEAD', 'DELETE'];
    private const PARSE_ERROR = -32700;
    private const INVALID_REQUEST = -32600;
    private const INVALID_PARAMS = -32602;
    /** An application code: MCP keeps -32000 to -32099 for itself. */
    private const INSUFFICIENT_SCOPE = -31001;

    private readonly ScopeMap $scopes;
    private readonly string $scopeRefusal;

    /**
     * @param array<string, string> $tools each tool name and the one scope it requires,
     *                                     such as `['get_order' => 'orders:read']`
     * @param UsageReporter $reporter the process's one usage reporter
     */
    public function __construct(
        TokenVerifier $verifier,
        ProtectedResourceMetadata $metadata,
        ResponseFactoryInterface $responses,
        private readonly StreamFactoryInterface $streams,
        array $tools,
        private readonly UsageReporter $reporter,
        private readonly int $maxBodyBytes = self::MAX_BODY_BYTES,
    ) {
        parent::__construct($verifier, $metadata, $responses);
        $pairs = [];
        foreach ($tools as $name => $scope) {
            $pairs[] = [self::TOOLS_CALL, (string) $name, $scope];
        }
        $this->scopes = ScopeMap::fromPairs($pairs);
        $this->scopeRefusal = $metadata->challenge('insufficient_scope');
    }

    protected function handle(
        Claims $claims,
        ServerRequestInterface $request,
        RequestHandlerInterface $handler,
    ): ResponseInterface {
        $method = $request->getMethod();
        if (in_array($method, self::PASS_METHODS, true)) {
            return $handler->handle($request);
        }
        // A body under any other method could carry a tool call: refuse it.
        if ($method !== 'POST') {
            return Responses::make($this->responses, 405, ['Allow' => 'GET, POST, DELETE']);
        }

        $body = $this->read($request->getBody());
        if ($body === null) {
            return $this->error(413, null, self::INVALID_REQUEST, 'Request body too large');
        }
        try {
            $message = Json::strict($body);
        } catch (DuplicateKey) {
            return $this->error(400, null, self::INVALID_REQUEST, 'Invalid Request');
        } catch (JsonError) {
            return $this->error(400, null, self::PARSE_ERROR, 'Parse error');
        }
        if (!$message instanceof JsonObject) {
            return $this->error(400, null, self::INVALID_REQUEST, 'Invalid Request');
        }

        $tool = null;
        if ($message->get('method') === self::TOOLS_CALL) {
            $id = $message->get('id');
            if (!is_string($id) && !is_int($id)) {
                return $this->error(400, null, self::INVALID_REQUEST, 'Invalid Request');
            }
            $params = $message->get('params');
            $name = $params instanceof JsonObject ? $params->get('name') : null;
            if (!is_string($name)) {
                return $this->error(400, $id, self::INVALID_PARAMS, 'Invalid params');
            }
            try {
                $this->scopes->check($claims, self::TOOLS_CALL, $name);
            } catch (InsufficientScope) {
                return $this->error(403, $id, self::INSUFFICIENT_SCOPE, 'Insufficient scope', [
                    'WWW-Authenticate' => $this->scopeRefusal,
                ]);
            }
            $tool = $name;
        }

        // The server reads the very bytes that were checked.
        $response = $handler->handle($request->withBody($this->streams->createStream($body)));
        $status = $response->getStatusCode();
        if ($tool !== null && $status >= 200 && $status <= 299) {
            $this->reporter->record($claims->azp, $tool, unit: 'tool_call', consumerId: $claims->consumerId);
        }

        return $response;
    }

    /** The body, read in full, or null if it is larger than the limit. */
    private function read(StreamInterface $stream): ?string
    {
        if ($stream->isSeekable()) {
            $stream->rewind();
        }
        $body = '';
        while (!$stream->eof()) {
            $chunk = $stream->read(16384);
            if ($chunk === '') {
                break;
            }
            $body .= $chunk;
            if (strlen($body) > $this->maxBodyBytes) {
                return null;
            }
        }

        return $body;
    }

    /** @param array<string, string> $headers */
    private function error(int $status, string|int|null $id, int $code, string $message, array $headers = []): ResponseInterface
    {
        Log::info("apiable.mcp_refused status={$status} code={$code}");
        $body = json_encode(
            ['jsonrpc' => '2.0', 'id' => $id, 'error' => ['code' => $code, 'message' => $message]],
            JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR,
        );

        return Responses::make($this->responses, $status, $headers + ['Content-Type' => 'application/json'], $body);
    }
}
