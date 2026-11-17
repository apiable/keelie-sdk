/**
 * Where the SDK writes its log lines.
 *
 * Each line is one fixed event name and its fields, such as
 * `apiable.token_rejected reason=expired`. The names are the Python SDK's, so one
 * search finds an event in both. No line holds a token, a secret or a value
 * taken from the request.
 *
 * By default `warn` goes to `console.warn`, and `info` and `debug` are dropped.
 * Give your own logger with {@link setLogger}: pino, winston and `console` all
 * fit.
 */

export interface Logger {
  debug(message: string): void;
  info(message: string): void;
  warn(message: string): void;
}

const quiet: Logger = {
  debug() {},
  info() {},
  warn(message) {
    console.warn(message);
  },
};

let current: Logger = quiet;

/** Send the SDK's log lines to `logger`. Give `undefined` for the default. */
export function setLogger(logger: Logger | undefined): void {
  current = logger ?? quiet;
}

/** @internal */
export const log: Logger = {
  debug: (message) => current.debug(message),
  info: (message) => current.info(message),
  warn: (message) => current.warn(message),
};

/** @internal The name of an error, for a log line. Never its message. */
export function errorName(error: unknown): string {
  return error instanceof Error ? error.name : typeof error;
}
