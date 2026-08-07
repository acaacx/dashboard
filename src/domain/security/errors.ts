/**
 * Domain errors for scan ingestion.
 *
 * Rule: an error carries enough context to debug the *shape* of a problem and
 * never enough to leak the payload. Scanner output routinely contains secrets
 * (Gitleaks matches), internal hostnames and source code, so no error here
 * accepts or stores the raw input.
 */

export abstract class SecurityDomainError extends Error {
  /** Stable machine-readable code, safe to return over HTTP. */
  abstract readonly code: string;
  /** Suggested HTTP status when this surfaces at the API boundary. */
  readonly httpStatus: number = 400;

  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }

  /** Safe-by-construction serialization. Never includes payload fragments. */
  toJSON(): { code: string; message: string } {
    return { code: this.code, message: this.message };
  }
}

export class UnsupportedScannerError extends SecurityDomainError {
  readonly code = "UNSUPPORTED_SCANNER";
  readonly scanner: string;

  constructor(scanner: string) {
    super(`No adapter is registered for scanner "${scanner}".`);
    this.scanner = scanner;
  }
}

export class InvalidScannerOutputError extends SecurityDomainError {
  readonly code = "INVALID_SCANNER_OUTPUT";
  readonly scanner?: string;
  /** Dotted path to the offending node, e.g. "Results[0].Vulnerabilities". */
  readonly path?: string;

  constructor(message: string, options?: { scanner?: string; path?: string }) {
    super(message);
    this.scanner = options?.scanner;
    this.path = options?.path;
  }
}

export class InvalidSarifError extends SecurityDomainError {
  readonly code = "INVALID_SARIF";
  readonly path?: string;

  constructor(message: string, options?: { path?: string }) {
    super(`Invalid SARIF document: ${message}`);
    this.path = options?.path;
  }
}

export class NormalizationError extends SecurityDomainError {
  readonly code = "NORMALIZATION_FAILED";
  readonly scanner?: string;

  constructor(message: string, options?: { scanner?: string }) {
    super(message);
    this.scanner = options?.scanner;
  }
}

export class ScanIngestionError extends SecurityDomainError {
  readonly code = "SCAN_INGESTION_FAILED";
  readonly httpStatus = 500;
}

export class PayloadTooLargeError extends SecurityDomainError {
  readonly code = "PAYLOAD_TOO_LARGE";
  readonly httpStatus = 413;

  constructor(limitBytes: number) {
    super(`Scan payload exceeds the ${limitBytes} byte limit.`);
  }
}

export function isSecurityDomainError(
  error: unknown,
): error is SecurityDomainError {
  return error instanceof SecurityDomainError;
}

/**
 * Reduce any thrown value to a message that is safe to log and return.
 * Unknown errors are deliberately flattened: a third-party stack trace can
 * contain payload fragments.
 */
export function toSafeErrorMessage(error: unknown): string {
  if (isSecurityDomainError(error)) return error.message;
  if (error instanceof Error) return error.name;
  return "Unknown error";
}
