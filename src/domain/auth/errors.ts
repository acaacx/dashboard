/**
 * Domain errors for authentication.
 *
 * Mirrors `src/domain/security/errors.ts`. Rule: an error names the shape of a
 * problem and never the credential. No error here accepts a password or a
 * session token, so none can leak one into a log or an HTTP body.
 */

export abstract class AuthDomainError extends Error {
  abstract readonly code: string;
  readonly httpStatus: number = 400;

  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }

  toJSON(): { code: string; message: string } {
    return { code: this.code, message: this.message };
  }
}

/**
 * Wrong password, or no such account. Deliberately one error for both: a
 * distinct "no such user" is an account-enumeration oracle.
 */
export class InvalidCredentialsError extends AuthDomainError {
  readonly code = "INVALID_CREDENTIALS";
  readonly httpStatus = 401;

  constructor() {
    super("Email or password is incorrect.");
  }
}

export class TooManyAttemptsError extends AuthDomainError {
  readonly code = "TOO_MANY_ATTEMPTS";
  readonly httpStatus = 429;
  readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    const minutes = Math.max(1, Math.ceil(retryAfterSeconds / 60));
    super(`Too many attempts. Try again in ${minutes} minute${minutes === 1 ? "" : "s"}.`);
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

export class DuplicateUserError extends AuthDomainError {
  readonly code = "DUPLICATE_USER";
  readonly httpStatus = 409;

  constructor(email: string) {
    super(`An account already exists for ${email}.`);
  }
}

export class UserNotFoundError extends AuthDomainError {
  readonly code = "USER_NOT_FOUND";
  readonly httpStatus = 404;

  constructor(email: string) {
    super(`No account exists for ${email}.`);
  }
}

/** Never quotes the password, not even its length beyond the minimum. */
export class WeakPasswordError extends AuthDomainError {
  readonly code = "WEAK_PASSWORD";

  constructor(minimum: number) {
    super(`A password must be at least ${minimum} characters.`);
  }
}

/**
 * No usable session: absent, expired, revoked, or belonging to a deleted user.
 *
 * A Server Action reports this as a value rather than redirecting. The caller is
 * a fetch from an open drawer, so a redirect would be followed by that fetch and
 * the user would see nothing happen.
 */
export class NotAuthenticatedError extends AuthDomainError {
  readonly code = "UNAUTHENTICATED";
  readonly httpStatus = 401;

  constructor() {
    super("Your session has expired. Sign in again to continue.");
  }
}

/** Signed in, but the role does not permit this. Names no credential. */
export class ForbiddenError extends AuthDomainError {
  readonly code = "FORBIDDEN";
  readonly httpStatus = 403;

  constructor() {
    super("Approver role is required to change a finding's status.");
  }
}

export function isAuthDomainError(error: unknown): error is AuthDomainError {
  return error instanceof AuthDomainError;
}
