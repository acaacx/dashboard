import type { User, UserRole } from "@/domain/auth/user";

export interface CreateUserInput {
  email: string;
  passwordHash: string;
  role: UserRole;
}

/**
 * User store.
 *
 * Two implementations, one behavioural contract
 * (`tests/repository/auth-repository-contract.ts`). Every method takes and
 * returns the domain type; no SQL row shape escapes an implementation.
 *
 * Emails are normalized by the implementation, so callers may pass whatever the
 * user typed.
 */
export interface UserRepository {
  findByEmail(email: string): Promise<User | null>;
  findById(id: string): Promise<User | null>;
  /** Throws `DuplicateUserError` when the email is taken. */
  create(input: CreateUserInput): Promise<User>;
  /** Email order, so CLI output is stable. */
  list(): Promise<User[]>;
  /** Null when no such account. */
  setRole(email: string, role: UserRole): Promise<User | null>;
  /** True when an account was removed. Its sessions go with it. */
  remove(email: string): Promise<boolean>;
  count(): Promise<number>;
}
