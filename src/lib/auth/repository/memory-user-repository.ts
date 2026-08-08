import { randomUUID } from "node:crypto";

import { DuplicateUserError } from "@/domain/auth/errors";
import { normalizeEmail, type User, type UserRole } from "@/domain/auth/user";
import type { CreateUserInput, UserRepository } from "./user-repository";

/**
 * In-memory user store — the zero-setup development default.
 *
 * Behaviourally identical to the PostgreSQL store, which is what the shared
 * contract suite exists to prove.
 *
 * Accounts do not survive a restart. That is a documented limitation, not an
 * oversight: authentication on the memory driver is a development convenience.
 */
export class InMemoryUserRepository implements UserRepository {
  private readonly byId = new Map<string, User>();
  private readonly removalListeners: Array<(userId: string) => void> = [];

  /**
   * Notified when a user is removed, so the session store can drop that user's
   * sessions. PostgreSQL gets this from ON DELETE CASCADE; here it is wired by
   * hand in the composition root.
   */
  onRemoved(listener: (userId: string) => void): void {
    this.removalListeners.push(listener);
  }

  async findByEmail(email: string): Promise<User | null> {
    const normalized = normalizeEmail(email);
    for (const user of this.byId.values()) {
      if (user.email === normalized) return { ...user };
    }
    return null;
  }

  async findById(id: string): Promise<User | null> {
    const user = this.byId.get(id);
    return user ? { ...user } : null;
  }

  async create(input: CreateUserInput): Promise<User> {
    const email = normalizeEmail(input.email);
    if (await this.findByEmail(email)) {
      throw new DuplicateUserError(email);
    }

    const user: User = {
      id: `usr_${randomUUID()}`,
      email,
      passwordHash: input.passwordHash,
      role: input.role,
      createdAt: new Date().toISOString(),
    };
    this.byId.set(user.id, user);
    return { ...user };
  }

  async list(): Promise<User[]> {
    return [...this.byId.values()]
      .map((user) => ({ ...user }))
      .sort((left, right) => left.email.localeCompare(right.email));
  }

  async setRole(email: string, role: UserRole): Promise<User | null> {
    const existing = await this.findByEmail(email);
    if (!existing) return null;

    const updated: User = { ...existing, role };
    this.byId.set(updated.id, updated);
    return { ...updated };
  }

  async remove(email: string): Promise<boolean> {
    const existing = await this.findByEmail(email);
    if (!existing) return false;

    this.byId.delete(existing.id);
    for (const listener of this.removalListeners) listener(existing.id);
    return true;
  }

  async count(): Promise<number> {
    return this.byId.size;
  }
}
