import { SESSION_COOKIE_NAME } from "@/lib/auth/cookie";
import { getAuthService, resetAuthContainer } from "@/lib/auth/container";

/**
 * Create a real account and session against the configured store and return a
 * Cookie header for it.
 *
 * A real session rather than a stubbed guard: the thing under test is whether
 * an anonymous request reaches a handler, and a stubbed guard would assert
 * nothing about that.
 */
export async function withSession(
  email = "tester@example.com",
  role: "VIEWER" | "APPROVER" = "APPROVER",
): Promise<{ cookie: string; email: string }> {
  const password = "correct horse battery staple";
  const service = await getAuthService();

  await service.createUser(email, password, role);
  const { token } = await service.authenticate(email, password);

  return { cookie: `${SESSION_COOKIE_NAME}=${token}`, email };
}

/** Force the memory driver and drop any cached container. Call in beforeEach. */
export function useMemoryAuth(): void {
  process.env.SECURITY_STORAGE = "memory";
  resetAuthContainer();
}

export function clearMemoryAuth(): void {
  resetAuthContainer();
  delete process.env.SECURITY_STORAGE;
}
