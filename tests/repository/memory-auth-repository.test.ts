import { InMemorySessionRepository } from "@/lib/auth/repository/memory-session-repository";
import { InMemoryUserRepository } from "@/lib/auth/repository/memory-user-repository";
import { runAuthRepositoryContract } from "./auth-repository-contract";

runAuthRepositoryContract("in-memory", {
  create: async () => {
    const users = new InMemoryUserRepository();
    // The memory driver has no foreign keys, so the session store is told about
    // the user store to reproduce ON DELETE CASCADE. The contract asserts both
    // drivers behave the same; this is how the memory side keeps that promise.
    const sessions = new InMemorySessionRepository();
    users.onRemoved((userId) => sessions.removeForUser(userId));
    return { users, sessions };
  },
});
