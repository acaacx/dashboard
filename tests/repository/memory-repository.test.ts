import { InMemorySecurityFindingRepository } from "@/lib/security/repository/memory-security-finding-repository";
import { runSecurityFindingRepositoryContract } from "./repository-contract";

runSecurityFindingRepositoryContract("in-memory", {
  create: async () => new InMemorySecurityFindingRepository(),
});
