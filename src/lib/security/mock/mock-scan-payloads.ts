/**
 * ============================ MOCK DATA ============================
 *
 * Everything in this directory is FABRICATED. No real repository, commit,
 * credential, CVE record or Azure resource is described here.
 *
 * These are scanner-NATIVE payloads, not pre-built findings. They are pushed
 * through the real adapters by `seedMockData`, so the demo data exercises the
 * same parse -> normalize -> fingerprint -> reconcile path that production
 * ingestion uses. A bug in an adapter shows up in the mock dashboard rather
 * than hiding behind hand-written findings.
 *
 * No production code path imports this file: it is reachable only from
 * `seedMockData`, which the container calls when SECURITY_DATA_SOURCE=mock.
 * ==================================================================
 */

/**
 * Credential-shaped placeholders are assembled at runtime rather than written
 * as literals, so no string in this repository ever looks like a real key to a
 * secret scanner (including the one guarding this repo). They are inert either
 * way — and the Gitleaks adapter discards these fields regardless.
 */
const FAKE_AWS_KEY = ["AKIA", "MOCK", "NOTAREALKEY"].join("");
const FAKE_STRIPE_KEY = ["sk", "live", "MOCKNOTAREALTOKEN"].join("_");

export interface MockRepositoryProfile {
  repositoryName: string;
  repositoryId: string;
  applicationId: string;
  environment: string;
  branch: string;
  commitSha: string;
}

export const MOCK_REPOSITORIES: Record<string, MockRepositoryProfile> = {
  payment: {
    repositoryName: "payment-service",
    repositoryId: "repo_payment_service",
    applicationId: "app_payments",
    environment: "production",
    branch: "main",
    commitSha: "9f1c4a2e7b3d5086af17c2d9e4b6a8130fc52947",
  },
  user: {
    repositoryName: "user-service",
    repositoryId: "repo_user_service",
    applicationId: "app_identity",
    environment: "production",
    branch: "main",
    commitSha: "3a7e91b4c6d28f05e1b93c7a4d8620fe5197bc3d",
  },
  checkout: {
    repositoryName: "checkout-service",
    repositoryId: "repo_checkout_service",
    applicationId: "app_commerce",
    environment: "staging",
    branch: "main",
    commitSha: "c42d8b16e93f7a0524c1d9b8e6f30a7519db4e2c",
  },
  order: {
    repositoryName: "order-service",
    repositoryId: "repo_order_service",
    applicationId: "app_commerce",
    environment: "production",
    branch: "main",
    commitSha: "71b3e5d9a2c48f60193bd7e4a5c82f01639ae8d5",
  },
  frontend: {
    repositoryName: "frontend-app",
    repositoryId: "repo_frontend_app",
    applicationId: "app_storefront",
    environment: "staging",
    branch: "main",
    commitSha: "e58a1c37d94b26f0851ea3c7b924d6f0138cb5a7",
  },
  infrastructure: {
    repositoryName: "infrastructure",
    repositoryId: "repo_infrastructure",
    applicationId: "app_platform",
    environment: "production",
    branch: "main",
    commitSha: "2d9f7e14b8a35c60e72d1a9f4b83c5061ea7d92b",
  },
};

/**
 * `includeStale` adds findings that exist only in the historical scan. The
 * later scan omits them, which is what drives the auto-resolution path and
 * gives the trend chart and MTTR something real to compute.
 */
type PayloadBuilder = (includeStale: boolean) => unknown;

// --- Semgrep (native JSON, `semgrep --json`) --------------------------------

function semgrepResult(options: {
  checkId: string;
  path: string;
  startLine: number;
  endLine: number;
  message: string;
  severity: "ERROR" | "WARNING" | "INFO";
  impact?: "HIGH" | "MEDIUM" | "LOW";
  confidence?: "HIGH" | "MEDIUM" | "LOW";
  cwe: string[];
  owasp?: string[];
  fix?: string;
}) {
  return {
    check_id: options.checkId,
    path: options.path,
    start: { line: options.startLine, col: 5, offset: 0 },
    end: { line: options.endLine, col: 42, offset: 0 },
    extra: {
      message: options.message,
      severity: options.severity,
      fingerprint: `mock_${options.checkId}_${options.path}_${options.startLine}`,
      lines: "        <source line omitted from mock fixture>",
      fix: options.fix,
      metadata: {
        cwe: options.cwe,
        owasp: options.owasp ?? [],
        confidence: options.confidence ?? "MEDIUM",
        impact: options.impact ?? "MEDIUM",
        likelihood: "MEDIUM",
        category: "security",
        technology: ["python"],
        references: ["https://owasp.org/www-project-top-ten/"],
        shortlink: "https://sg.run/mock",
      },
    },
  };
}

export const semgrepPaymentService: PayloadBuilder = (includeStale) => ({
  version: "1.95.0",
  results: [
    semgrepResult({
      checkId:
        "python.lang.security.audit.formatted-sql-query.formatted-sql-query",
      path: "src/payments/repository.py",
      startLine: 142,
      endLine: 144,
      message:
        "Detected SQL statement built from user-controlled input. This allows SQL injection; use a parameterised query instead.",
      severity: "ERROR",
      impact: "HIGH",
      confidence: "HIGH",
      cwe: [
        "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
      ],
      owasp: ["A03:2021 - Injection"],
      fix: "Use a parameterised query: cursor.execute(query, (customer_id,))",
    }),
    semgrepResult({
      checkId: "javascript.express.security.audit.express-session-hardcoded-secret",
      path: "src/payments/session.js",
      startLine: 18,
      endLine: 18,
      message:
        "A hardcoded session secret was detected. Load the secret from configuration instead.",
      severity: "WARNING",
      impact: "MEDIUM",
      cwe: ["CWE-798: Use of Hard-coded Credentials"],
    }),
    ...(includeStale
      ? [
          semgrepResult({
            checkId: "python.lang.security.audit.dangerous-subprocess-use",
            path: "src/payments/reconcile.py",
            startLine: 61,
            endLine: 61,
            message:
              "Detected subprocess call with shell=True and a non-literal argument.",
            severity: "ERROR",
            impact: "MEDIUM",
            cwe: ["CWE-78: OS Command Injection"],
          }),
        ]
      : []),
  ],
  errors: [],
  paths: { scanned: ["src/payments"] },
});

export const semgrepUserService: PayloadBuilder = (includeStale) => ({
  version: "1.95.0",
  results: [
    semgrepResult({
      checkId: "python.django.security.audit.unvalidated-user-input",
      path: "src/users/views.py",
      startLine: 88,
      endLine: 91,
      message:
        "Unvalidated user input flows into the response body without sanitisation.",
      severity: "ERROR",
      impact: "MEDIUM",
      confidence: "HIGH",
      cwe: ["CWE-20: Improper Input Validation"],
      owasp: ["A03:2021 - Injection"],
    }),
    semgrepResult({
      checkId: "python.lang.security.audit.md5-used-as-password",
      path: "src/users/legacy_hash.py",
      startLine: 24,
      endLine: 24,
      message: "MD5 is used to hash a password. Use bcrypt, scrypt or argon2.",
      severity: "WARNING",
      cwe: ["CWE-327: Use of a Broken or Risky Cryptographic Algorithm"],
    }),
    ...(includeStale
      ? [
          semgrepResult({
            checkId: "python.flask.security.audit.debug-enabled",
            path: "src/users/app.py",
            startLine: 12,
            endLine: 12,
            message: "Flask debug mode is enabled in application code.",
            severity: "WARNING",
            cwe: ["CWE-489: Active Debug Code"],
          }),
        ]
      : []),
  ],
  errors: [],
  paths: { scanned: ["src/users"] },
});

export const semgrepCheckoutService: PayloadBuilder = () => ({
  version: "1.95.0",
  results: [
    semgrepResult({
      checkId: "java.spring.security.audit.spring-csrf-disabled",
      path: "src/main/java/checkout/SecurityConfig.java",
      startLine: 34,
      endLine: 34,
      message:
        "CSRF protection is explicitly disabled for all endpoints in this Spring Security configuration.",
      severity: "ERROR",
      impact: "MEDIUM",
      confidence: "HIGH",
      cwe: ["CWE-352: Cross-Site Request Forgery (CSRF)"],
      owasp: ["A01:2021 - Broken Access Control"],
    }),
    semgrepResult({
      checkId: "java.lang.security.audit.crypto.weak-random",
      path: "src/main/java/checkout/TokenFactory.java",
      startLine: 51,
      endLine: 51,
      message:
        "java.util.Random is used to generate a security-sensitive value. Use SecureRandom.",
      severity: "WARNING",
      cwe: ["CWE-330: Use of Insufficiently Random Values"],
    }),
  ],
  errors: [],
  paths: { scanned: ["src/main/java"] },
});

// --- Gitleaks (native JSON, an array of leaks) ------------------------------

/**
 * The `Secret` and `Match` fields below carry inert placeholders assembled at
 * runtime. They exist so the mock payload has the same shape as a real report,
 * including the fields the adapter must refuse to store.
 */
export const gitleaksPaymentService: PayloadBuilder = () => [
  {
    Description: "Hardcoded AWS access key",
    StartLine: 27,
    EndLine: 27,
    StartColumn: 21,
    EndColumn: 61,
    Match: `aws_access_key_id = ${FAKE_AWS_KEY}`,
    Secret: FAKE_AWS_KEY,
    File: "deploy/legacy/aws.cfg",
    SymlinkFile: "",
    Commit: "9f1c4a2e7b3d5086af17c2d9e4b6a8130fc52947",
    Entropy: 3.8219,
    Author: "Mock Author",
    Email: "mock@example.invalid",
    Date: "2026-07-14T09:12:33Z",
    Message: "chore: legacy deploy config",
    Tags: ["aws", "key"],
    RuleID: "aws-access-token",
    Fingerprint:
      "9f1c4a2e7b3d5086af17c2d9e4b6a8130fc52947:deploy/legacy/aws.cfg:aws-access-token:27",
  },
  {
    Description: "Hardcoded API token",
    StartLine: 9,
    EndLine: 9,
    StartColumn: 15,
    EndColumn: 55,
    Match: `STRIPE_KEY = "${FAKE_STRIPE_KEY}"`,
    Secret: FAKE_STRIPE_KEY,
    File: "src/payments/config.py",
    SymlinkFile: "",
    Commit: "9f1c4a2e7b3d5086af17c2d9e4b6a8130fc52947",
    Entropy: 4.1023,
    Author: "Mock Author",
    Email: "mock@example.invalid",
    Date: "2026-07-20T16:41:02Z",
    Message: "feat: payment config",
    Tags: ["stripe", "token"],
    RuleID: "stripe-access-token",
    Fingerprint:
      "9f1c4a2e7b3d5086af17c2d9e4b6a8130fc52947:src/payments/config.py:stripe-access-token:9",
  },
];

// --- Checkov (native JSON) --------------------------------------------------

function checkovFailedCheck(options: {
  checkId: string;
  checkName: string;
  filePath: string;
  lineRange: [number, number];
  resource: string;
  severity?: "HIGH" | "MEDIUM" | "LOW" | null;
  guideline?: string;
}) {
  return {
    check_id: options.checkId,
    bc_check_id: options.checkId.replace("CKV", "BC"),
    check_name: options.checkName,
    check_result: { result: "FAILED" },
    file_path: options.filePath,
    file_abs_path: `/github/workspace${options.filePath}`,
    repo_file_path: options.filePath,
    file_line_range: options.lineRange,
    resource: options.resource,
    resource_address: options.resource,
    check_class: "checkov.terraform.checks.resource.azure",
    // Open-source Checkov emits null here; the adapter's documented default
    // applies. The two HIGH entries mirror a Prisma-linked run.
    severity: options.severity ?? null,
    guideline: options.guideline ?? "https://docs.example.invalid/checkov",
    code_block: [
      [options.lineRange[0], "  <code block omitted from mock fixture>"],
    ],
  };
}

export const checkovInfrastructure: PayloadBuilder = (includeStale) => ({
  check_type: "terraform",
  results: {
    passed_checks: [
      {
        check_id: "CKV_AZURE_1",
        check_name: "Ensure that Azure managed disks use customer-managed keys",
        check_result: { result: "PASSED" },
        file_path: "/azure/storage.tf",
        file_line_range: [1, 12],
        resource: "azurerm_managed_disk.data",
      },
    ],
    failed_checks: [
      checkovFailedCheck({
        checkId: "CKV_AZURE_59",
        checkName:
          "Ensure that Azure Storage Account does not allow public blob access",
        filePath: "/azure/storage.tf",
        lineRange: [14, 28],
        resource: "azurerm_storage_account.assets",
        severity: "HIGH",
      }),
      checkovFailedCheck({
        checkId: "CKV_AZURE_9",
        checkName:
          "Ensure that RDP and SSH access is restricted from the Internet (NSG rule allows 0.0.0.0/0)",
        filePath: "/azure/network.tf",
        lineRange: [63, 78],
        resource: "azurerm_network_security_rule.allow_ssh",
        severity: "HIGH",
      }),
      checkovFailedCheck({
        checkId: "CKV_AZURE_3",
        checkName:
          "Ensure that the Storage Account enables secure transfer (HTTPS only)",
        filePath: "/azure/storage.tf",
        lineRange: [14, 28],
        resource: "azurerm_storage_account.assets",
      }),
      checkovFailedCheck({
        checkId: "CKV_AZURE_33",
        checkName: "Ensure Storage logging is enabled for the queue service",
        filePath: "/azure/storage.tf",
        lineRange: [30, 41],
        resource: "azurerm_storage_account.events",
      }),
      checkovFailedCheck({
        checkId: "CKV_AZURE_35",
        checkName:
          "Ensure the default network access rule for Storage Accounts is set to deny",
        filePath: "/azure/storage.tf",
        lineRange: [30, 41],
        resource: "azurerm_storage_account.events",
      }),
      checkovFailedCheck({
        checkId: "CKV_AZURE_44",
        checkName: "Ensure Storage Account is using the latest version of TLS",
        filePath: "/azure/storage.tf",
        lineRange: [43, 55],
        resource: "azurerm_storage_account.logs",
      }),
      checkovFailedCheck({
        checkId: "CKV_AZURE_109",
        checkName: "Ensure that Key Vault allows firewall rules settings",
        filePath: "/azure/keyvault.tf",
        lineRange: [8, 24],
        resource: "azurerm_key_vault.platform",
      }),
      checkovFailedCheck({
        checkId: "CKV_AZURE_206",
        checkName: "Ensure that Storage Accounts use replication for durability",
        filePath: "/azure/storage.tf",
        lineRange: [43, 55],
        resource: "azurerm_storage_account.logs",
      }),
      checkovFailedCheck({
        checkId: "CKV_AZURE_112",
        checkName:
          "Ensure that Key Vault key is backed by an HSM and has an expiration date",
        filePath: "/azure/keyvault.tf",
        lineRange: [26, 38],
        resource: "azurerm_key_vault_key.signing",
      }),
      ...(includeStale
        ? [
            checkovFailedCheck({
              checkId: "CKV_AZURE_50",
              checkName:
                "Ensure Virtual Machine extensions are not installed automatically",
              filePath: "/azure/compute.tf",
              lineRange: [91, 104],
              resource: "azurerm_linux_virtual_machine.worker",
            }),
          ]
        : []),
    ],
  },
  summary: {
    passed: 1,
    failed: 9,
    skipped: 0,
    parsing_errors: 0,
    resource_count: 12,
    checkov_version: "3.2.334",
  },
});

// --- Trivy (native JSON) ----------------------------------------------------

function trivyVulnerability(options: {
  id: string;
  pkgName: string;
  installedVersion: string;
  fixedVersion?: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  title: string;
  description: string;
  cweIds?: string[];
}) {
  return {
    VulnerabilityID: options.id,
    PkgName: options.pkgName,
    InstalledVersion: options.installedVersion,
    FixedVersion: options.fixedVersion,
    Status: "fixed",
    Severity: options.severity,
    Title: options.title,
    Description: options.description,
    PrimaryURL: `https://avd.example.invalid/nvd/${options.id.toLowerCase()}`,
    CweIDs: options.cweIds ?? [],
    References: ["https://avd.example.invalid/reference"],
    DataSource: { ID: "ghsa", Name: "GitHub Security Advisory" },
  };
}

export const trivyUserService: PayloadBuilder = (includeStale) => ({
  SchemaVersion: 2,
  ArtifactName: "user-service",
  ArtifactType: "filesystem",
  Results: [
    {
      Target: "package-lock.json",
      Class: "lang-pkgs",
      Type: "npm",
      Vulnerabilities: [
        trivyVulnerability({
          id: "CVE-2026-21538",
          pkgName: "cross-spawn",
          installedVersion: "7.0.3",
          fixedVersion: "7.0.5",
          severity: "HIGH",
          title:
            "cross-spawn: regular expression denial of service via crafted argument",
          description:
            "A crafted command argument causes catastrophic backtracking in the argument parser, blocking the event loop.",
          cweIds: ["CWE-1333"],
        }),
        trivyVulnerability({
          id: "CVE-2025-9042",
          pkgName: "urllib3",
          installedVersion: "2.2.1",
          fixedVersion: "2.2.3",
          severity: "MEDIUM",
          title: "urllib3: redirect handling leaks Authorization header",
          description:
            "Authorization headers are retained across cross-origin redirects in some configurations.",
          cweIds: ["CWE-200"],
        }),
        ...(includeStale
          ? [
              trivyVulnerability({
                id: "CVE-2025-4402",
                pkgName: "requests",
                installedVersion: "2.31.0",
                fixedVersion: "2.32.0",
                severity: "MEDIUM",
                title: "requests: certificate verification bypass",
                description:
                  "Verification can be bypassed when a session is reused after a failed handshake.",
              }),
            ]
          : []),
      ],
    },
  ],
});

export const trivyOrderService: PayloadBuilder = () => ({
  SchemaVersion: 2,
  ArtifactName: "registry.example.invalid/order-service:1.14.2",
  ArtifactType: "container_image",
  Results: [
    {
      Target: "registry.example.invalid/order-service:1.14.2 (debian 12.5)",
      Class: "os-pkgs",
      Type: "debian",
      Vulnerabilities: [
        trivyVulnerability({
          id: "CVE-2026-5678",
          pkgName: "openssl",
          installedVersion: "3.0.11-1~deb12u2",
          fixedVersion: "3.0.13-1~deb12u1",
          severity: "HIGH",
          title: "openssl: use-after-free in certificate chain validation",
          description:
            "A malformed certificate chain can trigger a use-after-free during verification.",
          cweIds: ["CWE-416"],
        }),
      ],
    },
    {
      Target: "Dockerfile",
      Class: "config",
      Type: "dockerfile",
      Misconfigurations: [
        {
          Type: "Dockerfile Security Check",
          ID: "DS002",
          AVDID: "AVD-DS-0002",
          Title: "Image user should not be 'root'",
          Description:
            "Running containers with a root user increases the impact of a container escape.",
          Message:
            "Specify at least one USER command in the Dockerfile with a non-root user.",
          Resolution: "Add 'USER app' before the container entrypoint.",
          Severity: "MEDIUM",
          PrimaryURL: "https://avd.example.invalid/misconfig/ds002",
          CauseMetadata: {
            Provider: "Dockerfile",
            Service: "general",
            StartLine: 1,
            EndLine: 1,
            Resource: "registry.example.invalid/order-service:1.14.2",
          },
        },
      ],
    },
  ],
});

export const trivyFrontendApp: PayloadBuilder = () => ({
  SchemaVersion: 2,
  ArtifactName: "frontend-app",
  ArtifactType: "filesystem",
  Results: [
    {
      Target: "package-lock.json",
      Class: "lang-pkgs",
      Type: "npm",
      Vulnerabilities: [
        trivyVulnerability({
          id: "CVE-2026-3456",
          pkgName: "lodash",
          installedVersion: "4.17.20",
          fixedVersion: "4.17.21",
          severity: "HIGH",
          title: "lodash: prototype pollution via merge",
          description:
            "Deep merge of attacker-controlled objects can pollute Object.prototype.",
          cweIds: ["CWE-1321"],
        }),
        trivyVulnerability({
          id: "CVE-2025-7712",
          pkgName: "express",
          installedVersion: "4.17.1",
          fixedVersion: "4.20.0",
          severity: "MEDIUM",
          title:
            "express: outdated Node.js dependency with open redirect in response.location",
          description:
            "The bundled version predates the fix for an open redirect in res.location().",
          cweIds: ["CWE-601"],
        }),
        trivyVulnerability({
          id: "CVE-2025-1111",
          pkgName: "postcss",
          installedVersion: "8.4.14",
          fixedVersion: "8.4.31",
          severity: "MEDIUM",
          title: "postcss: improper input validation in source map parsing",
          description:
            "A crafted source map comment can desynchronise the parser state.",
          cweIds: ["CWE-20"],
        }),
      ],
    },
  ],
});
