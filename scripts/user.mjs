#!/usr/bin/env node
/**
 * Account provisioning.
 *
 * The admin surface for authentication. There is no self-signup: on a dashboard
 * listing exploitable vulnerabilities, anyone who could reach the login page
 * could otherwise grant themselves access.
 *
 *   npm run user -- create --email you@example.com --role approver
 *   npm run user -- list
 *   npm run user -- role --email you@example.com --role viewer
 *   npm run user -- delete --email them@example.com
 *
 * The password is prompted on stdin with echo disabled, never accepted as a
 * flag: argv is visible in `ps` and lands in shell history. USER_CLI_PASSWORD
 * exists for the test suite and is deliberately undocumented in --help.
 *
 * Talks to Postgres directly, like scripts/migrate.mjs, so it needs no
 * TypeScript build and no Next module resolution. The scrypt parameters below
 * MUST match src/lib/auth/password.ts — a test asserts a CLI-written hash
 * verifies through the application.
 */

import { createInterface } from "node:readline";
import { randomBytes, randomUUID, scrypt } from "node:crypto";
import { promisify } from "node:util";

import pg from "pg";

const scryptAsync = promisify(scrypt);

const MIN_PASSWORD_LENGTH = 12;
const N = 16384;
const R = 8;
const P = 1;
const KEY_LENGTH = 64;
const SALT_LENGTH = 16;

async function hashPassword(password) {
  if (password.length < MIN_PASSWORD_LENGTH) {
    fail(`A password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
  }
  const salt = randomBytes(SALT_LENGTH);
  const key = await scryptAsync(password, salt, KEY_LENGTH, { N, r: R, p: P });
  return ["scrypt", N, R, P, salt.toString("base64url"), key.toString("base64url")].join("$");
}

function fail(message) {
  console.error(message);
  process.exit(1);
}

function parseArgs(argv) {
  const [command, ...rest] = argv;
  const options = {};
  for (let index = 0; index < rest.length; index += 2) {
    const key = rest[index];
    if (!key?.startsWith("--")) fail(`Unexpected argument: ${key}`);
    options[key.slice(2)] = rest[index + 1];
  }
  return { command, options };
}

/** Read a password without echoing it, and confirm it. */
async function promptPassword() {
  if (process.env.USER_CLI_PASSWORD) return process.env.USER_CLI_PASSWORD;

  if (!process.stdin.isTTY) {
    fail("A password must be entered interactively. Run this in a terminal.");
  }

  const ask = (label) =>
    new Promise((resolve) => {
      const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
      process.stdout.write(label);

      // Suppress echo: the prompt is written, keystrokes are not.
      const onData = () => process.stdout.write("");
      process.stdin.on("data", onData);
      rl.question("", (answer) => {
        process.stdin.off("data", onData);
        rl.close();
        process.stdout.write("\n");
        resolve(answer);
      });
      rl.output.write = () => true;
    });

  const first = await ask("Password: ");
  const second = await ask("Confirm password: ");
  if (first !== second) fail("Passwords do not match.");
  return first;
}

function requireEmail(options) {
  const email = options.email?.trim().toLowerCase();
  if (!email || !email.includes("@")) fail("Pass --email you@example.com");
  return email;
}

function requireRole(options, fallback) {
  const role = (options.role ?? fallback)?.toUpperCase();
  if (role !== "VIEWER" && role !== "APPROVER") {
    fail("--role must be viewer or approver");
  }
  return role;
}

async function main() {
  const { command, options } = parseArgs(process.argv.slice(2));

  if (!command || command === "--help" || command === "help") {
    console.log(
      "Usage:\n" +
        "  npm run user -- create --email you@example.com [--role viewer|approver]\n" +
        "  npm run user -- list\n" +
        "  npm run user -- role --email you@example.com --role approver\n" +
        "  npm run user -- delete --email them@example.com\n",
    );
    process.exit(command ? 0 : 1);
  }

  const connectionString = process.env.DATABASE_URL?.trim();
  if (!connectionString) {
    fail(
      "DATABASE_URL is not set.\n" +
        "  Accounts live in the configured store, and this script is a separate\n" +
        "  process from the server — against the in-memory driver it would write\n" +
        "  to a store the server cannot see. Set DATABASE_URL and run\n" +
        "  `npm run db:migrate` first.\n" +
        "  With the memory driver, the dev server seeds an account and prints it.",
    );
  }

  const useSsl =
    !/sslmode=disable/i.test(connectionString) &&
    !/@(localhost|127\.0\.0\.1)[:/]/.test(connectionString);

  const client = new pg.Client({
    connectionString,
    ssl: useSsl ? { rejectUnauthorized: false } : undefined,
  });
  await client.connect();

  try {
    if (command === "create") {
      const email = requireEmail(options);
      const role = requireRole(options, "viewer");
      const passwordHash = await hashPassword(await promptPassword());

      try {
        await client.query(
          "INSERT INTO users (id, email, password_hash, role) VALUES ($1, $2, $3, $4)",
          [`usr_${randomUUID()}`, email, passwordHash, role],
        );
      } catch (error) {
        if (error.code === "23505") fail(`An account already exists for ${email}.`);
        throw error;
      }
      console.log(`Created ${email} (${role}).`);
      return;
    }

    if (command === "list") {
      const { rows } = await client.query(
        "SELECT email, role, created_at FROM users ORDER BY email ASC",
      );
      if (rows.length === 0) {
        console.log("No accounts exist.");
        return;
      }
      // Never prints password_hash. A hash in a terminal ends up in a scrollback
      // buffer, a screenshot, or a support ticket.
      for (const row of rows) {
        console.log(`${row.email}\t${row.role}\t${row.created_at.toISOString()}`);
      }
      return;
    }

    if (command === "role") {
      const email = requireEmail(options);
      const role = requireRole(options);
      const result = await client.query("UPDATE users SET role = $2 WHERE email = $1", [
        email,
        role,
      ]);
      if (result.rowCount === 0) fail(`No account exists for ${email}.`);
      console.log(`${email} is now ${role}.`);
      return;
    }

    if (command === "delete") {
      const email = requireEmail(options);
      // Sessions go with the user through ON DELETE CASCADE. Findings the user
      // decided on are untouched: attribution is a denormalized snapshot, so an
      // offboarded employee's risk acceptances stay intact and attributed.
      const result = await client.query("DELETE FROM users WHERE email = $1", [email]);
      if (result.rowCount === 0) fail(`No account exists for ${email}.`);
      console.log(`Deleted ${email}.`);
      return;
    }

    fail(`Unknown command: ${command}`);
  } finally {
    await client.end();
  }
}

main().catch((error) => {
  // Never print the error object: a pg error can carry parameter values, and
  // one of this script's parameters is a password hash.
  console.error(error.message);
  process.exit(1);
});
