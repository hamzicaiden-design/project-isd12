/*
  Manage Aiden's Browser accounts.

    npm run user -- add <name>           make an account (asks for a password)
    npm run user -- add <name> --admin   make a master (admin) account
    npm run user -- remove <name>        delete an account (logs them out)
    npm run user -- list                 show every account

  Add --local to change the test accounts used by "npm run dev"
  instead of the real ones online.

  Passwords are hashed here, on your computer, the same way the
  Worker checks them (PBKDF2, see src/index.js), so the real
  password is never stored anywhere.
*/

import { execFileSync } from "node:child_process";
import { pbkdf2Sync, randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";

/* Must match src/index.js */
const HASH_ITERATIONS = 100000;
const USERNAME_PATTERN = /^[a-z0-9_-]{3,20}$/;
const MIN_PASSWORD_LENGTH = 4;


const args = process.argv.slice(2);
const flags = args.filter(arg => arg.startsWith("--"));
const [command, rawName] = args.filter(arg => !arg.startsWith("--"));

const where = flags.includes("--local") ? "--local" : "--remote";
const name = String(rawName || "").toLowerCase();


/* Run wrangler's own script directly (no shell, so the JSON stays intact) */

const wranglerScript = fileURLToPath(
  new URL("../node_modules/wrangler/bin/wrangler.js", import.meta.url)
);

function wrangler(...wranglerArgs) {

  return execFileSync(
    process.execPath,
    [wranglerScript, "kv", "key", ...wranglerArgs, "--binding", "USERS", where],
    { encoding: "utf8", stdio: ["ignore", "pipe", "inherit"] }
  );

}


/*
  Ask for the password. In a normal terminal the typing is hidden;
  otherwise (like when it's piped in) we just read one line.
*/

function askPassword(question) {

  return new Promise(resolve => {

    const input = createInterface({ input: process.stdin, output: process.stdout, terminal: Boolean(process.stdin.isTTY) });

    if (process.stdin.isTTY) {
      input._writeToOutput = text => {
        process.stdout.write(text.startsWith(question) ? text : "");
      };
    }

    input.question(question, answer => {
      input.close();
      process.stdout.write("\n");
      resolve(answer);
    });

  });

}


function needName() {

  if (!USERNAME_PATTERN.test(name)) {
    console.error("Usernames are 3-20 characters: letters, numbers, _ or -");
    process.exit(1);
  }

}


if (command === "add") {

  needName();

  const password = await askPassword("Password for " + name + ": ");

  if (password.length < MIN_PASSWORD_LENGTH) {
    console.error("Use at least " + MIN_PASSWORD_LENGTH + " characters.");
    process.exit(1);
  }

  const salt = randomBytes(16);
  const hash = pbkdf2Sync(password, salt, HASH_ITERATIONS, 32, "sha256");

  const account = {
    role: flags.includes("--admin") ? "admin" : "user",
    salt: salt.toString("base64url"),
    hash: hash.toString("base64url")
  };

  wrangler("put", "user:" + name, JSON.stringify(account));

  console.log(`Saved ${name} (${account.role}) ${where === "--local" ? "for local testing" : "online"}.`);

} else if (command === "remove") {

  needName();

  wrangler("delete", "user:" + name);

  console.log("Removed " + name + ".");

} else if (command === "list") {

  const keys = JSON.parse(wrangler("list", "--prefix", "user:"));

  for (const key of keys) {

    const account = JSON.parse(wrangler("get", key.name));

    console.log(key.name.slice("user:".length).padEnd(22) + account.role.padEnd(8) + (account.disabled ? "DISABLED: " + (account.reason || "(no reason)") : ""));

  }

  if (keys.length === 0) console.log("No accounts yet.");

} else {

  console.log("Use: npm run user -- add <name> [--admin] | remove <name> | list   (add --local for test accounts)");

}
