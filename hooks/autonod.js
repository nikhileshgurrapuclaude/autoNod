#!/usr/bin/env node
/*
 * autoNod — safe auto-approval for Claude Code
 * -------------------------------------------------
 * A PreToolUse hook. Runs before every matched tool call and decides:
 *   - "deny"   -> block it (holds even under bypassPermissions / --dangerously-skip-permissions)
 *   - "allow"  -> approve without prompting
 *   - (nothing) -> fall through to Claude Code's normal permission prompt
 *
 * Evaluation order is DENY FIRST, then ALLOW, then fall through.
 * That mirrors Claude Code's own deny > ask > allow precedence: the hard
 * floor (secrets / backend / network) can never be punched through by the
 * convenience allowlist.
 *
 * SCOPE / HONEST LIMITS:
 *   This governs what CLAUDE does through its tools. It is NOT a firewall,
 *   NOT server security, and cannot stop an external attacker or a real
 *   network breach. It stops Claude from reading your secrets and from
 *   using its own web tools to send data out. That is the whole promise.
 */

"use strict";

const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------------------
// 1. Read the tool-call payload from stdin. If anything is off, fall through
//    (exit 0 with no output) so the user just gets a normal prompt — we never
//    fail "open" into an allow.
// ---------------------------------------------------------------------------
function fallThrough() {
  process.exit(0); // no stdout => normal permission flow
}

function decide(decision, reason) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: decision, // "allow" | "deny" | "ask"
        permissionDecisionReason: `autoNod: ${reason}`,
      },
    }),
  );
  process.exit(0);
}

let payload;
try {
  const raw = fs.readFileSync(0, "utf8");
  payload = JSON.parse(raw);
} catch (e) {
  fallThrough();
}

const toolName = payload.tool_name || "";
const toolInput = payload.tool_input || {};
const cwd = payload.cwd || process.cwd();

// ---------------------------------------------------------------------------
// 2. Load config (defaults + user overrides). Never throw.
// ---------------------------------------------------------------------------
const DEFAULTS = {
  allowedDirs: [
    "src/",
    "app/",
    "pages/",
    "components/",
    "styles/",
    "public/",
    "assets/",
    "lib/",
  ],
  allowedRootFiles: ["index.html", "package.json", "tsconfig.json"],
  allowedExtensions: [
    ".tsx",
    ".jsx",
    ".ts",
    ".js",
    ".mjs",
    ".cjs",
    ".css",
    ".scss",
    ".sass",
    ".less",
    ".html",
    ".htm",
    ".vue",
    ".svelte",
    ".astro",
    ".json",
    ".md",
    ".mdx",
    ".svg",
  ],
  backendDomains: [],
  extraDenyPaths: ["server/", "backend/"],
  autoApproveSafeBash: true,
  denyAllNetworkTools: true,
};

let config = DEFAULTS;
try {
  const cfgPath = path.join(__dirname, "autonod.config.json");
  if (fs.existsSync(cfgPath)) {
    const user = JSON.parse(fs.readFileSync(cfgPath, "utf8"));
    config = { ...DEFAULTS, ...user };
  }
} catch (e) {
  config = DEFAULTS;
}

// ---------------------------------------------------------------------------
// 3. Pattern banks
// ---------------------------------------------------------------------------

// Files that must NEVER be read/edited/written automatically.
const SECRET_PATH_PATTERNS = [
  /(^|\/)\.env(\.|$)/i, // .env, .env.local, .env.production, ...
  /(^|\/)\.env[^/]*$/i,
  /\.pem$/i,
  /\.key$/i,
  /(^|\/)id_rsa/i,
  /(^|\/)\.npmrc$/i,
  /(^|\/)\.netrc$/i,
  /(^|\/)\.aws(\/|$)/i,
  /(^|\/)credentials?(\.|$)/i,
  /(^|\/)secrets?(\.|\/|$)/i,
  /\.p12$/i,
  /\.pfx$/i,
];

// Secret-looking CONTENT that should never be written into a file by Claude.
const SECRET_CONTENT_PATTERNS = [
  /-----BEGIN[A-Z ]*PRIVATE KEY-----/,
  /AKIA[0-9A-Z]{16}/, // AWS access key id
  /(mongodb|postgres|postgresql|mysql|redis|amqp)(\+srv)?:\/\/[^\s"'`]+@/i, // conn string w/ creds
  /aws_secret_access_key\s*[:=]/i,
  /(^|\W)(sk|rk)_(live|test)_[0-9a-zA-Z]{16,}/, // stripe-style secret keys
  /gh[pousr]_[0-9A-Za-z]{20,}/, // github tokens
];

// Bash that reads/dumps/exfiltrates secrets or reaches the network.
const BASH_DENY_PATTERNS = [
  /\.env\b/i, // any bash touching an env file
  /\bprintenv\b/i,
  /\bset\s*\|\s*grep/i,
  /\bcurl\b/i,
  /\bwget\b/i,
  /\bnc\b\s/i, // netcat
  /\btelnet\b/i,
  /\bscp\b/i,
  /\brsync\b.*::/i,
  /\bssh\b\s+[^\s]+@/i,
];

// Bash we're comfortable auto-approving (harmless frontend workflow).
const BASH_SAFE_PATTERNS = [
  /^\s*(npm|pnpm|yarn|bun)\s+(run\s+)?(dev|build|start|lint|test|format|typecheck|check|preview)\b/i,
  /^\s*(npm|pnpm|yarn|bun)\s+(-v|--version)\b/i,
  /^\s*(npx\s+)?(tsc|eslint|prettier|vite|next|svelte-kit|astro)\b/i,
  /^\s*git\s+(status|diff|log|branch|show)\b/i,
  /^\s*(ls|dir|pwd|cd|echo|jobs|sleep|which|where|whoami)\b/i,
  /^\s*node\s+(-v|--version)\b/i,
  /^\s*cat\s+package\.json\b/i,
];

// Commands allowed on the RIGHT side of a pipe (read-only filters / pagers).
const SAFE_FILTERS =
  /^(select-object|out-string|out-host|head|tail|grep|findstr|sort|wc|tee|cat|less|more|awk|sed\s+-n)\b/i;

// ---------------------------------------------------------------------------
// 4. Helpers
// ---------------------------------------------------------------------------
function collectPaths(input) {
  const keys = ["file_path", "path", "notebook_path", "filePath"];
  const out = [];
  for (const k of keys) if (typeof input[k] === "string") out.push(input[k]);
  return out;
}

function toRel(p) {
  try {
    const abs = path.isAbsolute(p) ? p : path.resolve(cwd, p);
    return path.relative(cwd, abs);
  } catch (e) {
    return p;
  }
}

function matchesAny(str, patterns) {
  return patterns.some((re) => re.test(str));
}

// --- compound bash analysis --------------------------------------------------
// Claude Code usually wraps commands as: cd "project" && <actual command>.
// We split on && and ; and require EVERY segment to be independently safe.
// If the command uses backgrounding (&), OR-chains (||), command substitution
// ($(...) / backticks), or anything we can't reason about, we bail to a normal
// prompt rather than guess — that ambiguity is exactly where damage hides.

function hasDangerousShellSyntax(cmd) {
  if (/\$\(|`/.test(cmd)) return true; // command substitution
  if (/\|\|/.test(cmd)) return true; // OR chain
  // Neutralize the '&&' AND-operator and harmless redirection tokens so their
  // '&' characters don't look like backgrounding. Anything left is a lone '&'.
  const normalized = cmd
    .replace(/&&/g, " ; ")
    .replace(/2>&1|1>&2|&>>?|>&\d?/g, "");
  if (/(^|[^>0-9])&(\s|$|\))/.test(normalized)) return true; // backgrounding &
  return false;
}

function segmentIsSafe(seg) {
  seg = seg.trim();
  if (!seg) return true;
  // Allow a single pipe into read-only filters (e.g. `npm run lint | tail`).
  const parts = seg.split("|").map((s) => s.trim());
  const head = parts[0];
  if (!matchesAny(head, BASH_SAFE_PATTERNS)) return false;
  for (let i = 1; i < parts.length; i++) {
    if (!SAFE_FILTERS.test(parts[i])) return false;
  }
  return true;
}

function isSafeCompoundBash(cmd) {
  if (hasDangerousShellSyntax(cmd)) return false;
  return cmd.split(/&&|;/).every(segmentIsSafe);
}

function containsDeniedPath(rel) {
  if (matchesAny(rel, SECRET_PATH_PATTERNS)) return "secret / credential file";
  for (const frag of config.extraDenyPaths) {
    if (rel.includes(frag)) return `protected backend path (${frag})`;
  }
  return null;
}

function escapesProject(rel) {
  return rel.startsWith("..") || path.isAbsolute(rel);
}

function isAllowedFrontendFile(rel) {
  const ext = path.extname(rel).toLowerCase();
  if (!config.allowedExtensions.includes(ext)) return false;
  const base = path.basename(rel);
  if (config.allowedRootFiles.includes(base) && !rel.includes("/")) return true;
  return config.allowedDirs.some(
    (d) => rel.startsWith(d) || rel.includes("/" + d),
  );
}

function inputBlob() {
  try {
    return JSON.stringify(toolInput);
  } catch (e) {
    return "";
  }
}

function referencesBackendDomain(str) {
  return config.backendDomains.find((d) => d && str.includes(d)) || null;
}

// ---------------------------------------------------------------------------
// 5. Decision logic
// ---------------------------------------------------------------------------

// 5a. Network tools — Claude's own egress. Deny by default.
if (toolName === "WebFetch" || toolName === "WebSearch") {
  if (config.denyAllNetworkTools) {
    decide(
      "deny",
      `${toolName} blocked — no network egress from Claude (prevents leaking secrets/backend info).`,
    );
  }
  fallThrough();
}

// 5b. Bash
if (toolName === "Bash") {
  const cmd = String(toolInput.command || "");

  const dom = referencesBackendDomain(cmd);
  if (dom)
    decide("deny", `command references protected backend host "${dom}".`);
  if (matchesAny(cmd, BASH_DENY_PATTERNS)) {
    decide(
      "deny",
      "command reads secrets or reaches the network (env dump / curl / wget / ssh / scp, etc.).",
    );
  }
  if (config.autoApproveSafeBash && isSafeCompoundBash(cmd)) {
    decide("allow", "recognized safe frontend command(s).");
  }
  fallThrough(); // unknown / complex bash still prompts — deliberately conservative
}

// 5c. File tools (Edit / Write / MultiEdit / NotebookEdit / Read)
const paths = collectPaths(toolInput);

// Deny FIRST on any protected path.
for (const p of paths) {
  const rel = toRel(p);
  const why = containsDeniedPath(rel);
  if (why) decide("deny", `${toolName} on "${rel}" blocked — ${why}.`);
}

// Deny if writing secret-looking content or a backend domain into a file.
if (["Write", "Edit", "MultiEdit", "NotebookEdit"].includes(toolName)) {
  const blob = inputBlob();
  if (matchesAny(blob, SECRET_CONTENT_PATTERNS)) {
    decide(
      "deny",
      "the content being written looks like a secret (private key / token / connection string).",
    );
  }
  const dom = referencesBackendDomain(blob);
  if (dom)
    decide(
      "deny",
      `the content being written references protected backend host "${dom}".`,
    );
}

// Allow safe frontend file edits.
if (
  ["Write", "Edit", "MultiEdit", "NotebookEdit", "Read"].includes(toolName) &&
  paths.length > 0
) {
  const allAllowed = paths.every((p) => {
    const rel = toRel(p);
    return !escapesProject(rel) && isAllowedFrontendFile(rel);
  });
  if (allAllowed) {
    decide("allow", "safe frontend file inside the project — auto-approved.");
  }
}

// Anything else: let Claude Code's normal permission flow handle it.
fallThrough();
