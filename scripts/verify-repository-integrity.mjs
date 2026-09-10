#!/usr/bin/env node
// Repository integrity scanner v2. Dependency-free. Exit 1 on any finding.
// Modes: --tracked (git ls-files, default; CI), --worktree (all files on disk), --commits <range> (forged-commit heuristics).
import { execFileSync } from "node:child_process";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, relative, extname, basename } from "node:path";

const argv = process.argv.slice(2);
const opt = (name) => { const i = argv.indexOf(name); return i >= 0 ? argv[i + 1] : null; };
const root = opt("--root") || process.cwd();
const mode = argv.includes("--worktree") ? "worktree" : "tracked";
const commitRange = opt("--commits");
const findings = [];
const flag = (path, what) => findings.push(`${path}: ${what}`);

const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", "target", "Pods", ".expo", ".pnpm-store", "fixtures"]);
const CONFIG_RE = /(^|\/)([^/]+\.config\.[cm]?[jt]s|app\.plugin\.js|\.pnpmfile\.cjs|preinstall\.[cm]?js|postinstall\.[cm]?js|install\.[cm]?js)$/i;
// Files a build or dev server executes on its own. Network and runtime-require are only suspicious here; app-level
// configs such as auth.config.js legitimately call fetch and are held to the eval/process/long-line rules only.
const BUILD_CONFIG_RE = /(^|\/)((postcss|tailwind|vite|vitest|next|webpack|rollup|rolldown|metro|babel|jest|playwright|electron\.vite|electron-builder|tsup|esbuild|svelte|astro|nuxt|remix|expo|eas|drizzle|prisma|eslint|prettier|stylelint|commitlint|lint-staged|knip|turbo|nx|craco|react-native|app|tauri|capacitor|cypress|wdio|karma|gulpfile|gruntfile)\.config\.[cm]?[jt]s|app\.plugin\.js|\.pnpmfile\.cjs|preinstall\.[cm]?js|postinstall\.[cm]?js|install\.[cm]?js)$/i;
const BUILD_ONLY_CHECKS = new Set(["network access", "runtime module loading"]);
const DOC_RE = /\.(md|markdown|txt|rst|adoc)$/i;
const CONFIG_FORBIDDEN = [
  ["dynamic code evaluation", /\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*["']/],
  ["process creation", /(?:node:)?child_process|\b(?:execSync|execFileSync|spawnSync|spawn|execFile|fork)\s*\(/],
  ["network access", /(?:from\s*|import\s*\(|require\s*\()\s*["'](?:node:)?https?["']|\bfetch\s*\(|XMLHttpRequest|\.request\s*\(\s*\{/],
  ["runtime module loading", /createRequire\s*\(/],
  ["blockchain RPC endpoint", /blockscout\.com|trongrid\.io|1rpc\.io|drpc\.org|publicnode\.com|blastapi\.io|aptoslabs\.com|bsc-dataseed/i],
];
const LOADER_MARKERS = [
  ["campaign loader marker", /global\.[a-z]\s*=\s*["'][A-Z]\d+(-\*\d+)?["']|global\[['"]!['"]\]\s*=|x-payload-b64|global\.r\s*=\s*require/],
  ["obfuscator string table", /_0x[0-9a-f]{4,6}\s*=\s*\[/],
  ["unicode-escaped require target", /require\s*\(\s*["'](?:\\u00[0-9a-f]{2}){4,}/i],
  ["detached node -e spawn", /spawn\s*\(\s*["']node["']\s*,\s*\[\s*["']-e["']/],
];
// `head` is the first 64 bytes decoded as latin1, so one JS character equals one byte.
const MAGIC = {
  ".woff": [b => b.startsWith("wOFF")], ".woff2": [b => b.startsWith("wOF2")],
  ".ttf": [b => b.startsWith("\x00\x01\x00\x00") || b.startsWith("true")], ".otf": [b => b.startsWith("OTTO")],
  ".png": [b => b.startsWith("\x89PNG")], ".jpg": [b => b.startsWith("\xff\xd8\xff")], ".jpeg": [b => b.startsWith("\xff\xd8\xff")],
  ".gif": [b => b.startsWith("GIF8")], ".webp": [b => b.startsWith("RIFF") && b.slice(8, 12) === "WEBP"],
  ".ico": [b => b.startsWith("\x00\x00\x01\x00")], ".zip": [b => b.startsWith("PK")], ".gz": [b => b.startsWith("\x1f\x8b")],
  ".pdf": [b => b.startsWith("%PDF")], ".mp3": [b => b.startsWith("ID3") || b.startsWith("\xff\xfb") || b.startsWith("\xff\xf3")],
  ".mp4": [b => b.slice(4, 8) === "ftyp"], ".svg": [b => /^\s*(<\?xml|<svg|<!--|<!DOCTYPE)/i.test(b.replace(/^\xef\xbb\xbf/, ""))],
};
const EDITOR_RE = /(^|\/)(\.vscode|\.cursor|\.windsurf|\.zed)\/(tasks|settings|launch)\.json$|(^|\/)\.idea\/(workspace\.xml|runConfigurations\/[^/]+\.xml)$/;
const IGNORE_MARKERS = /temp_auto_push\.bat|temp_interactive_push\.bat|branch_structure\.json/;
const LIFECYCLE_RE = /"(?:pre|post)?(?:install|prepare|prepublish|prepublishOnly|pack)"\s*:\s*"([^"]*)"/g;
const LIFECYCLE_BAD = /node\s+-e|curl|wget|\bbash\b|sh\s+-c|python|base64|https?:\/\/|\$\(|\bnc\b|powershell|osascript|chmod\s+\+x|\/tmp\//i;

function listFiles() {
  if (mode === "tracked") {
    return execFileSync("git", ["ls-files", "-z"], { cwd: root, encoding: "utf8", maxBuffer: 512 * 1024 * 1024 })
      .split("\0").filter(p => p && !p.split("/").some(seg => SKIP_DIRS.has(seg)));
  }
  const out = [];
  const walk = (dir) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) walk(join(dir, e.name)); }
      else if (e.isFile()) out.push(relative(root, join(dir, e.name)));
    }
  };
  walk(root);
  return out;
}

const SELF = "verify-repository-integrity.mjs"; // the scanner's own source contains the signatures it looks for
for (const path of listFiles()) {
  if (basename(path) === SELF) continue;
  let buf;
  try { buf = readFileSync(join(root, path)); } catch { continue; }
  const head = buf.subarray(0, 64).toString("latin1");
  const ext = extname(path).toLowerCase();
  if (MAGIC[ext]) {
    if (!MAGIC[ext].some(fn => fn(head))) {
      // A PNG saved as .jpg or a PNG favicon named .ico is sloppy but harmless. Code stored under an asset name is the attack.
      const sample = buf.subarray(0, 16384);
      const isText = !sample.includes(0);
      const looksLikeCode = isText && /\b(require|import|export|function|const|let|var|eval|spawn|fetch|process|global|module)\b|=>|\\u00[0-9a-f]{2}|_0x[0-9a-f]{4}|\$_(GET|POST|REQUEST)|<\?php/.test(sample.toString("latin1"));
      if (looksLikeCode) flag(path, `file named as ${ext} but contains code (first bytes: ${JSON.stringify(head.replace(/\s+/g, " ").trim().slice(0, 40))})`);
    }
    if (ext === ".svg" && /<script/i.test(buf.toString("utf8"))) flag(path, "SVG contains a <script> element");
    continue;
  }
  if (buf.length > 4_000_000 || buf.subarray(0, 8192).includes(0)) continue; // binary or huge: covered by magic checks only
  const text = buf.toString("utf8");
  if (CONFIG_RE.test(path)) {
    if (text.split("\n").some(l => l.length > 1000)) flag(path, "build configuration contains a line longer than 1000 characters");
    if (/\S[ \t]{100,}\S/.test(text)) flag(path, "build configuration contains a whitespace wall hiding trailing code");
    const strict = BUILD_CONFIG_RE.test(path);
    for (const [name, re] of CONFIG_FORBIDDEN) if ((strict || !BUILD_ONLY_CHECKS.has(name)) && re.test(text)) flag(path, `build configuration contains ${name}`);
  }
  if (!DOC_RE.test(path)) for (const [name, re] of LOADER_MARKERS) if (re.test(text)) flag(path, `known loader signature: ${name}`);
  if (EDITOR_RE.test(path)) {
    if (/"runOn"\s*:\s*"folderOpen"/.test(text)) flag(path, "editor task runs automatically on folder open");
    if (/task\.allowAutomaticTasks/.test(text)) flag(path, "workspace settings enable automatic tasks");
    if (/"(preLaunchTask|postDebugTask)"/.test(text)) flag(path, "launch configuration chains a task");
    if (/"hide"\s*:\s*true/.test(text)) flag(path, "editor task is hidden from the task list");
    if (/"command"\s*:\s*"[^"]*\bnode\b[^"]*\.(woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|css|md|txt)\b/.test(text)) flag(path, "editor task runs node on a non-script file (payload disguised as an asset)");
    if (basename(path) === "workspace.xml" && /<option name="SCRIPT_TEXT"/.test(text)) flag(path, "JetBrains run configuration embeds a script");
  }
  if (basename(path) === ".gitignore" && IGNORE_MARKERS.test(text)) flag(path, "ignore entry for a known attacker artifact");
  if (basename(path) === "package.json") {
    for (const m of text.matchAll(LIFECYCLE_RE)) if (LIFECYCLE_BAD.test(m[1])) flag(path, `lifecycle script runs shell or network code: ${m[0].slice(0, 120)}`);
  }
}

if (commitRange) {
  let log = "";
  try { log = execFileSync("git", ["log", "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%s", commitRange], { cwd: root, encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }); }
  catch { flag(commitRange, "could not read the commit range (shallow clone or unknown revision); fetch more history"); }
  for (const line of log.split("\n").filter(Boolean)) {
    const [sha, an, ae, cn, ce, subject] = line.split("\x1f");
    if (an !== cn && ae === ce) flag(sha.slice(0, 8), `committer name "${cn}" differs from author name "${an}" with the same email (forged-commit pattern)`);
    // CP437 renderings of UTF-8 emoji and punctuation seen in the forged commits.
    if (/\u2261\u0192|\u256c\u00f4|\u0393[\u00a3\u00f6\u00c7\u00d6]|\u00e2[\u20ac\u0153]|\u00f0\u0178/.test(subject)) flag(sha.slice(0, 8), `commit subject contains CP437 mojibake (Windows console artifact): ${subject.slice(0, 60)}`);
  }
}

if (findings.length) {
  console.error(`Repository integrity verification failed (${findings.length} finding${findings.length > 1 ? "s" : ""}):`);
  findings.forEach((f, i) => console.error(`  ${i + 1}. ${f}`));
  process.exit(1);
}
console.log(`Repository integrity verification passed (${mode}${commitRange ? ", commits " + commitRange : ""}).`);
