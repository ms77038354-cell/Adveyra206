import express from "express";
import cookieSession from "cookie-session";
import bcrypt from "bcryptjs";
import rateLimit from "express-rate-limit";
import { GoogleGenAI, Type } from "@google/genai";
import fs from "node:fs/promises";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import archiver from "archiver";
import multer from "multer";
import AdmZip from "adm-zip";

const app = express();
const PORT = process.env.PORT || 10000;
const ROOT = path.resolve("workspace");
const MAX_FILE_BYTES = 2_000_000;
const MAX_ZIP_BYTES = 25_000_000;
const MAX_IMPORT_FILES = 500;
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_ZIP_BYTES, files: 1 } });
const execFileAsync = promisify(execFile);
const BACKUP_ROOT = path.resolve(".adveyra-backups");

app.set("trust proxy", 1);
app.use(express.json({ limit: "18mb" }));
app.use(cookieSession({
  name: "adveyra_session",
  keys: [process.env.SESSION_SECRET || "CHANGE_THIS_SESSION_SECRET_BEFORE_DEPLOY"],
  httpOnly: true,
  sameSite: "lax",
  secure: process.env.NODE_ENV === "production",
  maxAge: 8 * 60 * 60 * 1000
}));
app.use(express.static("public", { etag: true, maxAge: 0 }));

// Serve project preview assets from the workspace with strict no-cache headers.
app.use("/preview", requireAuth, express.static(ROOT, {
  etag: false, lastModified: false, maxAge: 0,
  setHeaders(res) { res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate"); res.setHeader("Pragma", "no-cache"); res.setHeader("Expires", "0"); }
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });
const apiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 30, standardHeaders: true, legacyHeaders: false });

function requireAuth(req, res, next) {
  if (!req.session?.admin) return res.status(401).json({ error: "Please log in." });
  next();
}

function isIgnoredName(name) {
  return name === ".git" || name === "node_modules" || /^\.env(?:\.|$)/i.test(name) || name.startsWith(".adveyra-");
}

function safePath(input) {
  if (typeof input !== "string" || !input.trim()) throw new Error("A file path is required.");
  const normalized = input.replaceAll("\\", "/").replace(/^\/+/, "");
  if (normalized.split("/").some(part => part === ".." || part === "." || isIgnoredName(part))) throw new Error("Invalid or protected path. .git, node_modules, .env and internal backup paths are blocked.");
  const full = path.resolve(ROOT, normalized);
  if (full !== ROOT && !full.startsWith(ROOT + path.sep)) throw new Error("Path is outside the project workspace.");
  return { full, relative: normalized };
}

async function ensureWorkspace() {
  await fs.mkdir(ROOT, { recursive: true });
  await fs.mkdir(BACKUP_ROOT, { recursive: true });
}
await ensureWorkspace();

async function backupExisting(full, relative) {
  try {
    const stat = await fs.stat(full);
    if (!stat.isFile()) return;
    const safeName = relative.replaceAll("/", "__");
    const dir = path.join(BACKUP_ROOT, new Date().toISOString().replaceAll(":", "-").replaceAll(".", "-"));
    await fs.mkdir(dir, { recursive: true });
    await fs.copyFile(full, path.join(dir, safeName));
  } catch (error) { if (error.code !== "ENOENT") throw error; }
}

async function walkWorkspace(dir = ROOT, prefix = "") {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const result = [];
  for (const entry of entries) {
    if (isIgnoredName(entry.name)) continue;
    const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isDirectory()) result.push({ path: rel, type: "directory" }, ...(await walkWorkspace(path.join(dir, entry.name), rel)));
    else result.push({ path: rel, type: "file" });
  }
  return result;
}

app.get("/api/health", (_req, res) => res.json({ ok: true, app: "ADVEYRA AI STUDIO" }));

app.get("/api/session", (req, res) => res.json({ authenticated: Boolean(req.session?.admin), username: req.session?.username || null }));

app.post("/api/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  const expectedUser = process.env.ADMIN_USERNAME;
  const hash = process.env.ADMIN_PASSWORD_HASH;
  if (!expectedUser || !hash) return res.status(503).json({ error: "Admin credentials are not configured on the server." });
  if (username !== expectedUser || typeof password !== "string" || !(await bcrypt.compare(password, hash))) {
    return res.status(401).json({ error: "Incorrect username or password." });
  }
  req.session = { admin: true, username: expectedUser };
  res.json({ ok: true });
});

app.post("/api/logout", requireAuth, (req, res) => {
  req.session = null;
  res.json({ ok: true });
});

app.get("/api/files", requireAuth, async (_req, res) => {
  try { res.json({ files: await walkWorkspace() }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.get("/api/file", requireAuth, async (req, res) => {
  try {
    const { full, relative } = safePath(req.query.path);
    const content = await fs.readFile(full, "utf8");
    res.json({ path: relative, content });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/api/file", requireAuth, async (req, res) => {
  try {
    const { full, relative } = safePath(req.body?.path);
    const content = req.body?.content;
    if (typeof content !== "string" || Buffer.byteLength(content, "utf8") > MAX_FILE_BYTES) {
      return res.status(400).json({ error: "File content must be text and no larger than 500 KB." });
    }
    await fs.mkdir(path.dirname(full), { recursive: true });
    await backupExisting(full, relative);
    await fs.writeFile(full, content, "utf8");
    res.json({ ok: true, path: relative });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/api/folder", requireAuth, async (req, res) => {
  try { const { full, relative } = safePath(req.body?.path); await fs.mkdir(full, { recursive: false }); res.json({ ok: true, path: relative }); }
  catch (e) { res.status(400).json({ error: e.code === "EEXIST" ? "Folder already exists." : e.message }); }
});

app.post("/api/rename", requireAuth, async (req, res) => {
  try {
    const from = safePath(req.body?.from); const to = safePath(req.body?.to);
    await fs.mkdir(path.dirname(to.full), { recursive: true });
    await fs.rename(from.full, to.full);
    res.json({ ok: true, from: from.relative, to: to.relative });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete("/api/file", requireAuth, async (req, res) => {
  try {
    const { full, relative } = safePath(req.body?.path);
    const stat = await fs.stat(full);
    if (!stat.isFile()) return res.status(400).json({ error: "Only files can be deleted from this action." });
    await backupExisting(full, relative);
    await fs.unlink(full);
    res.json({ ok: true, path: relative, backupCreated: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/api/files/bulk-delete", requireAuth, apiLimiter, async (req, res) => {
  try {
    const paths = Array.isArray(req.body?.paths) ? [...new Set(req.body.paths)] : [];
    if (!paths.length) return res.status(400).json({ error: "Select at least one file." });
    if (paths.length > 500) return res.status(413).json({ error: "A maximum of 500 files can be deleted at once." });
    const targets = paths.map(safePath);
    for (const target of targets) {
      const stat = await fs.stat(target.full);
      if (!stat.isFile()) throw new Error(`${target.relative} is not a file.`);
    }
    for (const target of targets) await backupExisting(target.full, target.relative);
    for (const target of targets) await fs.unlink(target.full);
    res.json({ ok: true, deleted: targets.length, paths: targets.map(x => x.relative), backupsCreated: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/api/files/download-selected", requireAuth, apiLimiter, async (req, res) => {
  try {
    const paths = Array.isArray(req.body?.paths) ? [...new Set(req.body.paths)] : [];
    if (!paths.length) return res.status(400).json({ error: "Select at least one file to download." });
    if (paths.length > 500) return res.status(413).json({ error: "A maximum of 500 files can be downloaded at once." });
    const files = [];
    for (const value of paths) {
      const target = safePath(value);
      const stat = await fs.stat(target.full);
      if (!stat.isFile()) throw new Error(`${target.relative} is not a file.`);
      files.push(target);
    }
    res.setHeader("Content-Type", "application/zip");
    res.setHeader("Content-Disposition", 'attachment; filename="adveyra-selected-files.zip"');
    const archive = archiver("zip", { zlib: { level: 8 } });
    archive.on("error", error => res.destroy(error));
    archive.pipe(res);
    for (const file of files) archive.file(file.full, { name: file.relative });
    await archive.finalize();
  } catch (e) { if (!res.headersSent) res.status(400).json({ error: e.message }); else res.destroy(e); }
});

app.post("/api/upload-file", requireAuth, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Choose a file to upload." });
    const { full, relative } = safePath(req.body?.path || req.file.originalname);
    if (req.file.size > MAX_FILE_BYTES) return res.status(413).json({ error: "Single-file upload limit is 2 MB. Use ZIP import for a project." });
    await fs.mkdir(path.dirname(full), { recursive: true });
    await backupExisting(full, relative);
    await fs.writeFile(full, req.file.buffer);
    res.json({ ok: true, path: relative, size: req.file.size });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post("/api/import-zip", requireAuth, upload.single("archive"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Choose a ZIP archive." });
    const zip = new AdmZip(req.file.buffer);
    const entries = zip.getEntries().filter(e => !e.isDirectory);
    if (!entries.length) return res.status(400).json({ error: "The ZIP archive contains no files." });
    if (entries.length > MAX_IMPORT_FILES) return res.status(413).json({ error: `ZIP contains too many files. Maximum: ${MAX_IMPORT_FILES}.` });
    const prepared = [];
    let total = 0;
    for (const entry of entries) {
      const raw = entry.entryName.replaceAll("\\", "/");
      if (raw.startsWith("/") || raw.split("/").some(part => part === ".." || part === ".")) throw new Error(`Unsafe ZIP path rejected: ${raw}`);
      const parts = raw.split("/");
      if (parts.some(part => isIgnoredName(part))) continue;
      const relative = parts.filter(Boolean).join("/");
      if (!relative) continue;
      const data = entry.getData();
      total += data.length;
      if (total > 100_000_000) return res.status(413).json({ error: "ZIP expands beyond the 100 MB import limit." });
      const { full } = safePath(relative);
      prepared.push({ full, relative, data });
    }
    if (!prepared.length) return res.status(400).json({ error: "No importable project files found. .env, .git and node_modules are excluded." });
    // Back up overwritten files before writing any imported content.
    for (const item of prepared) await backupExisting(item.full, item.relative);
    for (const item of prepared) { await fs.mkdir(path.dirname(item.full), { recursive: true }); await fs.writeFile(item.full, item.data); }
    res.json({ ok: true, imported: prepared.length, totalBytes: total, files: prepared.map(x => x.relative) });
  } catch (e) { res.status(400).json({ error: `ZIP import failed: ${e.message}` }); }
});

app.get("/api/diagnostics", requireAuth, async (_req, res) => {
  const checks = [];
  checks.push({ name: "Node.js runtime", ok: Number(process.versions.node.split(".")[0]) >= 20, detail: `Node ${process.versions.node}` });
  checks.push({ name: "Gemini API key configured", ok: Boolean(process.env.GEMINI_API_KEY), detail: process.env.GEMINI_API_KEY ? "Key is configured (hidden)" : "Add GEMINI_API_KEY in Render" });
  checks.push({ name: "Admin credentials configured", ok: Boolean(process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD_HASH), detail: process.env.ADMIN_USERNAME ? "Admin variables found" : "Set ADMIN_USERNAME and ADMIN_PASSWORD_HASH" });
  checks.push({ name: "Session secret configured", ok: Boolean(process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 32), detail: process.env.SESSION_SECRET?.length >= 32 ? "Session secret length looks good" : "Set a random SESSION_SECRET of at least 32 characters" });
  checks.push({ name: "Workspace writable", ok: await fs.access(ROOT).then(() => true).catch(() => false), detail: "Project workspace" });
  const githubReady = Boolean(process.env.GITHUB_TOKEN && process.env.GITHUB_OWNER && process.env.GITHUB_REPO);
  const githubMissing = [!process.env.GITHUB_TOKEN && "GITHUB_TOKEN", !process.env.GITHUB_OWNER && "GITHUB_OWNER", !process.env.GITHUB_REPO && "GITHUB_REPO"].filter(Boolean);
  checks.push({ name: "GitHub integration configured", ok: githubReady, detail: githubReady ? `Configured for ${process.env.GITHUB_OWNER}/${process.env.GITHUB_REPO} (${process.env.GITHUB_BRANCH || "main"})` : `Missing Render variables: ${githubMissing.join(", ")}` });
  res.json({ checks, model: process.env.GEMINI_MODEL || "gemini-3.1-flash-lite" });
});

app.get("/api/export", requireAuth, async (_req, res) => {
  res.setHeader("Content-Type", "application/zip");
  res.setHeader("Content-Disposition", 'attachment; filename="adveyra-project.zip"');
  const archive = archiver("zip", { zlib: { level: 8 } });
  archive.on("error", error => res.destroy(error));
  archive.pipe(res);
  archive.directory(ROOT, false);
  await archive.finalize();
});

app.post("/api/chat", requireAuth, apiLimiter, async (req, res) => {
  if (!process.env.GEMINI_API_KEY) {
    return res.status(503).json({ error: "GEMINI_API_KEY is not configured in the hosting environment." });
  }
  const messages = Array.isArray(req.body?.messages) ? req.body.messages.slice(-16) : [];
  if (!messages.length) return res.status(400).json({ error: "No chat messages provided." });

  const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
  const model = process.env.GEMINI_MODEL || "gemini-3.1-flash-lite";
  const systemInstruction = `You are ADVEYRA AI STUDIO, a careful senior software engineer and coding agent.
You can inspect, create and edit real project files using the available tools.
Before modifying an existing project, inspect its files first. Preserve existing functionality and avoid unnecessary rewrites.
Use relative paths only. Never request, reveal, or write secrets, API keys, passwords, or .env files.
Do not claim that a command, test, preview, GitHub push, or deployment was performed unless this application actually provides and confirms that operation.
You do not have a shell or deployment tool. You can create and edit project files only.
When asked to build something, create practical working source files, then summarize files changed and any manual setup still required.
Ask before destructive changes.`;

  const tools = [{
    functionDeclarations: [
      {
        name: "list_project_files",
        description: "List all files in the current project workspace.",
        parameters: { type: Type.OBJECT, properties: {}, required: [] }
      },
      {
        name: "read_project_file",
        description: "Read a UTF-8 text file from the current project workspace.",
        parameters: {
          type: Type.OBJECT,
          properties: { path: { type: Type.STRING, description: "Relative path of the file." } },
          required: ["path"]
        }
      },
      {
        name: "write_project_file",
        description: "Create or replace a UTF-8 text file in the project workspace. Only write files needed for the user's requested project changes.",
        parameters: {
          type: Type.OBJECT,
          properties: {
            path: { type: Type.STRING, description: "Relative path of the file." },
            content: { type: Type.STRING, description: "Complete UTF-8 text content to save." }
          },
          required: ["path", "content"]
        }
      }
    ]
  }];

  async function runTool(name, args) {
    if (name === "list_project_files") {
      async function walk(dir, prefix = "") {
        const entries = await fs.readdir(dir, { withFileTypes: true });
        const out = [];
        for (const entry of entries) {
          if (isIgnoredName(entry.name)) continue;
          const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
          if (entry.isDirectory()) out.push(...await walk(path.join(dir, entry.name), rel));
          else out.push(rel);
        }
        return out;
      }
      return await walk(ROOT);
    }
    if (name === "read_project_file") {
      const { full } = safePath(args.path);
      return await fs.readFile(full, "utf8");
    }
    if (name === "write_project_file") {
      const { full, relative } = safePath(args.path);
      if (typeof args.content !== "string" || Buffer.byteLength(args.content, "utf8") > MAX_FILE_BYTES) {
        throw new Error("File is too large or invalid.");
      }
      await fs.mkdir(path.dirname(full), { recursive: true });
      await backupExisting(full, relative);
      await fs.writeFile(full, args.content, "utf8");
      return { saved: relative, backupCreated: true };
    }
    throw new Error("Unknown tool.");
  }

  try {
    // Gemini uses role "model" for assistant turns and role "user" for user turns.
    const contents = messages.map((m, index) => {
      const parts = [{ text: String(m.content || "").slice(0, 12000) }];
      if (index === messages.length - 1 && Array.isArray(req.body?.images)) {
        for (const image of req.body.images.slice(0, 4)) {
          if (!image || typeof image.data !== "string" || !/^image\/(png|jpeg|webp|gif)$/.test(image.mimeType || "")) continue;
          const raw = image.data.replace(/^data:image\/[^;]+;base64,/, "");
          if (raw.length > 5_000_000) continue;
          parts.push({ inlineData: { mimeType: image.mimeType, data: raw } });
        }
      }
      return { role: m.role === "assistant" ? "model" : "user", parts };
    });

    let finalText = "";
    for (let turn = 0; turn < 6; turn++) {
      const response = await ai.models.generateContent({
        model,
        contents,
        config: {
          systemInstruction,
          tools,
          temperature: 0.2,
          maxOutputTokens: 8192
        }
      });

      const functionCalls = response.functionCalls || [];
      if (!functionCalls.length) {
        finalText = response.text || "The agent completed its tool steps. Please check the project files.";
        break;
      }

      // Preserve the model's function-call turn, then return tool results as a user turn.
      const modelContent = response.candidates?.[0]?.content;
      if (modelContent) contents.push(modelContent);
      const functionResponses = [];
      for (const call of functionCalls) {
        let result;
        try {
          result = await runTool(call.name, call.args || {});
        } catch (toolError) {
          result = { error: toolError.message };
        }
        const functionResponse = {
          name: call.name,
          response: { result }
        };
        if (call.id) functionResponse.id = call.id;
        functionResponses.push({ functionResponse });
      }
      contents.push({ role: "user", parts: functionResponses });
    }

    if (!finalText) finalText = "I completed the available file operations. Please refresh the Files panel to review the changes.";
    res.json({ reply: finalText });
  } catch (e) {
    const status = Number(e?.status || e?.code || 0);
    const message = String(e?.message || "Gemini request failed.");
    console.error("Gemini request failed:", message);
    if (status === 429 || /quota|rate.?limit|resource exhausted/i.test(message)) {
      return res.status(429).json({ error: "Gemini API free-tier quota or rate limit reached. Wait for the limit to reset or review your Google AI Studio usage limits." });
    }
    if (status === 400 && /model/i.test(message)) {
      return res.status(400).json({ error: `Gemini model '${model}' is unavailable for this API key. Check GEMINI_MODEL in Render.` });
    }
    if (status === 401 || status === 403 || /api.?key|permission|unauthenticated/i.test(message)) {
      return res.status(502).json({ error: "Gemini API key is invalid or does not have permission to use this model. Check GEMINI_API_KEY in Render." });
    }
    res.status(500).json({ error: message.slice(0, 500) });
  }
});

app.post("/api/github/push", requireAuth, apiLimiter, async (req, res) => {
  const { GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO } = process.env;
  const branch = process.env.GITHUB_BRANCH || "main";
  if (!GITHUB_TOKEN || !GITHUB_OWNER || !GITHUB_REPO) {
    return res.status(503).json({ error: "Configure GITHUB_TOKEN, GITHUB_OWNER and GITHUB_REPO in hosting environment variables first." });
  }
  try {
    async function gh(url, options = {}) {
      const r = await fetch(`https://api.github.com${url}`, {
        ...options,
        headers: {
          "Accept": "application/vnd.github+json",
          "Authorization": `Bearer ${GITHUB_TOKEN}`,
          "X-GitHub-Api-Version": "2022-11-28",
          "Content-Type": "application/json",
          ...(options.headers || {})
        }
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.message || `GitHub API error ${r.status}`);
      return data;
    }
    let ref;
    try { ref = await gh(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/ref/heads/${branch}`); }
    catch { return res.status(400).json({ error: `Branch '${branch}' was not found. Create the repository and branch first.` }); }
    const parentSha = ref.object.sha;
    const parentCommit = await gh(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/commits/${parentSha}`);
    async function walk(dir, prefix = "") {
      const entries = await fs.readdir(dir, { withFileTypes: true });
      let out = [];
      for (const entry of entries) {
        if (isIgnoredName(entry.name)) continue;
        const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
        if (entry.isDirectory()) out.push(...await walk(path.join(dir, entry.name), rel));
        else {
          const content = await fs.readFile(path.join(dir, entry.name));
          const blob = await gh(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/blobs`, { method: "POST", body: JSON.stringify({ content: content.toString("base64"), encoding: "base64" }) });
          out.push({ path: rel, mode: "100644", type: "blob", sha: blob.sha });
        }
      }
      return out;
    }
    const treeItems = await walk(ROOT);
    if (!treeItems.length) return res.status(400).json({ error: "The workspace is empty. Create or import project files before pushing." });
    const tree = await gh(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/trees`, {
      method: "POST", body: JSON.stringify({ base_tree: parentCommit.tree.sha, tree: treeItems })
    });
    const commit = await gh(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/commits`, {
      method: "POST", body: JSON.stringify({ message: req.body?.message || "Update from ADVEYRA AI Studio", tree: tree.sha, parents: [parentSha] })
    });
    await gh(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/git/refs/heads/${branch}`, {
      method: "PATCH", body: JSON.stringify({ sha: commit.sha })
    });
    res.json({ ok: true, commit: commit.sha, url: `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/commit/${commit.sha}` });
  } catch (e) {
    const message = String(e.message || "GitHub push failed.");
    const status = /bad credentials|resource not accessible|not found|permission|protected branch/i.test(message) ? 400 : 502;
    res.status(status).json({ error: `GitHub push failed: ${message}. Check that the token has Contents: Read and write permission and that owner, repository and branch are correct.` });
  }
});

app.listen(PORT, "0.0.0.0", () => console.log(`ADVEYRA AI STUDIO listening on ${PORT}`));
