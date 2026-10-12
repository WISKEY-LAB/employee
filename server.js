const crypto = require("node:crypto");
const fs = require("node:fs/promises");
const http = require("node:http");
const path = require("node:path");
const { promisify } = require("node:util");

const pbkdf2 = promisify(crypto.pbkdf2);
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const dataFile = path.resolve(process.env.DATA_FILE || path.join(__dirname, "data", "peopledesk.json"));
const sessionCookie = isProduction ? "__Host-peopledesk-session" : "peopledesk-session";
const sessionLifetime = 12 * 60 * 60 * 1000;
const maximumRequestBytes = 12 * 1024 * 1024;
const maximumImageCharacters = 440_000;
const allowedCurrencies = new Set(["USD", "EUR", "GBP", "INR", "CAD", "AUD", "PKR"]);
const allowedEmploymentTypes = new Set(["Full-time", "Part-time", "Contract", "Intern"]);
const allowedStatuses = new Set(["Active", "On leave", "Inactive"]);

function createServer(options = {}) {
  const storeFile = options.dataFile || dataFile;
  let setupKey = options.setupKey ?? process.env.ADMIN_SETUP_KEY;
  if (!setupKey && isProduction) {
    throw new Error("ADMIN_SETUP_KEY must be configured before starting PeopleDesk in production.");
  }
  if (!setupKey) {
    setupKey = crypto.randomBytes(32).toString("hex");
    console.log(`Local first-admin setup key: ${setupKey}`);
  }

  const sessions = new Map();
  const loginAttempts = new Map();
  let database;
  let writeQueue = Promise.resolve();

  async function loadDatabase() {
    try {
      const saved = JSON.parse(await fs.readFile(storeFile, "utf8"));
      if (!saved || !Array.isArray(saved.admins) || !Array.isArray(saved.employees)) {
        throw new Error("PeopleDesk data file has an invalid format.");
      }
      database = saved;
    } catch (error) {
      if (error.code === "ENOENT") {
        database = { admins: [], employees: [] };
        return;
      }
      throw new Error(`Could not load the PeopleDesk database: ${error.message}`, { cause: error });
    }
  }

  function persistDatabase() {
    const contents = JSON.stringify(database);
    writeQueue = writeQueue.catch(() => {}).then(async () => {
      await fs.mkdir(path.dirname(storeFile), { recursive: true });
      const temporaryFile = `${storeFile}.${crypto.randomUUID()}.tmp`;
      try {
        await fs.writeFile(temporaryFile, contents, { mode: 0o600 });
        await fs.rename(temporaryFile, storeFile);
      } catch (error) {
        await fs.rm(temporaryFile, { force: true }).catch((cleanupError) => {
          console.error("Could not clean up a temporary database file.", cleanupError);
        });
        throw error;
      }
    });
    return writeQueue;
  }

  function sendJson(response, status, value, additionalHeaders = {}) {
    response.writeHead(status, {
      "Cache-Control": "no-store",
      "Content-Type": "application/json; charset=utf-8",
      "X-Content-Type-Options": "nosniff",
      ...additionalHeaders
    });
    response.end(JSON.stringify(value));
  }

  function sessionHeaders(token, clear = false) {
    const value = clear ? "" : token;
    const attributes = `Path=/; HttpOnly; SameSite=Strict${isProduction ? "; Secure" : ""}`;
    return {
      "Set-Cookie": `${sessionCookie}=${value}; ${attributes}${clear ? "; Max-Age=0" : `; Max-Age=${sessionLifetime / 1000}`}`
    };
  }

  function setSecurityHeaders(response) {
    response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("X-Frame-Options", "DENY");
    response.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    if (isProduction) response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
    response.setHeader(
      "Content-Security-Policy",
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    );
  }

  function readCookie(request, name) {
    const cookies = request.headers.cookie || "";
    for (const cookie of cookies.split(";")) {
      const separator = cookie.indexOf("=");
      if (separator === -1) continue;
      if (cookie.slice(0, separator).trim() === name) return cookie.slice(separator + 1).trim();
    }
    return "";
  }

  function getSession(request) {
    const token = readCookie(request, sessionCookie);
    const session = token && sessions.get(token);
    if (!session) return null;
    if (session.expiresAt <= Date.now()) {
      sessions.delete(token);
      return null;
    }
    session.expiresAt = Date.now() + sessionLifetime;
    return { token, username: session.username };
  }

  function denyCrossOriginMutation(request, response) {
    const origin = request.headers.origin;
    if (!origin) return false;
    try {
      if (new URL(origin).host === request.headers.host) return false;
    } catch (error) {
      console.error("Received a malformed request Origin header.", error);
    }
    sendJson(response, 403, { error: "This request could not be verified." });
    return true;
  }

  async function readJson(request) {
    let size = 0;
    const chunks = [];
    for await (const chunk of request) {
      size += chunk.length;
      if (size > maximumRequestBytes) {
        const error = new Error("The uploaded data is too large. Please use smaller images.");
        error.status = 413;
        throw error;
      }
      chunks.push(chunk);
    }
    try {
      const value = JSON.parse(Buffer.concat(chunks).toString("utf8"));
      if (!value || typeof value !== "object" || Array.isArray(value)) {
        throw new Error("Request body must be a JSON object.");
      }
      return value;
    } catch (cause) {
      if (cause instanceof SyntaxError) {
        const error = new Error("The request body must contain valid JSON.");
        error.status = 400;
        throw error;
      }
      cause.status = 400;
      throw cause;
    }
  }

  function rateLimit(request, response, scope, limit = 10) {
    const identity = `${request.socket.remoteAddress || "unknown"}:${scope}`;
    const now = Date.now();
    const previous = loginAttempts.get(identity);
    const attempt = previous && previous.resetAt > now ? previous : { count: 0, resetAt: now + 15 * 60 * 1000 };
    attempt.count += 1;
    loginAttempts.set(identity, attempt);
    if (loginAttempts.size > 5000) {
      for (const [key, value] of loginAttempts) if (value.resetAt <= now) loginAttempts.delete(key);
    }
    if (attempt.count <= limit) return false;
    response.setHeader("Retry-After", String(Math.ceil((attempt.resetAt - now) / 1000)));
    sendJson(response, 429, { error: "Too many attempts. Please try again in a few minutes." });
    return true;
  }

  async function createPasswordHash(password) {
    const salt = crypto.randomBytes(16);
    const hash = await pbkdf2(password, salt, 210_000, 32, "sha256");
    return { salt: salt.toString("hex"), passwordHash: hash.toString("hex") };
  }

  async function verifyPassword(password, account) {
    const salt = Buffer.from(account.salt, "hex");
    const expected = Buffer.from(account.passwordHash, "hex");
    const actual = await pbkdf2(password, salt, 210_000, expected.length, "sha256");
    return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
  }

  function isAuthorized(request, response) {
    if (getSession(request)) return true;
    sendJson(response, 401, { error: "Your session has expired. Please sign in again." });
    return false;
  }

  function invalidInput(message) {
    const error = new Error(message);
    error.status = 400;
    return error;
  }

  function boundedText(value, field, maximumLength, required = false) {
    const text = value == null ? "" : String(value).trim();
    if (text.length > maximumLength || (required && !text)) {
      throw invalidInput(`${field} is required and must be no longer than ${maximumLength} characters.`);
    }
    return text;
  }

  function cleanImage(value) {
    if (value == null || value === "") return "";
    if (typeof value !== "string" || value.length > maximumImageCharacters ||
        !/^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/.test(value)) {
      throw invalidInput("Employee images must be compressed JPEGs smaller than 320 KB.");
    }
    return value;
  }

  function cleanEmployee(input) {
    if (!input || typeof input !== "object" || Array.isArray(input)) {
      throw invalidInput("Employee details must be provided as an object.");
    }
    const salary = Number(input.salary);
    const hoursPerWeek = Number(input.hoursPerWeek);
    const currency = boundedText(input.currency || "USD", "Currency", 3);
    const employmentType = boundedText(input.employmentType || "Full-time", "Employment type", 20);
    const status = boundedText(input.status || "Active", "Status", 20);
    if (!Number.isFinite(salary) || salary < 0 || salary > 1_000_000_000) {
      throw invalidInput("Enter a valid monthly salary.");
    }
    if (!Number.isFinite(hoursPerWeek) || hoursPerWeek < 0 || hoursPerWeek > 168) {
      throw invalidInput("Working hours must be between 0 and 168 per week.");
    }
    if (!allowedCurrencies.has(currency)) throw invalidInput("Select a supported currency.");
    if (!allowedEmploymentTypes.has(employmentType)) throw invalidInput("Select a supported employment type.");
    if (!allowedStatuses.has(status)) throw invalidInput("Select a supported employee status.");
    const email = boundedText(input.email, "Email address", 120, true);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw invalidInput("Enter a valid email address.");
    return {
      firstName: boundedText(input.firstName, "First name", 60, true),
      lastName: boundedText(input.lastName, "Last name", 60, true),
      email,
      phone: boundedText(input.phone, "Phone number", 30),
      dateOfBirth: boundedText(input.dateOfBirth, "Date of birth", 10),
      address: boundedText(input.address, "Home address", 180),
      employeeCode: boundedText(input.employeeCode, "Employee ID", 30),
      jobTitle: boundedText(input.jobTitle, "Job title", 80, true),
      department: boundedText(input.department, "Department", 60, true),
      employmentType,
      status,
      salary,
      currency,
      hoursPerWeek,
      startDate: boundedText(input.startDate, "Start date", 10),
      notes: boundedText(input.notes, "Additional notes", 1000),
      idType: boundedText(input.idType, "ID document type", 40),
      idNumber: boundedText(input.idNumber, "ID document number", 60),
      idExpiry: boundedText(input.idExpiry, "ID expiry date", 10),
      photo: cleanImage(input.photo),
      idFront: cleanImage(input.idFront),
      idBack: cleanImage(input.idBack)
    };
  }

  function nextEmployeeCode() {
    const highest = database.employees.reduce((max, employee) => {
      const match = /^EMP-(\d+)$/i.exec(employee.employeeCode || "");
      return match ? Math.max(max, Number(match[1])) : max;
    }, 0);
    return `EMP-${String(highest + 1).padStart(5, "0")}`;
  }

  function uniqueImportedEmployeeCode(candidate, usedCodes) {
    let code = boundedText(candidate.employeeCode, "Employee ID", 30);
    if (!code || usedCodes.has(code.toUpperCase())) {
      let sequence = 1;
      do {
        code = `EMP-${String(sequence++).padStart(5, "0")}`;
      } while (usedCodes.has(code));
    }
    usedCodes.add(code.toUpperCase());
    return code;
  }

  const server = http.createServer(async (request, response) => {
    setSecurityHeaders(response);
    const requestUrl = new URL(request.url, "http://localhost");
    const pathname = requestUrl.pathname;
    const method = request.method;

    if (pathname.startsWith("/api/") && method !== "GET" && denyCrossOriginMutation(request, response)) return;

    try {
      if (method === "GET" && pathname === "/healthz") {
        return sendJson(response, 200, { ok: true });
      }
      if (method === "GET" && pathname === "/api/status") {
        return sendJson(response, 200, {
          setupRequired: database.admins.length === 0,
          setupConfigured: Boolean(setupKey)
        });
      }
      if (method === "GET" && pathname === "/api/session") {
        const session = getSession(request);
        return sendJson(response, 200, { authenticated: Boolean(session), username: session?.username || "" });
      }
      if (method === "POST" && pathname === "/api/setup") {
        if (rateLimit(request, response, "setup", 8)) return;
        if (database.admins.length > 0) {
          return sendJson(response, 409, { error: "An admin account already exists. Please sign in." });
        }
        const body = await readJson(request);
        const submittedSetupKey = typeof body.setupKey === "string" ? Buffer.from(body.setupKey) : Buffer.alloc(0);
        const configuredSetupKey = Buffer.from(setupKey);
        if (submittedSetupKey.length !== configuredSetupKey.length ||
            !crypto.timingSafeEqual(submittedSetupKey, configuredSetupKey)) {
          return sendJson(response, 403, { error: "The first-admin setup key is incorrect." });
        }
        const username = boundedText(body.username, "Username", 40, true);
        const password = typeof body.password === "string" ? body.password : "";
        if (!/^[A-Za-z0-9_.@-]{3,40}$/.test(username)) {
          return sendJson(response, 400, { error: "Use 3–40 letters, numbers, dots, underscores, or hyphens for the username." });
        }
        if (password.length < 12 || password.length > 256) {
          return sendJson(response, 400, { error: "Choose a password between 12 and 256 characters long." });
        }
        const account = await createPasswordHash(password);
        if (database.admins.length > 0) {
          return sendJson(response, 409, { error: "An admin account was just created. Please sign in." });
        }
        const normalizedUsername = username.toLowerCase();
        const imported = [];
        const usedCodes = new Set(database.employees.map((item) => String(item.employeeCode || "").toUpperCase()));
        if (Array.isArray(body.employees)) {
          if (body.employees.length > 1000) {
            return sendJson(response, 400, { error: "The employee import must contain no more than 1,000 records." });
          }
          for (const candidate of body.employees) {
            const employee = cleanEmployee(candidate);
            employee.id = crypto.randomUUID();
            employee.employeeCode = uniqueImportedEmployeeCode(candidate, usedCodes);
            imported.push(employee);
          }
        }
        database.admins.push({ username, normalizedUsername, ...account });
        database.employees.push(...imported);
        try {
          await persistDatabase();
        } catch (error) {
          database.admins = [];
          database.employees = database.employees.filter((employee) => !imported.some((item) => item.id === employee.id));
          throw error;
        }
        const token = crypto.randomBytes(32).toString("hex");
        sessions.set(token, { username, expiresAt: Date.now() + sessionLifetime });
        return sendJson(response, 201, { username, importedCount: imported.length }, sessionHeaders(token));
      }
      if (method === "POST" && pathname === "/api/login") {
        const body = await readJson(request);
        const username = typeof body.username === "string" ? body.username.trim() : "";
        if (rateLimit(request, response, `login:${username.toLowerCase()}`)) return;
        const password = typeof body.password === "string" ? body.password : "";
        const account = database.admins.find((admin) => admin.normalizedUsername === username.toLowerCase());
        if (!account || !(await verifyPassword(password, account))) {
          return sendJson(response, 401, { error: "Incorrect username or password." });
        }
        const token = crypto.randomBytes(32).toString("hex");
        sessions.set(token, { username: account.username, expiresAt: Date.now() + sessionLifetime });
        return sendJson(response, 200, { username: account.username }, sessionHeaders(token));
      }
      if (method === "POST" && pathname === "/api/logout") {
        const session = getSession(request);
        if (session) sessions.delete(session.token);
        return sendJson(response, 200, { ok: true }, sessionHeaders("", true));
      }
      if (pathname.startsWith("/api/employees") && !isAuthorized(request, response)) return;
      if (method === "GET" && pathname === "/api/employees") {
        return sendJson(response, 200, { employees: database.employees });
      }
      if (method === "POST" && pathname === "/api/employees/import") {
        const body = await readJson(request);
        if (database.employees.length > 0) {
          return sendJson(response, 409, { error: "Shared employee records already exist. Your local copy was not imported." });
        }
        if (!Array.isArray(body.employees) || body.employees.length > 1000) {
          return sendJson(response, 400, { error: "The employee import must contain no more than 1,000 records." });
        }
        const imported = [];
        const usedCodes = new Set(database.employees.map((item) => String(item.employeeCode || "").toUpperCase()));
        for (const candidate of body.employees) {
          const employee = cleanEmployee(candidate);
          employee.id = crypto.randomUUID();
          employee.employeeCode = uniqueImportedEmployeeCode(candidate, usedCodes);
          imported.push(employee);
        }
        database.employees.push(...imported);
        try {
          await persistDatabase();
        } catch (error) {
          database.employees = database.employees.filter((employee) => !imported.some((item) => item.id === employee.id));
          throw error;
        }
        return sendJson(response, 201, { importedCount: imported.length });
      }
      if (method === "POST" && pathname === "/api/employees") {
        const employee = cleanEmployee(await readJson(request));
        employee.id = crypto.randomUUID();
        employee.employeeCode = nextEmployeeCode();
        database.employees.push(employee);
        try {
          await persistDatabase();
        } catch (error) {
          database.employees = database.employees.filter((item) => item.id !== employee.id);
          throw error;
        }
        return sendJson(response, 201, { employee });
      }
      const employeeRoute = /^\/api\/employees\/([0-9a-f-]+)$/i.exec(pathname);
      if (employeeRoute && method === "PUT") {
        const employeeId = employeeRoute[1];
        const index = database.employees.findIndex((item) => item.id === employeeId);
        if (index === -1) return sendJson(response, 404, { error: "Employee not found." });
        const currentEmployee = database.employees[index];
        const employee = cleanEmployee(await readJson(request));
        employee.id = currentEmployee.id;
        employee.employeeCode = currentEmployee.employeeCode;
        database.employees[index] = employee;
        try {
          await persistDatabase();
        } catch (error) {
          database.employees[index] = currentEmployee;
          throw error;
        }
        return sendJson(response, 200, { employee });
      }
      if (employeeRoute && method === "DELETE") {
        const index = database.employees.findIndex((item) => item.id === employeeRoute[1]);
        if (index === -1) return sendJson(response, 404, { error: "Employee not found." });
        const [employee] = database.employees.splice(index, 1);
        try {
          await persistDatabase();
        } catch (error) {
          database.employees.splice(index, 0, employee);
          throw error;
        }
        return sendJson(response, 200, { ok: true });
      }
      if (pathname.startsWith("/api/")) return sendJson(response, 404, { error: "API route not found." });
      if (method !== "GET" && method !== "HEAD") return sendJson(response, 405, { error: "Method not allowed." });
      if (pathname !== "/" && pathname !== "/index.html") {
        response.writeHead(404, { "Content-Type": "text/plain; charset=utf-8", "X-Content-Type-Options": "nosniff" });
        return response.end("Not found");
      }
      const page = await fs.readFile(path.join(__dirname, "index.html"));
      response.writeHead(200, {
        "Cache-Control": "no-store",
        "Content-Length": page.length,
        "Content-Type": "text/html; charset=utf-8"
      });
      return response.end(method === "HEAD" ? undefined : page);
    } catch (error) {
      if ((Number.isInteger(error.status) ? error.status : 500) >= 500) {
        console.error(`Request failed (${method} ${pathname}).`, error);
      }
      if (!response.headersSent) {
        const status = Number.isInteger(error.status) ? error.status : 500;
        sendJson(response, status, {
          error: status === 500 ? "The server could not complete your request. Please try again." : error.message
        });
      } else {
        response.destroy(error);
      }
    }
  });

  server.on("close", () => {
    sessions.clear();
    loginAttempts.clear();
  });
  server.loadDatabase = loadDatabase;
  server.closeResources = () => persistDatabase();
  return server;
}

async function startServer() {
  const server = createServer();
  await server.loadDatabase();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(PORT, "0.0.0.0", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  console.log(`PeopleDesk is listening on port ${PORT}.`);
  return server;
}

if (require.main === module) {
  startServer().catch((error) => {
    console.error("Could not start PeopleDesk.", error);
    process.exitCode = 1;
  });
}

module.exports = { createServer, startServer };
