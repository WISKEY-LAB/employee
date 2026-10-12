const assert = require("node:assert/strict");
const fs = require("node:fs/promises");
const os = require("node:os");
const path = require("node:path");
const test = require("node:test");
const { createServer } = require("../server");

const temporaryDirectories = [];
const setupKey = "test-only-first-admin-setup-key-2468";
const employee = {
  firstName: "Ayesha",
  lastName: "Khan",
  email: "ayesha@example.com",
  phone: "+1 555 010 1020",
  employeeCode: "",
  jobTitle: "People Manager",
  department: "People",
  employmentType: "Full-time",
  status: "Active",
  salary: 65000,
  currency: "USD",
  hoursPerWeek: 40,
  idType: "Passport",
  idNumber: "EXAMPLE-123",
  photo: "",
  idFront: "",
  idBack: ""
};

async function startTestServer(directory) {
  const server = createServer({
    dataFile: path.join(directory, "peopledesk.json"),
    setupKey
  });
  await server.loadDatabase();
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
  return { server, origin: `http://127.0.0.1:${server.address().port}` };
}

async function newWorkspace(t) {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), "peopledesk-test-"));
  temporaryDirectories.push(directory);
  t.after(() => fs.rm(directory, { recursive: true, force: true }));
  return directory;
}

function stopServer(t, server) {
  t.after(() => new Promise((resolve) => {
    if (!server.listening) return resolve();
    server.close(() => resolve());
  }));
}

async function api(origin, route, { method = "GET", body, cookie, headers = {} } = {}) {
  const response = await fetch(`${origin}${route}`, {
    method,
    headers: {
      ...(body === undefined ? {} : { "Content-Type": "application/json" }),
      ...(cookie ? { Cookie: cookie } : {}),
      ...headers
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) })
  });
  return { status: response.status, body: await response.json(), cookie: response.headers.getSetCookie()?.[0] || "" };
}

function cookieFrom(response) {
  return response.cookie.split(";", 1)[0];
}

async function setup(origin, overrides = {}) {
  return api(origin, "/api/setup", {
    method: "POST",
    body: {
      setupKey,
      username: "people-admin",
      password: "Long-Strong-Password-123!",
      employees: [],
      ...overrides
    }
  });
}

test("employee records are shared between sign-ins and survive a server restart", async (t) => {
  const directory = await newWorkspace(t);
  const first = await startTestServer(directory);
  stopServer(t, first.server);

  assert.equal((await api(first.origin, "/api/employees")).status, 401);
  const createdAdmin = await setup(first.origin);
  assert.equal(createdAdmin.status, 201);
  const firstDevice = cookieFrom(createdAdmin);
  assert.ok(firstDevice);

  const createdEmployee = await api(first.origin, "/api/employees", {
    method: "POST",
    cookie: firstDevice,
    body: employee
  });
  assert.equal(createdEmployee.status, 201);
  assert.match(createdEmployee.body.employee.employeeCode, /^EMP-00001$/);

  const secondSignIn = await api(first.origin, "/api/login", {
    method: "POST",
    body: { username: "PEOPLE-ADMIN", password: "Long-Strong-Password-123!" }
  });
  assert.equal(secondSignIn.status, 200);
  const secondDevice = cookieFrom(secondSignIn);
  assert.notEqual(secondDevice, firstDevice);
  assert.equal((await api(first.origin, "/api/employees", { cookie: secondDevice })).body.employees.length, 1);
  const employeeRecord = createdEmployee.body.employee;
  const updatedEmployee = await api(first.origin, `/api/employees/${employeeRecord.id}`, {
    method: "PUT",
    cookie: secondDevice,
    body: { ...employeeRecord, salary: 72000, department: "People Operations" }
  });
  assert.equal(updatedEmployee.status, 200);
  const sharedUpdate = await api(first.origin, "/api/employees", { cookie: firstDevice });
  assert.equal(sharedUpdate.body.employees[0].salary, 72000);
  assert.equal(sharedUpdate.body.employees[0].department, "People Operations");

  const restarted = await new Promise((resolve, reject) => first.server.close((error) =>
    error ? reject(error) : resolve(null)
  )).then(() => startTestServer(directory));
  stopServer(t, restarted.server);

  const signedInAgain = await api(restarted.origin, "/api/login", {
    method: "POST",
    body: { username: "people-admin", password: "Long-Strong-Password-123!" }
  });
  assert.equal(signedInAgain.status, 200);
  const saved = await api(restarted.origin, "/api/employees", { cookie: cookieFrom(signedInAgain) });
  assert.equal(saved.body.employees[0].email, "ayesha@example.com");
  assert.equal(saved.body.employees[0].employeeCode, "EMP-00001");
  assert.equal(saved.body.employees[0].salary, 72000);
  const deleted = await api(restarted.origin, `/api/employees/${saved.body.employees[0].id}`, {
    method: "DELETE",
    cookie: cookieFrom(signedInAgain)
  });
  assert.equal(deleted.status, 200);
  assert.equal((await api(restarted.origin, "/api/employees", { cookie: cookieFrom(signedInAgain) })).body.employees.length, 0);
});

test("only one administrator can win simultaneous first-time setup", async (t) => {
  const directory = await newWorkspace(t);
  const { server, origin } = await startTestServer(directory);
  stopServer(t, server);

  const attempts = await Promise.all([setup(origin), setup(origin)]);
  assert.deepEqual(attempts.map((attempt) => attempt.status).sort(), [201, 409]);
  assert.equal((await api(origin, "/api/status")).body.setupRequired, false);
});

test("admin setup requires its secret, supports one-time local data migration, and closes afterward", async (t) => {
  const directory = await newWorkspace(t);
  const { server, origin } = await startTestServer(directory);
  stopServer(t, server);

  const wrongKey = await setup(origin, { setupKey: "incorrect-key" });
  assert.equal(wrongKey.status, 403);

  const created = await setup(origin, { employees: [employee] });
  assert.equal(created.status, 201);
  assert.equal(created.body.importedCount, 1);

  const secondSetup = await setup(origin);
  assert.equal(secondSetup.status, 409);
  const migrated = await api(origin, "/api/employees", { cookie: cookieFrom(created) });
  assert.equal(migrated.body.employees.length, 1);
  assert.equal(migrated.body.employees[0].idNumber, "EXAMPLE-123");
});

test("cross-origin writes and malformed employee profiles are rejected", async (t) => {
  const directory = await newWorkspace(t);
  const { server, origin } = await startTestServer(directory);
  stopServer(t, server);
  const admin = await setup(origin);
  const cookie = cookieFrom(admin);

  const crossOrigin = await api(origin, "/api/employees", {
    method: "POST",
    cookie,
    headers: { Origin: "https://attacker.example" },
    body: employee
  });
  assert.equal(crossOrigin.status, 403);

  const invalidEmployee = await api(origin, "/api/employees", {
    method: "POST",
    cookie,
    body: { ...employee, salary: -1 }
  });
  assert.equal(invalidEmployee.status, 400);
  assert.equal((await api(origin, "/api/employees", { cookie })).body.employees.length, 0);
});

test.after(async () => {
  await Promise.all(temporaryDirectories.map((directory) =>
    fs.rm(directory, { recursive: true, force: true })
  ));
});
