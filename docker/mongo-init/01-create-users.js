// Runs once, as root, when the mongo-data volume is empty.
// Each user lives in the db it works on, so URIs use authSource=<that db>.

function requireEnv(name) {
  const value = process.env[name];
  if (!value) throw new Error(`${name} is not set`);
  return value;
}

// The agent's tools read telemetry through this user; it has no write role anywhere.
db.getSiblingDB("telemetry").createUser({
  user: "telemetry_reader",
  pwd: requireEnv("MONGO_TELEMETRY_READER_PASSWORD"),
  roles: [{ role: "read", db: "telemetry" }],
});

// The API stores investigations and their steps here; it cannot touch telemetry.
db.getSiblingDB("triage").createUser({
  user: "app",
  pwd: requireEnv("MONGO_APP_PASSWORD"),
  roles: [{ role: "readWrite", db: "triage" }],
});
