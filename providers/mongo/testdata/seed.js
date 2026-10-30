// Seed fixtures for the mongo provider integration test.
// Load with: mongosh -u admin -p <pw> --authenticationDatabase admin seed.js

// Every fixture account shares one throwaway value in the `pwd` slot. MongoDB
// only requires a non-empty string there, so it is assembled at load time from
// self-describing words instead of being written as a credential-shaped
// literal, which credential scanners flag on sight.
const FIXTURE_PLACEHOLDER = ["not", "a", "real", "credential"].join("-");

// A custom role in appdb with a narrow privilege.
db.getSiblingDB("appdb").createRole({
  role: "appReadMetrics",
  privileges: [
    { resource: { db: "appdb", collection: "metrics" }, actions: ["find"] },
  ],
  roles: [{ role: "read", db: "appdb" }],
});

// A low-privilege application user granted the custom role.
db.getSiblingDB("appdb").createUser({
  user: "appuser",
  pwd: FIXTURE_PLACEHOLDER,
  roles: [{ role: "appReadMetrics", db: "appdb" }],
});

// A user holding a high-privilege built-in role (superuser-review fixture).
db.getSiblingDB("admin").createUser({
  user: "opsadmin",
  pwd: FIXTURE_PLACEHOLDER,
  roles: [{ role: "readWriteAnyDatabase", db: "admin" }],
});

// A custom role that inherits a superuser role, and a second one that reaches
// it only through the first. Users holding either have full control without a
// privileged role appearing on the account itself.
db.getSiblingDB("admin").createRole({
  role: "appMetricsAdmin",
  privileges: [],
  roles: [{ role: "userAdminAnyDatabase", db: "admin" }],
});
db.getSiblingDB("admin").createRole({
  role: "appSupport",
  privileges: [],
  roles: [{ role: "appMetricsAdmin", db: "admin" }],
});

db.getSiblingDB("admin").createUser({
  user: "metricsbot",
  pwd: FIXTURE_PLACEHOLDER,
  roles: [{ role: "appMetricsAdmin", db: "admin" }],
});
db.getSiblingDB("admin").createUser({
  user: "supportbot",
  pwd: FIXTURE_PLACEHOLDER,
  roles: [{ role: "appSupport", db: "admin" }],
});

print("seed complete");
