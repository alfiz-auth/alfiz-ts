# @alfiz-auth/prisma

The Prisma storage driver for the Alfiz Application. It implements the
storage seam (`StorageDriver` from `@alfiz-auth/application`) over a Prisma
client — and does it without depending on `@prisma/client`: the driver is
written against a structural interface (`AlfizPrismaDelegates`) that any
client generated from the bundled schema fragment satisfies.

## 1. Merge the schema fragment

Copy the models from [`prisma/schema.prisma`](./prisma/schema.prisma) into
your application's own `schema.prisma` (they are a fragment — no datasource
or generator blocks — and all models are prefixed `Alfiz` to avoid
collisions), then migrate and generate as usual:

```sh
npx prisma migrate dev
npx prisma generate
```

## 2. Construct the driver

```ts
import { PrismaClient } from "@prisma/client";
import { createApplication } from "@alfiz-auth/application";
import { prismaDriver } from "@alfiz-auth/prisma";

const prisma = new PrismaClient();
const storage = prismaDriver(prisma); // structural match — no adapter needed
const app = createApplication({ storage /* ... */ });
```

## Multi-node deployments: pass an advisory lock

`runExclusive` defaults to an in-process mutex, which serializes graph
writes within one process only. If several nodes share the database, supply
a database advisory lock so two nodes cannot jointly write a graph cycle:

```ts
const storage = prismaDriver(prisma, {
  lock: (key, fn) =>
    prisma.$transaction(async (tx) => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${key}))`;
      return fn();
    }),
});
```

## What lives where

The driver stores and retrieves; it never interprets. All ids are opaque
strings assigned by the Application layer, which also owns graph integrity,
request workflows, catalog versioning, and the audit log. Epoch-ms
timestamps are stored as `BigInt` columns for lossless round-tripping;
optional core fields map to nullable columns (`undefined` ↔ `NULL`).
