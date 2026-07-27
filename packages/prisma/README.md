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
const storage = prismaDriver(prisma); // structural match — no adapter, no cast
const app = createApplication({ storage /* ... */ });
```

That no-cast promise is pinned in CI by a compile-only fixture
(`src/prisma-client-shape.ts`) replicating the exact input types
`prisma generate` emits — Json inputs that reject bare `null`,
`bigint | number` scalars, Prisma-style optional properties — so a
delegate-surface change that would force `as unknown as
AlfizPrismaDelegates` on adopters fails this package's own build instead.
The match holds under `exactOptionalPropertyTypes` too.

## The invalidation log (AlfizEpoch / AlfizEvent)

The fragment includes two models backing the Application's
`events: { persist: true }` option — the persisted invalidation log that
lets clients on OTHER processes revalidate their caches with one
single-row read (`AlfizEpoch`) instead of waiting out a TTL. They are
additive: merge them and `prisma migrate dev` as usual; the epoch row is
lazily created on first append, no seed required. A client generated
WITHOUT them still satisfies the driver interface — the driver then omits
the optional event methods and `events.persist` refuses at construction.

## Multi-node deployments: pass an advisory lock

`runExclusive` defaults to an in-process mutex, which serializes graph
writes within one process only. If several nodes share the database, supply
a database advisory lock so two nodes cannot jointly write a graph cycle —
and, with event persistence on, so two nodes cannot interleave sequence
allocation in the invalidation log (event appends serialize under the same
lock, key `alfiz:events`):

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
