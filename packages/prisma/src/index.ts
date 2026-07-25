/**
 * @alfiz/prisma — the Prisma storage driver for the Alfiz Application.
 *
 * Merge `prisma/schema.prisma` (a fragment of `Alfiz`-prefixed models) into
 * your own schema, generate your client, and hand it to `prismaDriver`; the
 * generated client satisfies {@link AlfizPrismaDelegates} structurally, so
 * `@prisma/client` never enters this package's dependency graph. All
 * semantics — ids, graph integrity, workflows, audit — live above the
 * storage seam in @alfiz/application.
 */

export * from "./delegates.js";
export * from "./driver.js";
