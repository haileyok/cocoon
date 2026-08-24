import assert from 'node:assert/strict'
import path from 'node:path'
import { pathToFileURL } from 'node:url'

const atprotoRoot = process.env.ATPROTO_ROOT
if (!atprotoRoot) throw new Error('ATPROTO_ROOT is required')
const base = process.env.COCOON_INTEROP_URL ?? 'http://127.0.0.1:18080'
const password = 'interop-pass'

const { Client } = await import(
  pathToFileURL(path.join(atprotoRoot, 'packages/lex/lex/dist/index.js')).href,
)
const { com } = await import(
  pathToFileURL(path.join(atprotoRoot, 'packages/pds/dist/lexicons/index.js')).href,
)

const defs = com.atproto.simplespace.defs

async function session(handle) {
  const client = new Client({ service: base })
  const result = await client.call(com.atproto.server.createSession, {
    identifier: handle,
    password,
  })
  return {
    did: result.did,
    client,
    headers: { authorization: `Bearer ${result.accessJwt}` },
  }
}

async function expectRejected(label, fn) {
  try {
    await fn()
  } catch {
    return
  }
  throw new Error(`${label} unexpectedly succeeded`)
}

const alice = await session('alice.pds.test')
const bob = await session('bob.pds.test')
const collection = 'com.example.spaceRecord'
const type = 'com.example.forum'

const createdSpace = await alice.client.call(
  com.atproto.simplespace.createSpace,
  {
    type,
    skey: 'interop',
    policy: defs.memberListPolicy.build({}),
    appAccess: defs.open.build({}),
  },
  { headers: alice.headers },
)
const space = createdSpace.uri
assert.equal(space, `at://${alice.did}/space/${type}/interop`)

await alice.client.call(
  com.atproto.simplespace.addMember,
  { space, did: bob.did },
  { headers: alice.headers },
)

const config = await alice.client.call(
  com.atproto.simplespace.getSpace,
  { space },
  { headers: alice.headers },
)
assert.equal(config.uri, space)
assert.equal(config.policy.$type, 'com.atproto.simplespace.defs#memberListPolicy')

const record = {
  $type: collection,
  text: 'reference client through Cocoon',
  createdAt: new Date().toISOString(),
}
const created = await alice.client.call(
  com.atproto.space.createRecord,
  { space, repo: alice.did, collection, record },
  { headers: alice.headers },
)
const rkey = created.uri.split('/').at(-1)
assert.ok(rkey)

const got = await alice.client.call(
  com.atproto.space.getRecord,
  { space, repo: alice.did, collection, rkey },
  { headers: alice.headers },
)
assert.equal(got.cid, created.cid)
assert.equal(got.value.text, record.text)

const listed = await alice.client.call(
  com.atproto.space.listRecords,
  { space, repo: alice.did, limit: 100 },
  { headers: alice.headers },
)
assert.equal(listed.records.length, 1)
assert.equal(listed.records[0].collection, collection)
assert.equal(listed.records[0].rkey, rkey)
assert.equal(listed.records[0].cid, created.cid)
assert.equal('uri' in listed.records[0], false)

const latest = await alice.client.call(
  com.atproto.space.getLatestCommit,
  { space, repo: alice.did },
  { headers: alice.headers },
)
assert.equal(latest.commit.rev.length > 0, true)

const repoCar = await alice.client.call(
  com.atproto.space.getRepo,
  { space, repo: alice.did },
  { headers: alice.headers },
)
assert.ok(repoCar instanceof Uint8Array)
assert.ok(repoCar.length > 0)

const beforeDelete = await alice.client.call(
  com.atproto.space.listRepoOps,
  { space, repo: alice.did, limit: 100 },
  { headers: alice.headers },
)
assert.equal(beforeDelete.ops.length, 1)
assert.equal(beforeDelete.ops[0].cid, created.cid)
assert.equal(beforeDelete.ops[0].prev, null)

await alice.client.call(
  com.atproto.space.deleteRecord,
  { space, repo: alice.did, collection, rkey },
  { headers: alice.headers },
)

const afterDelete = await alice.client.call(
  com.atproto.space.listRepoOps,
  { space, repo: alice.did, limit: 100 },
  { headers: alice.headers },
)
assert.equal(afterDelete.ops.length, 2)
assert.equal(afterDelete.ops[1].cid, null)
assert.equal(afterDelete.ops[1].prev, created.cid)

const page = await alice.client.call(
  com.atproto.space.listRepoOps,
  { space, repo: alice.did, limit: 1 },
  { headers: alice.headers },
)
assert.ok(page.cursor)
assert.match(page.cursor, /^[^/]+\/[0-9]+$/)

const discovered = await alice.client.call(
  com.atproto.space.listSpaces,
  {},
  { headers: alice.headers },
)
assert.ok(discovered.spaces.some((item) => item.uri === space))

await expectRejected('non-owner SimpleSpace metadata access', () =>
  bob.client.call(com.atproto.simplespace.getSpace, { space }, { headers: bob.headers }),
)
await expectRejected('non-owner member-list access', () =>
  bob.client.call(com.atproto.simplespace.listMembers, { space }, { headers: bob.headers }),
)

console.log(
  JSON.stringify({
    ok: true,
    scenarios: [
      'createSpace',
      'addMember',
      'getSpace',
      'createRecord',
      'getRecord',
      'listRecords',
      'getLatestCommit',
      'getRepo',
      'listRepoOps',
      'deleteRecord',
      'listSpaces',
      'owner/read_self authorization',
    ],
  }),
)
