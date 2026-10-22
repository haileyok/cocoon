// Generates vectors.json, export.star and export.json from the published
// reference (@atproto/space and @atproto/crypto 0.0.0-spaces-alpha-20261022141228).
//
// To re-run: in an empty directory, write a pnpm-workspace.yaml that overrides
// every @atproto/* package to that version (a bare ^0.0.0-spaces-alpha range
// otherwise resolves to broken 0.0.0 publishes), then
//   pnpm add @atproto/space@V @atproto/crypto@V @atproto/lex-cbor@V @atproto/lex-data@V
//   node gen-vectors.mjs <out dir>
// Signatures, token jtis and KEM key shares are random, so a re-run changes
// those (and only those) values.
import { writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { P256Keypair, Secp256k1Keypair } from '@atproto/crypto'
import { encode } from '@atproto/lex-cbor'
import { parseCid, toBase64 } from '@atproto/lex-data'
import * as space from '@atproto/space'

const out = process.argv[2] ?? '.'
const hex = (b) => Buffer.from(b).toString('hex')
const fromHex = (s) => new Uint8Array(Buffer.from(s, 'hex'))
const assert = (c, m) => {
  if (!c) throw new Error(`assertion failed: ${m}`)
}
const collect = async (gen) => {
  const parts = []
  for await (const p of gen) parts.push(p)
  return Buffer.concat(parts)
}

const now = 1790000000
const SPACE = 'at://did:example:space/space/app.bsky.group/test'
const REPO = 'did:example:alice'
const k256 = await Secp256k1Keypair.import(fromHex('706db12b4b77eed65bdcfa1395368cf36e5e553c4ff58d092d973f0045e2c32c'), { exportable: true })
const p256 = await P256Keypair.import(fromHex('9f3c1a0b5e7d2c4f6a8b0c1d2e3f405162738495a6b7c8d9eaf00112233445566'.slice(0, 64)), { exportable: true })
const kem = await P256Keypair.import(fromHex('2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe'), { exportable: true })

// Set hashes
const lthash = []
for (const ops of [
  [],
  [['+', 'one'], ['+', 'two']],
  [['+', 'two'], ['+', 'one']],
  [['+', 'a']],
  [['-', 'a']],
  [['+', 'a'], ['+', 'a']],
  [['+', 'a'], ['+', 'b'], ['-', 'a']],
  [['+', ''], ['+', 'é/ü/☃']],
  [['+', 'app.bsky.feed.post/3kbcq3p7ad400/bafyreidefdycgbfy3oglcb6ism3eqhyp5llsrpzxjsuac2gsy4mtrtx244']],
]) {
  const h = new space.LtHash()
  for (const [op, el] of ops) (op === '+' ? h.add(el) : h.remove(el))
  lthash.push({ ops, state: hex(h.state()), digest: hex(h.digest()), empty: h.isEmpty() })
}

// Commits and their MACs
const commits = []
for (const records of [
  [],
  [['app.bsky.feed.post', '1', { $type: 'app.bsky.feed.post', text: 'one' }]],
  [
    ['app.bsky.feed.post', '1', { $type: 'app.bsky.feed.post', text: 'one' }],
    ['app.bsky.feed.like', '3kbcq3p7ad400', { $type: 'app.bsky.feed.like', n: 2 }],
  ],
]) {
  const repo = new space.RepoCommit()
  const recs = []
  for (const [collection, rkey, value] of records) {
    const s = await space.serializeRecord(collection, rkey, value)
    repo.add(collection, rkey, s.cid)
    recs.push({ collection, rkey, cid: s.cid.toString() })
  }
  const ctx = { space: SPACE, repo: REPO, rev: '3kbcq3p7ad400' }
  const commit = repo.toCommit(ctx)
  const sharedSecret = fromHex('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f')
  const mac = space.computeCommitMac(sharedSecret, commit)
  assert(space.verifyCommit(commit, { space: SPACE, repo: REPO, sharedSecret, mac }), 'commit mac')
  commits.push({
    ctx,
    records: recs,
    data: hex(commit.data),
    sharedSecret: hex(sharedSecret),
    mac: hex(mac),
    macHeader: space.formatMacHeader(space.COMMIT_MAC_TYPE, mac),
  })
}

// Record MACs
const recordMacs = []
{
  const s = await space.serializeRecord('app.bsky.feed.post', '1', { $type: 'app.bsky.feed.post', text: 'one' })
  const uri = `${SPACE}/${REPO}/app.bsky.feed.post/1`
  const sharedSecret = fromHex('1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100')
  const mac = space.computeRecordMac(sharedSecret, uri, s.cid)
  assert(await space.verifyRecord({ uri, cid: s.cid.toString(), value: { $type: 'app.bsky.feed.post', text: 'one' } }, { uri, sharedSecret, mac }), 'record mac')
  recordMacs.push({ uri, cid: s.cid.toString(), sharedSecret: hex(sharedSecret), mac: hex(mac), macHeader: space.formatMacHeader(space.RECORD_MAC_TYPE, mac) })
}

// KEM: the syncer's encapsulation against the author's #atproto_kem key, and
// the repo host's decapsulation of it.
const kemVectors = []
for (let i = 0; i < 3; i++) {
  const { keyShare, sharedSecret } = await space.encapsulate(kem.did())
  assert(hex(space.decapsulate(kem, keyShare)) === hex(sharedSecret), 'kem')
  kemVectors.push({
    kemPrivateKey: hex(await kem.export()),
    kemKey: kem.did(),
    keyShare,
    sharedSecret: hex(sharedSecret),
    wantMacHeader: space.formatWantMacHeader(space.COMMIT_MAC_TYPE, keyShare),
    wantRecordMacHeader: space.formatWantMacHeader(space.RECORD_MAC_TYPE, keyShare),
  })
}

// HTTP signatures for credential use
const httpsig = []
for (const [authorization, audience] of [
  ['Atproto-Space-Credential credential', 'did:example:repo'],
  ['Atproto-Space-Credential eyJhbGciOiJFUzI1NksifQ.e30.c2ln', 'did:plc:ewvi7nxzyoun6zhxrhs64oiz'],
  ['atproto-space-credential lowercase', 'did:example:repo'],
]) {
  const headers = await space.createSpaceSigHeaders(p256, { authorization, audience })
  await space.verifyCredentialSig(headers, p256.did())
  httpsig.push({ keyDid: p256.did(), headers })
}

// Tokens
const tokens = []
const realNow = Date.now
Date.now = () => now * 1000
for (const [type, opts, key] of [
  ['delegation', { iss: REPO, sub: SPACE, aud: space.spaceHostAud('did:example:space') }, k256],
  ['credential', { iss: 'did:example:space', sub: SPACE, keyId: p256.did() }, k256],
  ['credential', { iss: 'did:example:space', sub: SPACE, keyId: p256.did() }, p256],
  ['clientAttestation', { iss: 'https://app.example.com/client-metadata.json', sub: 'https://app.example.com/client-metadata.json', aud: space.spaceHostAud('did:example:space'), kid: 'key-1' }, p256],
]) {
  const jwt = await space.createSpaceToken(type, opts, key)
  space.parseSpaceToken(type, jwt)
  tokens.push({ type, jwt, signingKey: key.did(), opts })
}
Date.now = realNow

writeFileSync(join(out, 'vectors.json'), JSON.stringify({ now, lthash, commits, recordMacs, kem: kemVectors, httpsig, tokens }, null, 2) + '\n')

// A repo as getRepo serves it, records in path order
const DID = 'did:plc:vlpdsspacesrefexport2345'
const EXPORT_SPACE = `at://${DID}/space/com.example.group/refexport`
const values = [
  ['com.example.spaceNote', '3lzzzzzzzzz23', { $type: 'com.example.spaceNote', text: 'note' }],
  ['com.example.spaceNote', 'longer-record-key-than-the-others', { $type: 'com.example.spaceNote', text: 'long key' }],
  ['com.example.spaceRecord', '3lzzzzzzzzz22', { $type: 'com.example.spaceRecord', n: 1, blob: { $type: 'blob', ref: parseCid('bafkreicolnfocmtylgp4dpek4lw32lxwckiaaaglzedqqgrixrdax7cp6m'), mimeType: 'image/png', size: 44 } }],
  ['com.example.spaceRecord', 'a', { $type: 'com.example.spaceRecord', n: 2 }],
  ['com.example.spaceRecord', 'self', { $type: 'com.example.spaceRecord', n: 3, bytes: new Uint8Array([1, 2, 3]) }],
]
const repo = new space.RepoCommit()
const serialized = []
for (const [collection, rkey, value] of values) {
  const s = await space.serializeRecord(collection, rkey, value)
  repo.add(collection, rkey, s.cid)
  serialized.push(s)
}
const commit = repo.toCommit({ space: EXPORT_SPACE, repo: DID, rev: '3mvzvh4fs222b' })
const { keyShare, sharedSecret } = await space.encapsulate(kem.did())
const mac = space.computeCommitMac(sharedSecret, commit)
const star = await collect(space.serializeRepo(commit, serialized))
const verified = await space.verifyRepoStarFull([star], { space: EXPORT_SPACE, repo: DID, sharedSecret, mac })
assert(verified.records.length === values.length, 'export round trip')
writeFileSync(join(out, 'export.star'), star)
writeFileSync(
  join(out, 'export.json'),
  JSON.stringify(
    {
      generatedBy: 'gen-vectors.mjs: @atproto/space serializeRepo at 0.0.0-spaces-alpha-20261022141228',
      did: DID,
      space: EXPORT_SPACE,
      rev: commit.rev,
      data: hex(commit.data),
      kemPrivateKey: hex(await kem.export()),
      keyShare,
      sharedSecret: hex(sharedSecret),
      macHeader: space.formatMacHeader(space.COMMIT_MAC_TYPE, mac),
      records: serialized.map((s) => ({ collection: s.collection, rkey: s.rkey, cid: s.cid.toString() })),
    },
    null,
    2,
  ) + '\n',
)
console.log('ok')
