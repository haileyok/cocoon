// Generates vectors.json, export.star, export.json, meta.star and meta.json
// from the published reference (@atproto/space and @atproto/crypto
// 0.0.0-spaces-alpha-20261112204144).
//
// To re-run: in an empty directory, write a pnpm-workspace.yaml that overrides
// every @atproto/* package to that version (a bare ^0.0.0-spaces-alpha range
// otherwise resolves to broken 0.0.0 publishes), then
//   npm install @atproto/space@V @atproto/crypto@V @atproto/lex-cbor@V @atproto/lex-data@V @atproto/star@V @atproto/syntax@V
//   (with the same overrides in package.json's "overrides")
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

const KEY_SHARE = 'did:key:zDnaExample'
const headerObj = (h) => Object.fromEntries(Object.entries(h))
const request = (profile, keyShare) => {
  const header = space.formatMacRequest(profile, keyShare)
  return { header, parsed: space.parseMacRequest(header, profile) }
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
  const req = request(space.COMMIT_MAC_PROFILE, KEY_SHARE)
  const { headers } = space.createCommitMacHeaders(commit, { ...req.parsed, sharedSecret })
  space.verifyCommit(commit, { space: SPACE, repo: REPO, keyShare: KEY_SHARE, sharedSecret, headers: new Headers(headers) })
  commits.push({
    ctx,
    records: recs,
    data: hex(commit.data),
    sharedSecret: hex(sharedSecret),
    keyShare: KEY_SHARE,
    acceptSignature: req.header,
    headers: headerObj(headers),
  })
}

// Record MACs
const recordMacs = []
{
  const s = await space.serializeRecord('app.bsky.feed.post', '1', { $type: 'app.bsky.feed.post', text: 'one' })
  const uri = `${SPACE}/${REPO}/app.bsky.feed.post/1`
  const sharedSecret = fromHex('1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100')
  const req = request(space.RECORD_MAC_PROFILE, KEY_SHARE)
  const { headers } = space.createRecordMacHeaders(uri, s.cid, { ...req.parsed, sharedSecret })
  await space.verifyRecord(
    { uri, cid: s.cid.toString(), value: { $type: 'app.bsky.feed.post', text: 'one' } },
    { uri, keyShare: KEY_SHARE, sharedSecret, headers: new Headers(headers) },
  )
  recordMacs.push({ uri, cid: s.cid.toString(), sharedSecret: hex(sharedSecret), keyShare: KEY_SHARE, acceptSignature: req.header, headers: headerObj(headers) })
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
    acceptCommitSignature: space.formatMacRequest(space.COMMIT_MAC_PROFILE, keyShare),
    acceptRecordSignature: space.formatMacRequest(space.RECORD_MAC_PROFILE, keyShare),
  })
}

// HTTP signatures for credential use
const httpsig = []
for (const [authorization, audience] of [
  ['Atproto-Space-Credential credential', 'did:example:repo'],
  ['Atproto-Space-Credential eyJhbGciOiJFUzI1NksifQ.e30.c2ln', 'did:plc:ewvi7nxzyoun6zhxrhs64oiz'],
  ['atproto-space-credential lowercase', 'did:example:repo'],
]) {
  const { headers } = await space.createSpaceSigHeaders({ authorization, audience, keypair: p256 })
  await space.verifyCredentialSig(headers, p256.did())
  httpsig.push({ keyDid: p256.did(), headers })
}

// Tokens
const tokens = []
const realNow = Date.now
Date.now = () => now * 1000
for (const [type, make, key] of [
  ['delegation', (k) => space.createDelegationToken({ iss: REPO, sub: SPACE, aud: space.spaceHostAud('did:example:space'), keypair: k }), k256],
  ['credential', (k) => space.createSpaceCredential({ iss: 'did:example:space', sub: SPACE, keyId: p256.did(), keypair: k }), k256],
  ['credential', (k) => space.createSpaceCredential({ iss: 'did:example:space', sub: SPACE, keyId: p256.did(), keypair: k }), p256],
  ['clientAttestation', (k) => space.createClientAttestation({ clientId: 'https://app.example.com/client-metadata.json', aud: space.spaceHostAud('did:example:space'), kid: 'key-1', keypair: k }), p256],
]) {
  const jwt = await make(key)
  const parsed = space.parseSpaceToken(type, jwt)
  tokens.push({ type, jwt, signingKey: key.did(), payload: parsed.payload, header: parsed.header })
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
const req = request(space.COMMIT_MAC_PROFILE, keyShare)
const { headers: exportHeaders } = space.createCommitMacHeaders(commit, { ...req.parsed, sharedSecret })
const star = await collect(space.writeRepoStar(commit, serialized))
const verified = await space.verifyRepoStarFull([star], { space: EXPORT_SPACE, repo: DID, keyShare, sharedSecret, headers: new Headers(exportHeaders) })
assert(verified.records.length === values.length, 'export round trip')
writeFileSync(join(out, 'export.star'), star)
writeFileSync(
  join(out, 'export.json'),
  JSON.stringify(
    {
      generatedBy: 'gen-vectors.mjs: @atproto/space writeRepoStar at 0.0.0-spaces-alpha-20261112204144',
      did: DID,
      space: EXPORT_SPACE,
      rev: commit.rev,
      data: hex(commit.data),
      kemPrivateKey: hex(await kem.export()),
      keyShare,
      sharedSecret: hex(sharedSecret),
      acceptSignature: req.header,
      headers: headerObj(exportHeaders),
      records: serialized.map((s) => ({ collection: s.collection, rkey: s.rkey, cid: s.cid.toString() })),
    },
    null,
    2,
  ) + '\n',
)

// A space meta archive as exportSpaceMeta serves it
const META_SPACE = `at://${DID}/space/com.example.group/refmeta`
const metaArchive = {
  space: META_SPACE,
  policy: { $type: 'com.atproto.memberspace.policy', publicRead: false, publicWrite: false, publishPolicy: true, publishMembers: false },
  policyState: [
    { key: 'com.atproto.memberspace.member/did:plc:bbbbbbbbbbbbbbbbbbbbbbbb', value: { $type: 'com.atproto.memberspace.member', read: true, write: false } },
    { key: 'com.atproto.memberspace.member/did:plc:aaaaaaaaaaaaaaaaaaaaaaaa', value: { $type: 'com.atproto.memberspace.member', read: true, write: true } },
  ],
  writers: [
    { did: 'did:plc:bbbbbbbbbbbbbbbbbbbbbbbb', repoRev: '3mvzvh4fs222b', data: new Uint8Array(32).fill(7), spaceRev: '3mvzvh4fs222c' },
    { did: 'did:plc:aaaaaaaaaaaaaaaaaaaaaaaa', repoRev: '3mvzvh4fs2223', data: new Uint8Array(32).fill(9), spaceRev: '3mvzvh4fs2224' },
  ],
}
const metaStar = await collect(space.writeSpaceMetaStar(metaArchive))
const readBack = await space.readSpaceMetaStar([metaStar])
assert(readBack.writers.length === 2 && readBack.policyState.length === 2, 'meta round trip')
writeFileSync(join(out, 'meta.star'), metaStar)
writeFileSync(
  join(out, 'meta.json'),
  JSON.stringify(
    {
      generatedBy: 'gen-vectors.mjs: @atproto/space writeSpaceMetaStar at 0.0.0-spaces-alpha-20261112204144',
      space: META_SPACE,
      policy: metaArchive.policy,
      policyState: readBack.policyState,
      writers: readBack.writers.map((w) => ({ did: w.did, repoRev: w.repoRev, data: hex(w.data), spaceRev: w.spaceRev })),
    },
    null,
    2,
  ) + '\n',
)
console.log('ok')
