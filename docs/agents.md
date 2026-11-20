# Agent accounts

Cocoon can host accounts for automated agents, bound to the person they act
for (their principal) with [ident.link](https://ident.link): the agent's DID
document declares `https://ident.link/agent-of/<principal DID>`, and the
principal's repo holds a `link.ident.endorsement` record keyed by the agent's
DID. Only the pair confirms the relationship.

## Creating them

- **`at.hailey.cocoon.createAgent`** (lexicon in `lexicons/at/hailey/cocoon/`),
  called by the principal with their own session. In one request Cocoon creates
  the account, with the declaration in its genesis PLC operation and an optional
  `recoveryKey` the principal holds offline first in its rotation keys, and
  writes the principal's endorsement. It returns the agent's DID, handle and a
  password, once. The declaration always names the caller, so nobody can make
  an account claiming to be someone else's agent. Only DIDs in
  `COCOON_AGENT_PRINCIPALS` may call it (empty turns it off), each at most
  `COCOON_AGENTS_PER_HOUR` (default 120) times an hour. An OAuth client asks for
  `rpc:at.hailey.cocoon.createAgent?aud=<this PDS's DID>` and
  `repo:link.ident.endorsement`.
- **`cocoon create-agent`**, offline with the PDS stopped: `--agent-of <did>`
  adds the declaration (the principal writes their endorsement themselves).
- **`com.atproto.server.createAccount`** takes `alsoKnownAs` (https URIs, at
  most 8, after the handle) and `recoveryKey` too, for clients that bring their
  own invite code.

## What an agent account can't do

Agent accounts (email under `agents.invalid`) can't call
`com.atproto.identity.*`, however they signed in, so an agent can't add, change
or remove its own declaration; that's its operator's, as the spec recommends.
They can't create agents either.
