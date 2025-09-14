# Cocoon

> [!WARNING]
You should not use this PDS. You should not rely on this code as a reference for a PDS implementation. You should not trust this code. Using this PDS implementation may result in data loss, corruption, etc.

Cocoon is a PDS implementation in Go. It is highly experimental, and is not ready for any production use.

## Implemented Endpoints

> [!NOTE]
Just because something is implemented doesn't mean it is finished. Tons of these are returning bad errors, don't do validation properly, etc. I'll make a "second pass" checklist at some point to do all of that.

### Identity

- [ ] `com.atproto.identity.getRecommendedDidCredentials`
- [ ] `com.atproto.identity.requestPlcOperationSignature`
- [x] `com.atproto.identity.resolveHandle`
- [ ] `com.atproto.identity.signPlcOperation`
- [ ] `com.atproto.identity.submitPlcOperation`
- [x] `com.atproto.identity.updateHandle`

### Repo

- [x] `com.atproto.repo.applyWrites`
- [x] `com.atproto.repo.createRecord`
- [x] `com.atproto.repo.putRecord`
- [x] `com.atproto.repo.deleteRecord`
- [x] `com.atproto.repo.describeRepo`
- [x] `com.atproto.repo.getRecord`
- [x] `com.atproto.repo.importRepo` (Works "okay". You still have to handle PLC operations on your own when migrating. Use with extreme caution.)
- [x] `com.atproto.repo.listRecords`
- [ ] `com.atproto.repo.listMissingBlobs`

### Server

- [x] `com.atproto.server.activateAccount`
- [x] `com.atproto.server.checkAccountStatus`
- [x] `com.atproto.server.confirmEmail`
- [x] `com.atproto.server.createAccount`
- [x] `com.atproto.server.createInviteCode`
- [x] `com.atproto.server.createInviteCodes`
- [x] `com.atproto.server.deactivateAccount`
- [ ] `com.atproto.server.deleteAccount`
- [x] `com.atproto.server.deleteSession`
- [x] `com.atproto.server.describeServer`
- [ ] `com.atproto.server.getAccountInviteCodes`
- [ ] `com.atproto.server.getServiceAuth`
- ~~[ ] `com.atproto.server.listAppPasswords`~~ - not going to add app passwords
- [x] `com.atproto.server.refreshSession`
- [ ] `com.atproto.server.requestAccountDelete`
- [x] `com.atproto.server.requestEmailConfirmation`
- [x] `com.atproto.server.requestEmailUpdate`
- [x] `com.atproto.server.requestPasswordReset`
- [ ] `com.atproto.server.reserveSigningKey`
- [x] `com.atproto.server.resetPassword`
- ~~[] `com.atproto.server.revokeAppPassword`~~ - not going to add app passwords
- [x] `com.atproto.server.updateEmail`

### Sync

- [x] `com.atproto.sync.getBlob`
- [x] `com.atproto.sync.getBlocks`
- [x] `com.atproto.sync.getLatestCommit`
- [x] `com.atproto.sync.getRecord`
- [x] `com.atproto.sync.getRepoStatus`
- [x] `com.atproto.sync.getRepo`
- [x] `com.atproto.sync.listBlobs`
- [x] `com.atproto.sync.listRepos`
- ~~[ ] `com.atproto.sync.notifyOfUpdate`~~ - BGS doesn't even have this implemented lol
- [x] `com.atproto.sync.requestCrawl`
- [x] `com.atproto.sync.subscribeRepos`

### Other

- [ ] `com.atproto.label.queryLabels`
- [x] `com.atproto.moderation.createReport` (Note: this should be handled by proxying, not actually implemented in the PDS)
- [x] `app.bsky.actor.getPreferences`
- [x] `app.bsky.actor.putPreferences`

## License

This project is licensed under MIT license. `server/static/pico.css` is also licensed under MIT license, available at [https://github.com/picocss/pico/](https://github.com/picocss/pico/).
