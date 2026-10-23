# Skydoge 0.45.3b

## THIS RELEASE IS A HARD FORK AT MAINNET BLOCK 1,976,112

**0.45.3b changes the consensus rules from mainnet block 1,976,112** (expected
around 2026-10-31 UTC at ~62 seconds per block; the height decides, not the
date). From that block, a node running 0.44.08 or any older release follows a
different chain from a node running 0.45.3b, permanently. **Every node, pool,
exchange, explorer and service must be on 0.45.3b before block 1,976,112.**
Below that height 0.45.3b accepts and rejects exactly what 0.44.08 did, with
one recorded exception that no mainnet block has ever exercised (see *Known
issues*).

The release files are named `mainchain-0.45.3-*`. 0.45.3b supersedes 0.45.1
and 0.45.2: **they do not have the same rules from block 1,976,112**, so a node
or pool left on either of them can follow a different chain from that block.
A second gate, the treasury anchor, activates later, at block 1,980,144.

**Pools that build their own coinbase** must copy the SCDB commitment output
from `getblocktemplate` into it, and keep the template's required drivechain
transactions in the block, in the template's order. Otherwise their blocks are
invalid from the fork height (`bad-scdb-commitment-missing`,
`bad-scdb-commitment`). See *What pools and solo miners must do*, below.

**Blocks hold at most 50,000 bytes from the fork.** A transaction larger than
that can never be mined after block 1,976,112, whatever its fee. Large
consolidations (hundreds of inputs) must be split into smaller transactions,
or sent before the fork.

### Verifying the download

`SHA256SUMS` is signed (`SHA256SUMS.asc`) with the Skydoge Release Signing Key:

    915D 0BAA 47E6 056B 5E02  FDAE 2DE1 360A 2AE8 EC88

The public key is `contrib/gitian-keys/skydoge-release-key.asc` in the source
tree; compare its fingerprint with the one published at https://skydoge.net.

```sh
gpg --import skydoge-release-key.asc
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing
```

The builds are reproducible with Gitian (`contrib/gitian-descriptors`).

### The fork gates

Five consensus gates activate together at 1,976,112 on mainnet:

| gate | what changes from block 1,976,112 |
| --- | --- |
| `SmallBlockHeight` | blocks may be at most 50,000 serialized bytes (`bad-blk-size`); relay and wallet limits move with it (below) |
| `TimewarpGuardHeight` | the timewarp guard on block timestamps |
| `SidechainParamsHeight` | production sidechain windows (withdrawal: 129,600-block minimum work score, 259,200-block verification period); at most 32 pending withdrawal bundles per sidechain; failed bundles are forgotten after 518,400 blocks; the boundary sweep at this exact height |
| `SCDBCommitmentHeight` | every coinbase must carry exactly one SCDB state commitment computed by the node (`bad-scdb-commitment-missing`, `bad-scdb-commitment`) |
| `EscrowRulesHeight` | a withdrawal payout's fee output must be zero-value; a sidechain slot whose treasury holds coins cannot be taken over |

A sixth gate, `CTIPAnchorHeight`, activates **4,032 blocks later, at
1,980,144** (about 2026-11-02): from that block every sidechain treasury
pointer is anchored to the unspent output set. It is later on purpose: by then
the SCDB commitment has shown, block by block, that every upgraded node
carries the same treasury pointers.

### What pools and solo miners must do before block 1,976,112

Upgrading the node is **not enough** for a pool.

1. **Upgrade every node** that builds or validates blocks to 0.45.3b.
2. **Build the coinbase the way the node gives it to you.** From 1,976,112
   every coinbase must carry the sidechain state commitment the node computes.
   Pool software that builds its own coinbase from `coinbasevalue` (stock
   yiimp, node-stratum-pool, ckpool) produces blocks that are rejected with
   `bad-scdb-commitment-missing`. Take the coinbase from `coinbasetxn` in
   `getblocktemplate`, change only the scriptSig (at most 100 bytes) and the
   payout output's script, and keep every other output byte for byte. Copying
   `default_witness_commitment` alone is not enough.

   A block over 50,000 bytes is refused (`bad-blk-size`). The 50,000 is the
   block's COMMITTED size, not its wire size: every version-3 transaction is
   charged 56 bytes for its critical-data span, up to 21 more than it takes on
   the wire. A pool that keeps the template's transaction list as it is needs
   nothing else. A pool that drops or adds transactions must keep
   80 + compactsize(count) + coinbase size + the sum of each transaction's
   `chargedsize` <= `committedsizelimit` (both in `getblocktemplate`, with
   `v3txcharge`); filling to `sizelimit` by wire bytes can build a block every
   upgraded node rejects. No existing field changed.

   From 1,976,112 `getblocktemplate` also marks every transaction the SCDB
   commitment depends on with `"required": true` - a sidechain deposit, a BMM
   request, the BMM fee transaction that spends it, and any spend of a
   sidechain treasury coin - and no longer lists `transactions` in `mutable`.
   **Never drop a required transaction, and never add a sidechain transaction
   the template did not offer**: such a block is rejected
   (`bad-scdb-commitment`). Ordinary transactions may still be dropped.
   `getblocktemplate` in proposal mode checks the commitment as well, so a
   pool can test a block it built before mining on it. From the same height a
   coinbase BMM (critical hash) commitment whose transaction is not in the
   block makes the block invalid (`bad-critical-commit-unmatched`): never keep
   the template's commitment outputs while dropping a BMM request.
3. **Set `-bmmfeescript` to the pool's own address.** The BMM fee transaction
   in a template collects the sidechains' BMM bids and pays them to an
   anyone-can-spend script (`OP_TRUE`) unless the node is started with
   `-bmmfeescript=<address or script hex>` (P2PKH, P2SH, P2WPKH or P2WSH).
   The option changes only what this node builds; the blocks are valid for
   every node.
4. **Remove `activatesidechains=1`** (or `-activatesidechains`) from
   `skydoge.conf` and from the command line. It makes the miner acknowledge
   every pending sidechain proposal, including one built to take over a
   sidechain slot. 0.45.3b refuses the setting on mainnet: the node stops at
   startup with an error that points to `acksidechainproposal`.
5. **To support a specific sidechain proposal, name it:**
   `acksidechainproposal=<proposalhash>`, one line per proposal, with the hash
   published by the project (for Hivemind: on skydoge.net, signed). Take the
   `proposalhash` from `skydoge-cli getsidechainactivationstatus <slot>`.
   `listhashsidechain` prints hashes byte-reversed, and a reversed hash
   acknowledges nothing; the node logs a warning when a configured hash names
   no pending proposal, and `skydoge-cli listsidechainproposalacks` shows what
   each value matches (`pending`, `active`, `reversed`, `nomatch`). **Remove
   the line once that sidechain is active.** The miner never acknowledges a
   proposal identical to the sidechain its slot already runs.
6. **Test your pool before the fork.** Ask the project for the test-network
   details and mine at least one block there through your real pool stack,
   then send the project its hash. It is the only way to know your coinbase is
   accepted.
7. **Keep your cached withdrawal bundles and votes across the `-reindex`.**
   0.45.3b keeps them when its own files describe them. If the node was last
   run by 0.45.0 or 0.45.1, first start 0.45.3b once WITHOUT `-reindex` and
   stop it, so that `withdrawal.dat` and `customvotes.dat` are rewritten; then
   do the `-reindex`. Either way, beforehand save `skydoge-cli
   listcachedwithdrawaltx <slot> true` (the hash and hex of every cached
   bundle) and `skydoge-cli listwithdrawalvotes` for each sidechain, and
   compare afterwards; re-submit a missing bundle with `skydoge-cli
   receivewithdrawalbundle <slot> <hex>` and set a missing vote again with
   `setwithdrawalvote`. **Do not reindex with 0.45.1 or 0.45.0.**

### What everyone else must do

* **Upgrade before block 1,976,112, then start the node once with
  `-reindex`** (a node that holds sidechain withdrawal bundles: pool step 7
  first) - a FULL `-reindex`, not `-reindex-chainstate`. A node whose
  sidechain database lost a treasury pointer under an older release computes
  a different SCDB commitment from the fork height and leaves the chain, and
  that loss cannot be seen from the node's own files. The rebuild replays
  every block from disk: do it well before the height.
* **Going back to 0.44.08 needs `-reindex` too.** From its first block,
  0.45.3b writes sidechain records in a format 0.44.08 cannot read.
* **A node still on 0.44.08 at the fork height does not necessarily stop
  there.** It keeps following the upgraded chain, with wrong sidechain state,
  until the first block the two rule sets judge differently. Until then it
  looks healthy. Exchanges and services must upgrade before the height and
  must not credit deposits seen only by an old node.
* **A late upgrade needs a full `-reindex`.** 0.45.3b refuses to start on a
  data directory that 0.44.08 or older ran past the fork height, and says so.
  **A data directory that 0.45.0, 0.45.1 or 0.45.2 ran past the fork height is
  NOT detected:** run the full `-reindex` yourself. In short: if the node ran
  past block 1,976,112 before the upgrade, start 0.45.3b once with
  `-reindex`, whatever the old version was.

### Consensus changes (from block 1,976,112 unless stated)

* **Blocks are limited to 50,000 serialized bytes**, and the timewarp guard
  applies to block timestamps.
* **Every coinbase carries the SCDB state commitment** (see the pool section).
* **Production sidechain windows:** a withdrawal needs a 129,600-block
  (about three months) minimum work score, with a 259,200-block verification
  period. The withdrawal work-score fields are widened to 32 bits so such a
  window can be expressed; records already on disk are read unchanged.
* **At most 64 active sidechains.** A proposal that would take the active
  count past 64 never activates.
* **A sidechain proposal may carry at most 2,000 bytes** of title plus
  description (`bad-sidechain-proposal-size`).
* **At most 32 withdrawal bundles may be pending per sidechain.** A new one
  displaces the pending bundle with the lowest work score (ties: the oldest);
  a bundle that has reached the payout threshold is never displaced, and a
  displaced bundle is not recorded as failed and may be proposed again.
* **A failed withdrawal bundle is forgotten 518,400 blocks (about a year)
  after it failed** (failures at or after the fork height only).
* **The boundary sweep.** Crossing the fork height raises the withdrawal
  threshold, which expires every bundle still in flight; at the fork block
  only, those bundles leave without being recorded failed, so they can be
  proposed again under the new rules.
* **BIP300 escrow rules:** a withdrawal payout whose fee output carries value
  is invalid (`bad-withdrawal-fee-value`), and a sidechain slot whose treasury
  holds coins cannot be taken over. See `doc/release-notes.md`, "Drivechain
  (BIP300/BIP301)", for these and for the differences from current BIP300
  that are kept on purpose.
* **A zero-value escrow output is invalid in a block**
  (`bad-sidechain-zero-value-escrow`).
* **Treasury spends are tightened:** the withdrawal-return destination is
  reserved to withdrawals, a withdrawal's amounts are checked against the
  treasury coin it spends, a withdrawal may not leave a zero-value treasury
  change, and a deposit into a slot that holds a treasury pointer must chain
  from it.
* **BMM requests are judged against the block's own parent**, and a coinbase
  BMM commitment must have its transaction in the block.
* **A sidechain proposal that is already pending, or identical to the active
  sidechain in its slot, is not tracked a second time.**
* **From block 1,980,144, every treasury pointer is anchored to the unspent
  output set.** A block is refused only when the block itself spent the coin
  a treasury pointer names; a pointer already broken earlier is logged and
  the block is accepted.

### Transaction size limits move with the small-block fork

From `SmallBlockHeight` (1,976,112 on mainnet):

* a standard transaction may be at most **40,000 serialized bytes**, so a
  transaction at the limit still fits a 50,000-byte block beside the coinbase.
  That is roughly 270 P2PKH inputs; a wallet sweeping more than that should
  split the spend across several transactions. This is relay and wallet
  policy; the consensus limit is the 50,000-byte block;
* a Drivechain `OP_RETURN` output may carry at most **10,000 bytes**;
* the wallet refuses to build a transaction over the limit rather than handing
  back one that can never confirm;
* transactions already in the mempool under the old limits are re-evaluated:
  the block that reaches the fork height drops the oversized ones.

### Policy, RPC and node changes (no consensus change)

* Relay refuses any spend of a treasury coin that is neither a deposit nor a
  withdrawal, and refuses zero-value escrow outputs.
* BMM requests compete on fee plus bid (BIP301's first-price auction per
  block per sidechain); a request that loses one template keeps competing in
  later templates on the same tip.
* The block template only offers a BMM request whose whole cost fits the
  block, and tries a sidechain's next request when the chosen one cannot be
  placed.
* A payout that a reorganisation takes back is rebuilt and paid again by the
  node's miner.
* The miner never pays a withdrawal bundle in the block that expires it, and
  builds its withdrawal votes and payouts against the sidechain state after
  the block's activations (slot replacements).
* `receivewithdrawalbundle` refuses a bundle that could never be paid out (not
  version 2, lock time 0, final sequence).
* `listcachedwithdrawaltx <slot> true` prints each cached bundle's raw hex,
  which `receivewithdrawalbundle <slot> <hex>` takes back.
* A `-reindex` keeps the cached withdrawal bundles and the withdrawal votes
  (0.45.0 and 0.45.1 dropped them).
* `getscdbstate` and `getscdbhash` report `depositcachesound` and
  `treasurylogsound`, and the node logs a warning when a record is written in
  that state.
* `rebuildscdb` verifies a rebuilt database before installing it.
* Several node-local records (removed BMM requests, displaced withdrawal
  bundles) are now bounded, and network messages are checked against their
  size before memory is allocated for them.
* **BIP37 bloom filters are off by default.** `-peerbloomfilters` now defaults
  to off and the `NODE_BLOOM` service bit follows it. **Operators serving SPV
  clients must set `-peerbloomfilters=1`**: a peer that sends `filterload` or
  `filteradd` to a node without `NODE_BLOOM` is banned for 24 hours, as in
  upstream Bitcoin Core.
* A node started with `-checklevel=3` or `-checklevel=4` no longer aborts when
  the coin database is inconsistent; it reports it and offers a reindex.
* `getblocktemplate` works on a regtest node with no peers.
* `libskydogeconsensus` exports its functions again (they were hidden in
  0.45.0-0.45.1, so no program could link against the shared library).
* Security fixes backported from upstream Bitcoin Core.

### Wallet and GUI

**IMPORTANT: "Create New Wallet" and "Restore My Wallet" never backed up your
wallet, and the twelve words they showed are not a backup.** Those entries
opened a BIP39 mnemonic calculator that cannot read or write your wallet. A
phrase saved from that screen restores a *different*, empty wallet. If you
kept those words as your backup, **take a real one today**:

* in the GUI: `File` -> `Backup Wallet…`;
* from the command line: `skydoge-cli backupwallet "/path/to/wallet-backup.dat"`;
* or copy `wallet.dat` out of the data directory with the wallet closed.

The two entries are now called `BIP39 Phrase Generator` and `BIP39 Phrase
Decoder`, under **Crypto Tools**, and the dialog states the warning itself.

Other wallet and GUI changes:

* Scheduled transactions: a schedule missed while the wallet was closed or
  locked is dropped and its coins released, but only once the node has caught
  up with the network; a schedule cancelled by abandoning its transaction no
  longer broadcasts; a schedule survives a crash between broadcast and
  removal; a scheduled transaction fires on its date rather than on every
  matching weekday.
* Abandoning a transaction now abandons its whole descendant chain.
* With several wallets loaded, `createsidechaindeposit`, the OP_RETURN builder
  and the coin-denial path use the calling wallet's own lock and change key.
* The multisig dialogs refuse a redeem script over 520 bytes (at most 15
  compressed keys), which could never be spent.
* A maximized window can be dragged again.
* BIP70 payment requests are removed, together with the protobuf dependency.
  The `bitcoin:` URI scheme and the receive dialog are unaffected.

### Known issues

* **The fork needs the hashrate.** If less than about 90 % of the hashrate
  runs 0.45.3b with a commitment-carrying coinbase at block 1,976,112, the
  chain can split. Pools: please confirm your upgrade with the project.
* **A miner majority can still take a sidechain's escrow.** That is the BIP300
  design (miners vote withdrawals), not a defect; the 129,600-block vote is
  the window in which users can see a bad bundle coming.
* **A displaced withdrawal bundle waits.** Bundles are not relayed between
  nodes: only the node that received a bundle from its sidechain holds it,
  and that node's miner re-proposes it when the table has room. The mainchain
  node a sidechain sends its bundles to must therefore mine, or pass the
  bundle to a pool that does.
* **The sidechain activation period is still 2,016 blocks** on mainnet (about
  1.4 days at this chain's spacing); the ~90 % threshold is unchanged.
* **Below the fork height, 0.45.3b refuses a withdrawal payout whose encoded
  fee total is negative or wraps**, which 0.44.0 accepts (0.44.08 already
  refuses it). No such payout exists in mainnet history.
