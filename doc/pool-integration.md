# Mining pool integration

This is the guide for the release that carries the hard fork at mainnet block
**1,976,112**. Read the release notes first; this document is the practical
part for pool and solo-miner software.

**The one-line version: from block 1,976,112 take the node's coinbase, do not
build your own, and include every transaction the template marks required.**

Before the fork this guide used to say that a block without the sidechain
outputs is still valid. That stops being true at 1,976,112: from that block a
coinbase without the node's sidechain commitment, or with one that is wrong, is
**invalid**, and the block is rejected by every upgraded node.

## Before block 1,976,112

1. Upgrade every node that builds or validates your blocks, then start each
   once with `-reindex` (a full `-reindex`, not `-reindex-chainstate`).
   Plan for the time it takes: a full `-reindex` of mainnet can take from
   minutes on a fast desktop to hours on a small virtual server. The node does not serve templates until it has finished,
   so do it well before block 1,976,112, one node at a time.
2. Remove `activatesidechains=1` from `skydoge.conf` and the command line; the
   node refuses it on mainnet. Acknowledge sidechain proposals by hash instead
   (below).
3. Set `-bmmfeescript=<your address>` (below).
4. Change your coinbase handling as described here.
5. Mine at least one block on the **test network** through your real pool
   stack and send the project its hash. It is the only way to know your
   coinbase is accepted.

## The coinbase

`getblocktemplate` returns the full coinbase in `coinbasetxn.data`. It carries
every commitment the block needs, among them the SCDB state commitment
(`OP_RETURN` with the marker `d8 5c db c0`), BMM commitments for the bids in the
template, withdrawal votes, sidechain proposals and acknowledgements, and the
witness commitment. They exist nowhere else in the template.

Change only:

- the **scriptSig**: keep the block-height push first (BIP34), then your
  extranonce and tag; at most 100 bytes in total (consensus);
- the **payout output's script**: output 0 carries the subsidy and fees and pays
  `OP_TRUE` - anyone can spend it - until you replace the script with yours.

Keep every other output byte for byte and in the same order. Do not rebuild the
coinbase from `coinbasevalue`, and copying `default_witness_commitment` alone is
not enough: stock yiimp, node-stratum-pool and ckpool do exactly that and
produce `bad-scdb-commitment-missing` blocks from the fork.

The block leaves **2,000 bytes** free for outputs a pool adds beside the payout,
for example a split payout (about 58 P2PKH outputs). Add them next to output 0;
never remove, reorder or edit the template's own outputs. The template does not
report this room as a field, so test any such layout on the test network first.

The older fields `NbCoinTxn` and `Modified_Coinbase_txn<i>` are still returned
and list the same outputs as hex scripts, output 0 first. A pool that rebuilds
the coinbase from them must replace output 0 only and copy every other output,
in order; `coinbasetxn` is the safer path because nothing has to be rebuilt.

## The transactions

From block 1,976,112 every template transaction that the SCDB commitment depends
on is marked `"required": true`: sidechain deposits, BMM requests, the BMM fee
transaction that collects their bids, and any spend of a sidechain treasury
coin. `"transactions"` is no longer listed in `mutable`.

- **Include every required transaction, in template order.** Dropping one makes
  the commitment wrong and the block invalid (`bad-scdb-commitment`).
- **Never add a sidechain transaction the template did not offer**, for the same
  reason. Dropping or adding ordinary transactions is still allowed.
- A coinbase BMM commitment whose transaction is not in the block makes the
  block invalid (`bad-critical-commit-unmatched`): never keep the template's
  commitment outputs while dropping a BMM request.
- Blocks are limited to **50,000 committed bytes**. A pool that keeps the
  template's transaction list as it is needs nothing else. A pool that drops or
  adds transactions must keep
  `80 + compactsize(count) + coinbase size + sum(chargedsize) <= committedsizelimit`,
  using the `chargedsize` of each transaction and `committedsizelimit` from the
  template (`v3txcharge` explains the charge for version-3 transactions).
  Filling to `sizelimit` by wire bytes can build a block every node rejects.
- If you change the transaction list, recompute the witness commitment as
  upstream does. Changing only the scriptSig or the payout script does not
  affect it.

## The BMM fee transaction and `-bmmfeescript`

Sidechains pay miners for blind merged mining with bids inside their BMM
requests. The template collects them in one BMM fee transaction, which is
required and pays `OP_TRUE` - whoever spends it first takes the bids - unless
the node is started with:

    -bmmfeescript=<address or scriptPubKey hex>

(P2PKH, P2SH, P2WPKH or P2WSH; anything else stops the node at startup.) The
pool cannot rewrite that output itself: the fee transaction comes before the
witness commitment, so changing it breaks the block. Set the option on every
node that serves templates. It changes only what that node builds.

## Refreshing templates

The node keeps a template for about 5 seconds, and longpoll wakes on a new tip,
not on a new BMM bid. A pool that only longpolls never includes bids that
arrive between blocks. Request a fresh template at least every few seconds and
on every new tip.

## Testing a block before mining on it

    skydoge-cli getblocktemplate '{"mode": "proposal", "data": "<block hex>"}'

returns `null` for a block the node would accept, or the reject reason. From
this release it also checks the SCDB commitment (`bad-scdb-commitment`,
`bad-scdb-commitment-missing`), so a pool can catch a wrong coinbase before it
spends hashrate on it.

## Sidechain proposals

    acksidechainproposal=<proposalhash>       (one line per proposal, in skydoge.conf)

acknowledges exactly the proposals you name. Take the hash from
`skydoge-cli getsidechainactivationstatus <slot>`, not from `listhashsidechain`
(which prints hashes byte-reversed). `skydoge-cli listsidechainproposalacks`
shows what each configured value matches (`pending`, `active`, `reversed`,
`nomatch`), and the node logs a warning while a configured hash names no pending
proposal. A proposal needs about 90 % of blocks over 2,016 blocks to activate,
and at most 64 sidechains can be active.

## Withdrawal votes

    skydoge-cli setwithdrawalvote upvote   <nsidechain> [<bundle hash>]
    skydoge-cli setwithdrawalvote downvote <nsidechain> [<bundle hash>]
    skydoge-cli setwithdrawalvote abstain  <nsidechain>

The default is abstain. From the fork a mainnet withdrawal bundle needs a work
score of 129,600 within a 259,200-block verification period, and at most 32
bundles can be pending per sidechain. Voting is a judgement about whether a
withdrawal is legitimate, and it is the pool's to make; naming the bundle hash
votes for that bundle only.

## Checking that it works

- `skydoge-cli listwithdrawalstatus <nsidechain>`: `nblocksleft` falls by one per
  block; `nworkscore` rises by one for each block mined while upvoting. If
  `nblocksleft` falls and `nworkscore` does not, the commitments are not reaching
  the chain.
- `skydoge-cli getsidechaindbinfo` and `skydoge-cli getscdbhash` report what the
  node believes about every slot.
- On the test network: the block you send the project must be accepted by the
  project's nodes.

## Notes

- The number of coinbase outputs changes from block to block. Never assume a
  count.
- The field names above are specific to this implementation and are not part of
  any BIP.
