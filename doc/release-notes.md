(note: this is a temporary file, to be added-to by anybody, and moved to
release-notes at release time)

Bitcoin Core version *version* is now available from:

  <https://bitcoincore.org/bin/bitcoin-core-*version*/>

This is a new major version release, including new features, various bugfixes
and performance improvements, as well as updated translations.

Please report bugs using the issue tracker at GitHub:

  <https://github.com/bitcoin/bitcoin/issues>

To receive security and update notifications, please subscribe to:

  <https://bitcoincore.org/en/list/announcements/join/>

How to Upgrade
==============

If you are running an older version, shut it down. Wait until it has completely
shut down (which might take a few minutes for older versions), then run the
installer (on Windows) or just copy over `/Applications/Bitcoin-Qt` (on Mac)
or `bitcoind`/`bitcoin-qt` (on Linux).

The first time you run version 0.15.0, your chainstate database will be converted to a
new format, which will take anywhere from a few minutes to half an hour,
depending on the speed of your machine.

Note that the block database format also changed in version 0.8.0 and there is no
automatic upgrade code from before version 0.8 to version 0.15.0. Upgrading
directly from 0.7.x and earlier without redownloading the blockchain is not supported.
However, as usual, old wallet versions are still supported.

Downgrading warning
-------------------

The chainstate database for this release is not compatible with previous
releases, so if you run 0.15 and then decide to switch back to any
older version, you will need to run the old release with the `-reindex-chainstate`
option to rebuild the chainstate data structures in the old format.

If your node has pruning enabled, this will entail re-downloading and
processing the entire blockchain.

Compatibility
==============

Bitcoin Core is extensively tested on multiple operating systems using
the Linux kernel, macOS 10.8+, and Windows Vista and later. Windows XP is not supported.

Bitcoin Core should also work on most other Unix-like systems but is not
frequently tested on them.

Notable changes
===============

Drivechain (BIP300/BIP301): what this hard fork implements, and where it deliberately differs
---------------------------------------------------------------------------------------------

Skydoge implements BIP300 (hashrate escrows) roughly as the specification read on
2023-07-13 (bitcoin/bips e7eba116) and BIP301 (blind merged mining) as it read in
2021/2022. The specification has changed since, mostly so that drivechain can be
deployed on an unmodified Bitcoin Core as a soft fork. This chain has the rules
natively and activates them by a height-gated hard fork, so most of those changes
buy nothing here. The differences below are **deliberate**; please do not "fix"
them from the current text of the BIPs.

Kept on purpose:

- **Sidechain activation needs about 90 % of blocks, not 50 %.** An unused slot
  activates when a proposal fails to get an acknowledgement in fewer than 201 of
  2016 blocks (`SIDECHAIN_ACTIVATION_MAX_FAILURES_PROD`). BIP300 master lowered
  this to 50 % in 2024. A bare majority must not be able to install a sidechain
  on this chain.
- **Taking over an active slot needs about 99.8 % of blocks for about 90 days.**
  A replacement proposal must reach the replacement period (the withdrawal
  minimum work score, 129,600 blocks after the fork) with the same 201-failure
  limit as a fresh activation. BIP300 master uses 50 % over 26,300 blocks. Ours
  is far stricter and protects the occupants of active slots; it is a
  deliberate choice, not an oversight.
- **OP_DRIVECHAIN is not used in its 2023 soft-fork form.** The treasury script
  stays the two-byte `0xb4 <slot>` form, a consensus rule from height 1. The
  four-byte `0xb4 <push1 n> OP_TRUE` form exists only so that legacy nodes
  accept it in a soft fork; changing it would move every treasury.
- **The BMM request format is kept**: critical data in the extended
  transaction serialisation with a 4-byte previous-block tail, and the accept
  `OP_RETURN D1617368 <h*>` without a slot byte. Sidechains (Hivemind, Thunder)
  and bidders build exactly this.
- **M4 (withdrawal votes) numbering is kept.** Version 0 is two bytes per
  sidechain that has bundles; an upvote index is written little-endian,
  abstain is the byte pair `FF FF` and downvote/alarm is the byte pair `FF FE`.
  BIP300 master renumbered the versions (its version 0 means "repeat the
  previous M4"); renumbering here would change the meaning of every historical
  M4. Miner and validator agree on this encoding.

New consensus rules at the fork height (`EscrowRulesHeight`, with the other
fork gates):

- **A withdrawal payout (M6) whose fee output carries value is invalid**
  (`bad-withdrawal-fee-value`). The second output of an M6 encodes the
  mainchain fee and must itself be zero-value, as BIP300 has said since
  its 2023-07-26 revision (bips 796c80eb). Its value used to be burnt from the
  treasury. `receivewithdrawalbundle` refuses such a bundle as policy.
- **A sidechain slot whose treasury holds coins cannot be taken over.** A
  replacement proposal for an active slot is refused at activation while the
  slot's treasury (CTIP) holds coins; previously activation erased the
  treasury pointer and stranded every coin in it. A slot with an empty
  treasury, or none, can still be replaced under the strict rule above.

Confirmed, unchanged: a deposit (M5) with more than one treasury output, and a
withdrawal payout with a treasury output beyond the change return, were already
invalid (`bad-sidechain-deposit`; BIP300 badaf013).

Credits
=======

Thanks to everyone who directly contributed to this release:


As well as everyone that helped translating on [Transifex](https://www.transifex.com/projects/p/bitcoin/).
