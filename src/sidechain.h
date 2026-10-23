// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAIN_H
#define BITCOIN_SIDECHAIN_H

#include <limits>
#include <primitives/transaction.h>
#include <pubkey.h>

#include <array>

// Drivechain's original values, for reference
//static const int SIDECHAIN_VERIFICATION_PERIOD = 26300;
//static const int SIDECHAIN_MIN_WORKSCORE = 13150;
//static const int SIDECHAIN_ACTIVATION_MAX_FAILURES = 201;
//static const int SIDECHAIN_ACTIVATION_PERIOD = 2016;

// The values below apply below the fork height (see further down)

//! Blocks that a withdrawal bundle has to acheieve minimum work score
static const int SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD = 263;
//static const int SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD = 263000; // DC original 6 months 26300

//! The minimum workscore votes for a withdrawal bundle to be paid out.
static const int SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE = 131;
//static const int SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE = 131500; // DC original 3 months 13150;

//! The destination string for the change of a withdrawal bundle
static const std::string SIDECHAIN_WITHDRAWAL_RETURN_DEST = "D";

//! WALLET POLICY, not consensus. The deposit fee the
//! Testchain-template sidechains take out of a deposit's payout
//! (SIDECHAIN_DEPOSIT_FEE in Hivemind's sidechain.h, also 0.00001). The
//! mainchain does not know a sidechain's real fee; a deposit of this much or
//! less can never pay its depositor on such a sidechain (Hivemind: payout
//! <= fee gets no payout output), so the wallet
//! refuses it.
static const CAmount SIDECHAIN_DEPOSIT_FEE = 1000;  // 0.00001 * COIN

//! Maximum serialized size (bytes) of a withdrawal bundle payout transaction.
//! Small-block soft fork: a bundle must fit in a 50 KB block
//! (MAX_SMALL_BLOCK_SERIALIZED_SIZE) alongside the coinbase, so larger
//! bundles could never be paid out and are rejected at ingestion.
static const unsigned int SIDECHAIN_MAX_WITHDRAWAL_BUNDLE_BYTES = 40000;

//! Security fix (resource exhaustion): maximum number of deposits kept in the
//! in-memory deposit cache per sidechain. Deposits are stored in CTIP spend
//! (chronological) order and only the OLDEST are pruned, so the CTIP (the
//! newest deposit, vDepositCache[x].back()) is always retained and CTIP
//! selection is unaffected. The cap is large enough to preserve Undo() for any
//! realistic reorg depth while bounding memory and the per-block deposit sort.
static const size_t SCDB_DEPOSIT_CACHE_MAX = 25000;

//! Max number of failures (blocks without commits) for a sidechain to activate
static const int SIDECHAIN_ACTIVATION_MAX_FAILURES = 2;
//static const int SIDECHAIN_ACTIVATION_MAX_FAILURES = 10070; // DC original 7 days 1007

//! The number of blocks in a sidechain activation period
static const int SIDECHAIN_ACTIVATION_PERIOD = 20;
//static const int SIDECHAIN_ACTIVATION_PERIOD = 20160; // DC original 14 days 2016

//! The number of blocks in a sidechain replacement period
static const int SIDECHAIN_REPLACEMENT_PERIOD = SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE;

// -----------------------------------------------------------------------------
// Which values apply where.
//
// The five constants above are the values the chain has run since launch.
// They stay consensus for every block BELOW
// Consensus::Params::SidechainParamsHeight (the fork height, 1,976,112 on
// mainnet) and are still used directly by display code. At and above that
// height the values come from the chain parameters of each network
// (chainparams.cpp). CONSENSUS CODE MUST USE THE GetSidechain*() accessors,
// never the bare constants, so the value is chosen by the block's height.
//
// Mainnet from the fork height:
//
//     withdrawal minimum work score  129,600 blocks (~90 days at 60 s)
//     withdrawal verification period 259,200 blocks (~180 days)
//     slot replacement               129,600 blocks (= the work score)
//     activation                     2,016 blocks, at most 201 failures
//                                    (~90 %, about 1.4 days at 60 s)
//
// SidechainWithdrawalState's nBlocksLeft and nWorkScore are 32-bit from the
// fork height so that windows this long can be expressed; below it the
// former 16-bit encoding is kept, byte for byte.
//
// The *_PROD constants below are Drivechain's original block counts, chosen
// for a 600-second spacing. Regtest uses them; mainnet and testnet set their
// own windows in chainparams.cpp.
//
// Below the fork height (unchanged since launch):
//
//     withdrawal minimum work score  131 blocks
//     withdrawal verification period 263 blocks
//     slot replacement               131 blocks
//     activation                     20 blocks, at most 2 failures
// -----------------------------------------------------------------------------
static const int SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD_PROD = 26300; // Drivechain block count (regtest)
static const int SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE_PROD = 13150;       // Drivechain block count (regtest)
static const int SIDECHAIN_ACTIVATION_MAX_FAILURES_PROD = 201;          // ~90% over 2016 blocks (BIP300); mainnet + regtest
static const int SIDECHAIN_ACTIVATION_PERIOD_PROD = 2016;               // Drivechain block count (mainnet + regtest)

//! Height-gated accessors. nHeight = height of the block whose rules apply.
//! Return the *_PROD value at/after Consensus::Params::SidechainParamsHeight,
//! the legacy testing value below it.
int GetSidechainWithdrawalVerificationPeriod(int nHeight);
int GetSidechainMinWorkScore(int nHeight);
int GetSidechainActivationMaxFailures(int nHeight);
int GetSidechainActivationPeriod(int nHeight);
//! Replacement period == withdrawal min workscore (unchanged rule).
int GetSidechainReplacementPeriod(int nHeight);

//! The number of sidechain SLOTS: the SCDB layout, every vote vector and the
//! per-block record are sized by this. Do not shrink it to limit activations;
//! that is what the next constant is for.
static const int SIDECHAIN_ACTIVATION_MAX_ACTIVE = 256;

//! The most sidechains that may be ACTIVE at once from SmallBlockHeight.
//! Every active slot costs every block a fixed share of the 50,000-byte cap
//! (SCDB update bytes, a withdrawal-hash commitment, a BMM request and its
//! commitment): ~393 committed bytes a slot when all of it fires, and the
//! reference miner reserves 112 more. At 32 slots the machinery takes a
//! quarter of the block, at ~77 the miner has no room left, at ~110 consensus
//! itself is full. 64 keeps a payout of a 36,681-byte bundle possible beside
//! the reserves and leaves the miner's ceiling unreached. Enforced on the
//! activation COMMITMENT (a coinbase may not commit to activating an inactive
//! slot that would take the count past this), so an over-limit activation
//! is a rejected block, never a silently divergent state; belt and braces at
//! the activation step itself. Lowering later is a soft fork; raising is a
//! hard fork.
static const unsigned int SIDECHAIN_SMALL_BLOCK_MAX_ACTIVE = 64;

//! The most withdrawal bundles one sidechain slot may have
//! pending at once, from SidechainParamsHeight. CONSENSUS.
//!
//! Before the fork the 263-block window bounded the table by expiry (~131
//! never-upvoted entries). The production windows remove that bound: any miner
//! may commit one arbitrary 32-byte bundle hash per active slot per block, and
//! a never-upvoted bundle then lives 129,600 blocks on mainnet - so a single
//! slot could reach ~129,600 entries, every one of them hashed into the SCDB
//! commitment and written into the per-block record every block (~5-10 MB per
//! block per slot), and every entry past vote index 65,279 could never be
//! upvoted (ParseSCDBBytes reads a uint16 with two sentinels).
//!
//! WHY 32. Honest use needs one or two: a Testchain-template sidechain keeps a
//! single bundle in flight and waits before re-proposing after a failure, and
//! the score rules let only one bundle per slot gain work at a time (an upvote
//! for one is a downvote for every other), so at most one can pay out per
//! window. 32 gives 16x headroom over that, keeps every index far below the
//! uint16 sentinels, and bounds the table at 32 x 41 = 1,312 bytes per active
//! slot per block in the record and the commitment pre-image (84 KB per block
//! at the 64-slot maximum).
//!
//! WHAT HAPPENS AT THE CAP: EVICTION, NOT REFUSAL. A new bundle for a full slot
//! displaces the pending bundle with the lowest work score (ties: the fewest
//! blocks left, i.e. the oldest; then the lowest index). The displaced bundle
//! is NOT recorded failed, so it may be proposed again. A bundle that has
//! already reached the payout threshold is never displaced; a block that
//! would need to displace one (every pending bundle of the slot payout-ready -
//! impossible under the score rules for any cap above 1) is invalid, and the
//! miner never builds it. Refusing the new bundle instead was the first design
//! and was rejected: a slot filled to the cap would refuse every honest bundle,
//! and keeping it filled costs one coinbase output per 129,600/32 = 4,050
//! blocks, so any miner with ~0.03% of the hashrate could freeze a sidechain's
//! withdrawals indefinitely. Under eviction the attacker's own never-upvoted
//! bundles are the weakest entries and are displaced first, while a bundle the
//! honest miners upvote outranks all of them.
//!
//! Lowering it later is a soft fork; raising it is a hard fork.
static const unsigned int SIDECHAIN_WITHDRAWAL_MAX_PENDING = 32;

//! The largest title plus description a
//! sidechain proposal commitment may carry, enforced by consensus from
//! SmallBlockHeight (the fork). Before it there was no limit at all
//! (script.cpp, IsSidechainProposalCommit: "should we have a max size?"),
//! while from the fork a proposal lives up to 201 failures instead of 2 and is
//! copied into every SCDB record - about 1.5 GB a day of records at 10 % of
//! the hashrate. 2,000 bytes is exactly what the reference miner already
//! refuses to commit (SIDECHAIN_PROPOSAL_MAX_COMMIT_BYTES, miner.h), so no
//! block the reference miner builds can break it. Only the parsed fields are
//! kept in SCDB, so capping them bounds what every record stores.
static const size_t SIDECHAIN_PROPOSAL_MAX_TEXT_BYTES = 2000;

//! The current sidechain version
static const int SIDECHAIN_VERSION_CURRENT = 0;

//! The max supported sidechain version
static const int SIDECHAIN_VERSION_MAX = 0;

//! The key for sidechain block data in ldb
static const char DB_SIDECHAIN_BLOCK_OP = 'S';

//! The key for sidechain block data stored in the compact (sparse) form, which
//! holds only the ACTIVE sidechain slots instead of the full 256-slot table.
//! Deliberately a distinct key: a binary without the re-expansion logic in
//! SidechainDB::ApplyLDBData finds no record under the legacy key and fails
//! ResyncSCDB loudly (forcing a reindex) rather than silently mis-reading a
//! short vector as the complete sidechain table.
static const char DB_SIDECHAIN_BLOCK_OP_SPARSE = 'V';

//! The key for a sparse record that additionally carries the treasury log and
//! the failed-withdrawal records, so that the treasury pointer is restorable
//! from the block it belongs to instead of only from the shutdown-written
//! deposit cache.
//!
//! A third key rather than a version byte inside the record, for the same
//! reason the sparse form got its own: the extra fields are appended to the
//! serialisation, so a binary that does not know to read them would stop early
//! and silently accept a record it only partly understood. Under its own key it
//! finds nothing, and fails loudly into a reindex.
static const char DB_SIDECHAIN_BLOCK_OP_TREASURY = 'W';

//! The key for a treasury record whose vSpent field is actually populated.
//!
//! vSpent has been in this serialisation since the beginning and nothing ever
//! wrote it, so every record up to and including the treasury key stores it as
//! an empty vector. That matters because the spent-withdrawal map is consensus
//! state - HaveSpentWithdrawal gates AddWithdrawal, one line above the failed
//! check that the treasury key exists to restore, and GetConsensusSections
//! hashes it as "spentwithdrawals" - yet its only copy was withdrawal.dat,
//! which carries no block stamp and no staleness check at all.
//!
//! The layout is byte-identical to the treasury form: this key adds no field,
//! it only promises that the field already there means something. A separate
//! key rather than a flag inside the record because an empty vSpent is
//! legitimate - most blocks spend no withdrawal - so nothing in the record's
//! contents can distinguish "populated and empty" from "never written", and
//! restoring from the latter would clear a map that was correctly loaded.
//! Downgrading finds no record under this key and fails loudly into a reindex,
//! which is the same trade the two keys above already make.
static const char DB_SIDECHAIN_BLOCK_OP_SPENT = 'X';

//! Record key for the WIDENED withdrawal-state format (uint32 nBlocksLeft /
//! nWorkScore). A superset of the spent key: it promises everything 'X' does,
//! plus that vWithdrawalStatus was written in the wide form.
//!
//! The key IS the format discriminator, which is the same mechanism the
//! treasury log used, and it is what keeps every record any earlier build ever
//! wrote readable: those carry 'S'/'V'/'W'/'X' and are parsed through
//! SidechainWithdrawalStateLegacy, byte for byte as before. Without a new key
//! the widened struct would misparse all of them.
static const char DB_SIDECHAIN_BLOCK_OP_WIDE = 'Y';

//! Record keys for the DELTA form: identical in layout to 'X' and 'Y'
//! respectively, except that vFailed and vSpent carry only THIS BLOCK'S
//! failures and spends rather than the entire cumulative set.
//!
//! WHY THIS EXISTS. Every record under 'S'/'V'/'W'/'X'/'Y' is a self-contained
//! snapshot, and two of the sections it snapshots grow monotonically with the
//! chain: mapFailedWithdrawal and mapSpentWithdrawal. Writing the whole of each
//! into every block makes the database QUADRATIC in chain length; the delta
//! form stores only what each block changed.
//!
//! A record under a CUMULATIVE key still means "the whole set as of this
//! block", so it doubles as the ANCHOR a delta chain is reconstructed from. No
//! new key was needed for anchors, and every database any earlier build wrote
//! stays readable and keeps its exact meaning.
//!
//! Both dimensions get a key, deliberately. 'Z' is the narrow sibling of 'X'
//! and '[' the wide sibling of 'Y', so setting SidechainParamsHeight later
//! cannot silently drop the delta form and reintroduce the quadratic growth -
//! which is exactly what adding only the narrow key would have done.
//! How often a CUMULATIVE (anchor) record is written instead of a delta.
//!
//! NODE-LOCAL POLICY, NOT CONSENSUS. Nothing on the wire and no block commits
//! to the record, so two nodes may choose different values and still agree
//! about every block. It is a pure trade: the reconstruction walk is bounded by
//! this many records, and the database keeps one full snapshot per this many
//! blocks instead of one per block.
//!
//! The anchors themselves each carry the whole set; keeping one per this many
//! blocks keeps any historical block cheap to restore.
static const int SCDB_RECORD_ANCHOR_INTERVAL = 100;

static const char DB_SIDECHAIN_BLOCK_OP_DELTA = 'Z';
static const char DB_SIDECHAIN_BLOCK_OP_DELTA_WIDE = '[';

//! The SidechainDB update script version
static const uint8_t SCDB_BYTES_VERSION = 0;
static const uint8_t SCDB_BYTES_MAX_VERSION = 0;

// Custom characters for withdrawal bundle votes
static const char SCDB_UPVOTE = 'u';
static const char SCDB_DOWNVOTE = 'd';
static const char SCDB_ABSTAIN = 'a';

struct Sidechain {
    bool fActive;
    uint8_t nSidechain;
    int32_t nVersion = SIDECHAIN_VERSION_CURRENT;
    std::string title;
    std::string description;
    uint256 hashID1;
    uint160 hashID2;

    Sidechain()
    {
        fActive = false;
        nSidechain = 0;
        nVersion = SIDECHAIN_VERSION_CURRENT;
        title = "";
        description = "";
        hashID1.SetNull();
        hashID2.SetNull();
    }

    bool operator==(const Sidechain& s) const;
    std::string GetSidechainName() const;
    std::string ToString() const;
    uint256 GetSerHash() const;

    // Sidechain proposal script functions
    bool DeserializeFromProposalScript(const CScript& script);
    CScript GetProposalScript() const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(fActive);
        READWRITE(nSidechain);
        READWRITE(nVersion);
        READWRITE(title);
        READWRITE(description);
        READWRITE(hashID1);
        READWRITE(hashID2);
    }

    // This is the same as normal serialization but without fActive
    template <typename Stream>
    inline void SerializeProposal(Stream& s) {
        s << nSidechain;
        s << nVersion;
        s << title;
        s << description;
        s << hashID1;
        s << hashID2;
    }

    // This is the same as normal serialization but without fActive
    template <typename Stream>
    inline void DeserializeProposal(Stream& s) {
        s >> nSidechain;
        s >> nVersion;
        // Security fix (memory-exhaustion): the payload is attacker-controlled
        // coinbase OP_RETURN data. The default std::string reader does
        // resize(ReadCompactSize(s)) with no bound, so a 5-byte length prefix
        // could claim up to MAX_SIZE (32 MB) and force a large transient
        // allocation before operator>> underflows. Bound each varstr by the
        // bytes actually REMAINING in the stream (s.size()) before resize().
        // This is consensus-neutral: any length that exceeds the remaining
        // bytes was already an underflow that threw std::ios_base::failure, so
        // no presently-valid proposal changes outcome - only the wasted
        // allocation is removed. An over-claim now throws before allocating,
        // and DeserializeFromProposalScript catches the throw.
        uint64_t nTitleSize = ReadCompactSize(s);
        if (nTitleSize > s.size())
            throw std::ios_base::failure("sidechain proposal title too large");
        title.resize(nTitleSize);
        if (nTitleSize)
            s.read((char*)&title[0], nTitleSize);

        uint64_t nDescSize = ReadCompactSize(s);
        if (nDescSize > s.size())
            throw std::ios_base::failure("sidechain proposal description too large");
        description.resize(nDescSize);
        if (nDescSize)
            s.read((char*)&description[0], nDescSize);

        s >> hashID1;
        s >> hashID2;
    }
};

struct SidechainActivationStatus
{
    int nAge;
    int nFail;
    Sidechain proposal;

    uint256 GetSerHash() const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nAge);
        READWRITE(nFail);
        READWRITE(proposal);
    }
};

struct SidechainDeposit {
    uint8_t nSidechain;
    std::string strDest;
    CMutableTransaction tx;
    uint32_t nBurnIndex; // The deposit burn output in the deposit transaction
    uint32_t nTx; // The deposit's transaction number in the block
    uint256 hashBlock;

    bool operator==(const SidechainDeposit& a) const;
    std::string ToString() const;
    uint256 GetSerHash() const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSidechain);
        READWRITE(strDest);
        READWRITE(tx);
        READWRITE(nBurnIndex);
        READWRITE(nTx);
        READWRITE(hashBlock);
    }
};

//! The pre-widening on-the-wire form of SidechainWithdrawalState.
//!
//! EXPLICIT SECOND TYPE, NOT A VERSION BRANCH, and that is deliberate.
//! GetCommitmentHash pins its serialisation version to a frozen constant
//! precisely so that no hashed type branches on version - "it removes the
//! hazard of a future version bump silently moving a consensus hash". Widening
//! the fields by teaching SidechainWithdrawalState to serialise two ways would
//! reverse that decision and hide a consensus format change inside a stream
//! flag. So the two formats are two types, and which one is used is chosen by
//! the record key on disk and by the height in the commitment - both of them
//! places a reader can see.
//!
//! 37 bytes: 1 + 2 + 2 + 32. The widened form is 41.
struct SidechainWithdrawalStateLegacy {
    uint8_t nSidechain;
    uint16_t nBlocksLeft;
    uint16_t nWorkScore;
    uint256 hash;

    uint256 GetSerHash() const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSidechain);
        READWRITE(nBlocksLeft);
        READWRITE(nWorkScore);
        READWRITE(hash);
    }
};

struct SidechainWithdrawalState {
    uint8_t nSidechain;
    // WIDENED FROM uint16_t. The mainnet withdrawal window is 129,600 blocks
    // (3 months at 60s); the uint16_t ceiling is 65,535, so neither the
    // countdown nor the score could hold a production value. Below
    // SidechainParamsHeight the values are the legacy 263/131 and always fit,
    // which is why the narrow form above can still carry every historical
    // record byte for byte.
    uint32_t nBlocksLeft;
    uint32_t nWorkScore;
    uint256 hash;

    uint256 GetSerHash() const;
    bool operator==(const SidechainWithdrawalState& a) const;
    std::string ToString() const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSidechain);
        READWRITE(nBlocksLeft);
        READWRITE(nWorkScore);
        READWRITE(hash);
    }
};

//! Narrow/widen between the two withdrawal-state formats.
//!
//! Narrowing ASSERTS rather than truncating: below SidechainParamsHeight the
//! verification period is 263 and the work score cannot exceed it, so a value
//! that does not fit is a programming error - a wide value being written into a
//! legacy record - and silently truncating it would put a wrong number into a
//! consensus hash. Fail loudly instead.
inline SidechainWithdrawalStateLegacy NarrowWithdrawalState(const SidechainWithdrawalState& s)
{
    assert(s.nBlocksLeft <= std::numeric_limits<uint16_t>::max());
    assert(s.nWorkScore  <= std::numeric_limits<uint16_t>::max());
    SidechainWithdrawalStateLegacy out;
    out.nSidechain = s.nSidechain;
    out.nBlocksLeft = (uint16_t)s.nBlocksLeft;
    out.nWorkScore = (uint16_t)s.nWorkScore;
    out.hash = s.hash;
    return out;
}

inline SidechainWithdrawalState WidenWithdrawalState(const SidechainWithdrawalStateLegacy& s)
{
    SidechainWithdrawalState out;
    out.nSidechain = s.nSidechain;
    out.nBlocksLeft = s.nBlocksLeft;
    out.nWorkScore = s.nWorkScore;
    out.hash = s.hash;
    return out;
}

typedef std::vector<std::vector<SidechainWithdrawalState>> WithdrawalStatusTable;
typedef std::vector<std::vector<SidechainWithdrawalStateLegacy>> WithdrawalStatusTableLegacy;

inline WithdrawalStatusTableLegacy NarrowWithdrawalTable(const WithdrawalStatusTable& in)
{
    WithdrawalStatusTableLegacy out;
    out.reserve(in.size());
    for (const std::vector<SidechainWithdrawalState>& slot : in) {
        std::vector<SidechainWithdrawalStateLegacy> row;
        row.reserve(slot.size());
        for (const SidechainWithdrawalState& st : slot) row.push_back(NarrowWithdrawalState(st));
        out.push_back(row);
    }
    return out;
}

inline WithdrawalStatusTable WidenWithdrawalTable(const WithdrawalStatusTableLegacy& in)
{
    WithdrawalStatusTable out;
    out.reserve(in.size());
    for (const std::vector<SidechainWithdrawalStateLegacy>& slot : in) {
        std::vector<SidechainWithdrawalState> row;
        row.reserve(slot.size());
        for (const SidechainWithdrawalStateLegacy& st : slot) row.push_back(WidenWithdrawalState(st));
        out.push_back(row);
    }
    return out;
}

struct SidechainSpentWithdrawal {
    uint8_t nSidechain;
    uint256 hash;
    uint256 hashBlock;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSidechain);
        READWRITE(hash);
        READWRITE(hashBlock);
    }
};

struct SidechainFailedWithdrawal {
    uint8_t nSidechain;
    uint256 hash;
    //! The height of the block that recorded the failure, or -1 where it is
    //! not known (a failure restored from a record written before the wide
    //! format carried heights - by construction a pre-fork failure).
    //!
    //! DELIBERATELY NOT IN SerializationOp: this struct's own serialisation is
    //! the committed pre-image (GetCommitmentHash), withdrawal.dat and every
    //! narrow record, and all three must stay byte-identical. The wide records
    //! carry the heights in a separate trailing vector (SidechainBlockData).
    //! Only failures at or after SidechainParamsHeight are ever dropped, and
    //! only those are guaranteed to carry a height.
    int32_t nFailHeight = -1;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSidechain);
        READWRITE(hash);
    }
};

struct SidechainCTIP {
    COutPoint out;
    CAmount amount;

    uint256 GetSerHash() const;
    std::string ToString() const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(out);
        READWRITE(amount);
    }
};

/**
 * One sidechain's treasury as of a connected block.
 *
 * The treasury pointer used to live only in SidechainDB::mapCTIP, which is
 * incrementally maintained in memory and written out once, at shutdown. A node
 * that stopped uncleanly therefore came back with the treasury as of its last
 * clean shutdown, and the only safe response was to refuse to start and rebuild
 * from blocks. Recording the pointer against the block it belongs to makes it
 * restorable the same way the withdrawal, activation and sidechain lists
 * already are.
 *
 * nSeq counts treasury movements for this sidechain rather than blocks: it
 * advances only when the pointer actually moves, which gives an ordering over
 * the movements and a record of them. amountPrev is the value the pointer
 * carried before this movement, which makes one step of rollback exact without
 * consulting the deposit cache.
 *
 * nSeq is NODE-LOCAL and must never be treated as consensus or compared between
 * nodes. It counts the movements *this node observed*: a node upgraded partway
 * along the chain starts counting from where it was upgraded, while a node that
 * rebuilt from genesis counts every movement since, so two honest nodes at the
 * same block legitimately hold different sequence numbers. Only the pointer
 * itself - out and amount - is derived from the chain, and only that is what
 * GetConsensusSections hashes. Adding nSeq there would make honest nodes report
 * divergence.
 */
struct SidechainTreasuryEntry {
    uint8_t nSidechain;
    uint32_t nSeq;
    COutPoint out;
    CAmount amount;
    CAmount amountPrev;

    SidechainTreasuryEntry() : nSidechain(0), nSeq(0), amount(0), amountPrev(0) { }

    std::string ToString() const;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nSidechain);
        READWRITE(nSeq);
        READWRITE(out);
        READWRITE(amount);
        READWRITE(amountPrev);
    }
};

/**
 * Base object for sidechain related database entries
 */
struct SidechainObj {
    char sidechainop;

    SidechainObj(void) { }
    virtual ~SidechainObj(void) { }

    uint256 GetSerHash(void) const;
    virtual std::string ToString(void) const;
};

/**
 * SCDB data for a block - database object
 */
struct SidechainBlockData: public SidechainObj {
    std::vector<std::vector<SidechainWithdrawalState>> vWithdrawalStatus;
    std::vector<SidechainSpentWithdrawal> vSpent;
    std::vector<SidechainActivationStatus> vActivationStatus;
    std::vector<Sidechain> vSidechain;

    /**
     * The treasury pointer of every active sidechain as of this block, and the
     * withdrawals recorded failed up to it. Present only in records written
     * under DB_SIDECHAIN_BLOCK_OP_TREASURY or DB_SIDECHAIN_BLOCK_OP_SPENT;
     * older records leave both empty and the treasury is recovered from the
     * deposit cache as before.
     */
    std::vector<SidechainTreasuryEntry> vTreasury;
    std::vector<SidechainFailedWithdrawal> vFailed;

    SidechainBlockData(void) : SidechainObj() { sidechainop = DB_SIDECHAIN_BLOCK_OP; }
    virtual ~SidechainBlockData(void) { }

    //! Whether this record carries the treasury log. Reading it is only valid
    //! after sidechainop has been read, which the serialisation below does
    //! first. The spent form is a superset of the treasury form and carries it
    //! too, so it must answer true here.
    bool HasTreasury() const
    {
        return sidechainop == DB_SIDECHAIN_BLOCK_OP_TREASURY ||
               sidechainop == DB_SIDECHAIN_BLOCK_OP_SPENT ||
               sidechainop == DB_SIDECHAIN_BLOCK_OP_WIDE ||
               sidechainop == DB_SIDECHAIN_BLOCK_OP_DELTA ||
               sidechainop == DB_SIDECHAIN_BLOCK_OP_DELTA_WIDE;
    }

    //! Whether vSpent in this record was written rather than left empty by a
    //! build that never populated it. Same validity rule as HasTreasury.
    bool HasSpent() const
    {
        return sidechainop == DB_SIDECHAIN_BLOCK_OP_SPENT ||
               sidechainop == DB_SIDECHAIN_BLOCK_OP_WIDE ||
               sidechainop == DB_SIDECHAIN_BLOCK_OP_DELTA ||
               sidechainop == DB_SIDECHAIN_BLOCK_OP_DELTA_WIDE;
    }

    //! Whether this record can serve as the BASE of a delta reconstruction -
    //! i.e. whether it states BOTH the failed and the spent set in full.
    //!
    //! NOT the same as "is not a delta": five keys are not deltas, but 'S' and
    //! 'V' carry no vTreasury/vFailed section at all and 'W' carries vFailed
    //! with a vSpent that nothing ever populated. Stopping a reconstruction walk
    //! on one of those and then clearing both maps EMPTIES consensus state that
    //! AddWithdrawal gates on, behind no flag day.
    //!
    //! Only 'X' and 'Y' qualify, which is exactly HasSpent() minus the deltas.
    bool IsFailedSpentAnchor() const
    {
        return HasSpent() && !HasFailedSpentDelta();
    }

    //! Whether vFailed and vSpent in this record are a PER-BLOCK DELTA rather
    //! than the cumulative set. A record for which this is false is an ANCHOR:
    //! it states both sets in full as of its block, and a reconstruction walk
    //! stops there.
    //!
    //! Note the asymmetry with HasSpent(): a delta record DOES carry vSpent, so
    //! HasSpent() is true for it - what changes is the MEANING of the bytes,
    //! not their presence. Read this before deciding what to do with them.
    bool HasFailedSpentDelta() const
    {
        return sidechainop == DB_SIDECHAIN_BLOCK_OP_DELTA ||
               sidechainop == DB_SIDECHAIN_BLOCK_OP_DELTA_WIDE;
    }

    //! Whether vWithdrawalStatus in this record is the WIDE (uint32) form.
    //! Same validity rule as HasTreasury: only meaningful once sidechainop has
    //! been read, which the serialisation below does first.
    bool HasWideWithdrawalState() const
    {
        return sidechainop == DB_SIDECHAIN_BLOCK_OP_WIDE ||
               sidechainop == DB_SIDECHAIN_BLOCK_OP_DELTA_WIDE;
    }

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(sidechainop);
        // The KEY chooses the withdrawal-state format. Records written by any
        // build before the widening carry S/V/W/X and are read through the
        // legacy 37-byte form, byte for byte as they were written; only the new
        // Y key carries the 41-byte wide form. This is why no existing
        // blocks/sidechain database has to be rebuilt.
        if (HasWideWithdrawalState()) {
            READWRITE(vWithdrawalStatus);
        } else if (ser_action.ForRead()) {
            WithdrawalStatusTableLegacy legacy;
            READWRITE(legacy);
            vWithdrawalStatus = WidenWithdrawalTable(legacy);
        } else {
            WithdrawalStatusTableLegacy legacy = NarrowWithdrawalTable(vWithdrawalStatus);
            READWRITE(legacy);
        }
        READWRITE(vSpent);
        READWRITE(vActivationStatus);
        READWRITE(vSidechain);
        // Appended fields, read back only for the keys that promise them.
        // sidechainop is deserialised above, so this branch sees the stored
        // value on the way in and the writer's choice on the way out. The
        // spent key carries these as well - it adds no field of its own, only
        // the promise that vSpent above was written.
        if (HasTreasury()) {
            READWRITE(vTreasury);
            READWRITE(vFailed);
        }
        // The failure height of every vFailed entry, in the
        // same order, appended for the WIDE keys only. The wide keys are only
        // ever written at or after SidechainParamsHeight, which no mainnet node
        // has reached, so no existing mainnet record changes meaning. A wide
        // record without this field fails to read - deliberately: startup resync then fails ("Failed to
        // initialize SCDB") and the node does not start until it is restarted
        // once with -reindex (the GUI offers it), instead of restoring
        // failures with unknown heights that this release could not prune.
        if (HasWideWithdrawalState()) {
            std::vector<int32_t> vFailHeight;
            if (!ser_action.ForRead()) {
                vFailHeight.reserve(vFailed.size());
                for (const SidechainFailedWithdrawal& f : vFailed)
                    vFailHeight.push_back(f.nFailHeight);
            }
            READWRITE(vFailHeight);
            if (ser_action.ForRead()) {
                if (vFailHeight.size() != vFailed.size())
                    throw std::ios_base::failure("SidechainBlockData: failure heights do not match the failed set");
                for (size_t i = 0; i < vFailed.size(); i++)
                    vFailed[i].nFailHeight = vFailHeight[i];
            }
        }
    }

    std::string ToString(void) const;
    uint256 GetSerHash() const;
};

bool ParseDepositAddress(const std::string& strAddressIn, std::string& strAddressOut, unsigned int& nSidechainOut);

/** WALLET POLICY. Whether the destination part of a deposit
 *  address (what ParseDepositAddress returns) can be an address on ANY
 *  sidechain in use: Base58Check with a valid checksum and a payload of 21
 *  or 22 bytes (one or two version bytes + a 20-byte hash - Hivemind and the
 *  Testchain template; a 33/34-byte WIF private key is refused),
 *  bech32 with a valid checksum (any HRP), or "0x" plus 40 hex digits
 *  (Ethereum-style accounts). False means certainly
 *  unpayable on every sidechain format this release knows. The mainchain
 *  cannot know which network's version bytes or HRP the target sidechain
 *  uses, so a well-formed address of the WRONG network passes this check;
 *  the sidechain then records the deposit without paying it (Hivemind does this)
 *  and its coins stay in the escrow. */
bool IsPlausibleSidechainDestination(const std::string& strDest);

/** WALLET POLICY. Empty when a deposit of nAmount to strDest may be
 *  sent; otherwise the reason it is refused. fAllowUnknownFormat skips the
 *  destination-format check (for a sidechain whose address format this
 *  release does not know); the amount check has no override. */
std::string DepositPolicyError(CAmount nAmount, const std::string& strDest, bool fAllowUnknownFormat = false);

#endif // BITCOIN_SIDECHAIN_H
