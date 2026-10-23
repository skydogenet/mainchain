// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SIDECHAINDB_H
#define BITCOIN_SIDECHAINDB_H

#include <deque>
#include <map>
#include <memory> // Required for forward declaration of CTransactionRef typedef
#include <set>
#include <vector>

#include <amount.h>
#include <uint256.h>

class CCriticalData;
class COutPoint;
class CScript;
class CTransaction;
typedef std::shared_ptr<const CTransaction> CTransactionRef;
class CMutableTransaction;
class CTxOut;
class uint256;

struct Sidechain;
struct SidechainActivationStatus;
struct SidechainBlockData;
struct SidechainCTIP;
struct SidechainDeposit;
struct SidechainWithdrawalState;
struct SidechainSpentWithdrawal;
struct SidechainFailedWithdrawal;
struct SidechainTreasuryEntry;

//! The frozen encoding of SidechainDB::GetCommitmentHash().
//!
//! CONSENSUS FROM SCDBCommitmentHeight. Every byte below is part of the
//! committed pre-image. Renaming a tag, reordering a section, adding or
//! dropping one, or changing any hashed struct's SerializationOp changes every
//! commitment and forks the chain. The "sections may be renamed or resplit
//! freely" licence in the GetConsensusSections() comment applies to
//! GetConsensusSections and DOES NOT extend here. Deliberately different string
//! values from the section names there, so a rename-by-grep cannot reach these.
//!
//! At namespace scope only because C++11 forbids an in-class initialiser for a
//! non-integral static member. They belong to GetCommitmentHash() and to
//! nothing else.
static const int  SCDB_COMMITMENT_SER_VERSION = 0;
static const char* const SCDB_COMMITMENT_DOMAIN = "skydoge/scdb/commitment/1";
static const char* const SCDB_COMMITMENT_TAG_SIDECHAINS = "scdb1/sidechains";
static const char* const SCDB_COMMITMENT_TAG_WITHDRAWALSTATUS = "scdb1/withdrawalstatus";
static const char* const SCDB_COMMITMENT_TAG_ACTIVATIONSTATUS = "scdb1/activationstatus";
static const char* const SCDB_COMMITMENT_TAG_CTIP = "scdb1/ctip";
static const char* const SCDB_COMMITMENT_TAG_FAILED = "scdb1/failedwithdrawals";
static const char* const SCDB_COMMITMENT_TAG_SPENT = "scdb1/spentwithdrawals";

class SidechainDB
{
public:
    SidechainDB();

    void ApplyLDBData(const uint256& hashBlockLastSeen, const SidechainBlockData& data);

    /** Add txid of BMM transaction removed from mempool to cache */
    void AddRemovedBMM(const uint256& hashRemoved);

    /** Add txid of removed sidechain deposit transaction */
    void AddRemovedDeposit(const uint256& hashRemoved);

    /** Add deposit(s) to cache */
    /**
     * Cache deposits and, unless told otherwise, move the treasury pointer to
     * the newest of them.
     *
     * fUpdateCTIP exists for the one caller that must not move the pointer:
     * the startup load of the deposit file, once the treasury has already been
     * restored from the per-block record. That file is written at shutdown, so
     * after an unclean stop it can describe an older block, and letting it
     * redefine the pointer would undo the restore. The deposits themselves are
     * still worth caching there - they are the node's own history.
     */
    bool AddDeposits(const std::vector<SidechainDeposit>& vDeposit, bool fUpdateCTIP = true);

    /**
     * Whether the treasury currently held came from a per-block record rather
     * than from the deposit cache.
     *
     * Also answers for the failed withdrawal map, which ApplyLDBData clears and
     * reinstalls under the same key and from the same record.
     */
    bool HasTreasuryFromRecord() const { return fTreasuryFromRecord; }

    /**
     * Whether the spent withdrawal map currently held came from a per-block
     * record rather than from withdrawal.dat.
     *
     * Separate from the treasury flag because the two keys are not the same
     * promise: a record written under the treasury key serialises vSpent as the
     * empty vector nothing ever filled, and only the spent key says the field
     * means anything. A node whose tip record predates that key still has the
     * file as its only copy of the spent set.
     */
    bool HasSpentFromRecord() const { return fSpentFromRecord; }

    /**
     * Drop a slot's cached deposits, and their transaction ids with them.
     *
     * What happens to a slot when a new sidechain takes it over: the incoming
     * occupant must not inherit the previous one's deposits. Used by
     * UpdateActivationStatus on the connect path, and by a rebuild replaying
     * records, which sees the same handover as a change of occupant between
     * two consecutive records and has to reproduce its effect exactly.
     *
     * The txid filter is shared by every slot, so its entries have to go too
     * or the incoming sidechain could never cache a deposit reusing one of
     * those transactions - which would also defeat a repair that re-scans
     * blocks.
     */
    void ResetSlotDeposits(uint8_t nSidechain);

    /**
     * Whether the deposit cache can actually produce the treasury pointer this
     * database is holding.
     *
     * UpdateCTIP derives the pointer from the newest deposit of a slot, so a
     * slot holding a pointer whose cache is empty - or whose newest deposit
     * names a different output - has a deposit history that does not support
     * it. Since the pointer began arriving from the per-block record, that is
     * reachable without anything being corrupt: the record survives an unclean
     * stop and the deposit file does not, so the pointer can be right while the
     * history behind it is missing or stale.
     *
     * This is what a repair keys on. It says nothing about the pointer being
     * wrong - the record is the better copy - only that the deposits no longer
     * explain it, which is the condition a rebuild from blocks fixes.
     *
     * Slots with no pointer are not examined: a sidechain that has never
     * received a deposit legitimately has neither.
     */
    bool DepositCacheSupportsTreasury(uint8_t& nSlotOut) const;

    /** Add a new withdrawal bundle to SCDB. From SidechainParamsHeight a
     * slot already holding SIDECHAIN_WITHDRAWAL_MAX_PENDING bundles first
     * displaces its weakest bundle that has not reached the payout threshold
     * (see SIDECHAIN_WITHDRAWAL_MAX_PENDING); if none qualifies the bundle is
     * refused. */
    bool AddWithdrawal(uint8_t nSidechain, const uint256& hash, int nHeight, bool fDebug = false);

    /** Whether a block at nHeight may add a new bundle to nSidechain as far as
     * the pending cap is concerned: true below SidechainParamsHeight, below the
     * cap, or when a bundle could be displaced. The miner asks this before it
     * commits a bundle, so it never builds a block AddWithdrawal would refuse
     * for the cap. Reads the state as it is before the block's own update,
     * which is what the miner has; the block's expiries can only make room. */
    bool WithdrawalSlotHasRoom(uint8_t nSidechain, int nHeight) const;

    /** The index in vWithdrawalStatus[nSidechain] of the bundle the cap would
     * displace at nHeight, or -1 if every bundle has reached the payout
     * threshold. Lowest work score, then fewest blocks left, then lowest
     * index. */
    int GetWithdrawalToDisplace(uint8_t nSidechain, int nHeight) const;

    /** True if the update of the block at nHeight expires this bundle (it is
     * removed by RemoveExpiredWithdrawals, which runs at the START of that
     * block's update): no blocks left, or too few left to reach the threshold.
     * The one predicate RemoveExpiredWithdrawals and the miner both use. A
     * payout of a bundle that expires in the same block is checked against the
     * parent state and passes, but that block's update then removes the bundle
     * before it can be marked spent, and the block is invalid (bad-scdb-update)
     * - so the miner must not build one. */
    static bool WithdrawalExpiresAt(const SidechainWithdrawalState& state, int nHeight);


    /** Drop failures recorded at or after SidechainParamsHeight that are at
     * least WithdrawalFailedRetention blocks old at nHeight. Returns how many
     * were dropped. Consensus from SidechainParamsHeight. */
    int PruneFailedWithdrawals(int nHeight);

    /** How many failures the last non-fJustCheck update dropped. ConnectBlock
     * writes a full (anchor) record for such a block, so a delta chain never
     * spans a drop and the record walk needs no knowledge of the rule. */
    int GetFailedPrunedLastUpdate() const { return nFailedPrunedLastUpdate; }

    /** Add spent withdrawals to SCDB */
    void AddSpentWithdrawals(const std::vector<SidechainSpentWithdrawal>& vSpent);

    /** Add failed withdrawals to SCDB without recording which block failed
     * them. Only for records read back from disk that predate the block
     * index; a block being connected must use the overload below so that
     * disconnecting it can take the failure back out again. */
    void AddFailedWithdrawals(const std::vector<SidechainFailedWithdrawal>& vFailed);

    /** Add failed withdrawals to SCDB, remembering the block that failed them */
    void AddFailedWithdrawals(const uint256& hashBlock, const std::vector<SidechainFailedWithdrawal>& vFailed);

    /** Record only which block failed a withdrawal, without changing what SCDB
     * considers failed. For restoring the index from disk, where the failures
     * themselves have already been established. */
    void AddFailedWithdrawalBlocks(const uint256& hashBlock, const std::vector<SidechainFailedWithdrawal>& vFailed);

    /** Remove failed BMM request from cache once it has been abandoned */
    void BMMAbandoned(const uint256& txid);

    /** Add active sidechains to the in-memory cache */
    void CacheSidechains(const std::vector<Sidechain>& vSidechainIn);

    /** Add a users custom vote to the in-memory cache */
    bool CacheCustomVotes(const std::vector<std::string>& vote);

    /** Add SidechainActivationStatus to the in-memory cache */
    void CacheSidechainActivationStatus(const std::vector<SidechainActivationStatus>& vActivationStatusIn);

    /** Add proposed sidechain to the in-memory cache */
    void CacheSidechainProposals(const std::vector<Sidechain>& vSidechainProposalIn);

    /** Add sidechain-to-be-activated hash to cache */
    void CacheSidechainHashToAck(const uint256& u);

    /** Add withdrawal transaction to the in-memory cache */
    bool CacheWithdrawalTx(const CTransaction& tx, const uint8_t nSidechain);

    /** Check SCDB withdrawal verification status */
    bool CheckWorkScore(uint8_t nSidechain, const uint256& hash, int nHeight, bool fDebug = false) const;

    /** Clear out the cached list of removed sidechain deposit transactions */
    void ClearRemovedDeposits();

    /** Return number of active sidechains */
    unsigned int GetActiveSidechainCount() const;

    /** Check if the hash of the sidechain is in our hashes of sidechains to
     * activate cache. Return true if it is, or false if not. */
    bool GetAckSidechain(const uint256& u) const;

    /** Get list of currently active sidechains */
    std::vector<Sidechain> GetActiveSidechains() const;

    /** Get list of all sidechains */
    std::vector<Sidechain> GetSidechains() const;

    /** Get list of BMM txid that miner removed from the mempool. */
    std::set<uint256> GetRemovedBMM() const;

    /** Get list of deposit txid that were removed from the mempool. */
    std::vector<uint256> GetRemovedDeposits() const;

    /** Return the CTIP (critical transaction index pair) for nSidechain */
    bool GetCTIP(uint8_t nSidechain, SidechainCTIP& out) const;

    /** Return the CTIP (critical transaction index pair) for all sidechains */
    std::map<uint8_t, SidechainCTIP> GetCTIP() const;

    /**
     * Return the treasury log entries, for writing into the per-block record.
     * Ordered by slot, because it comes from a std::map keyed by slot - the
     * record must serialise identically for the same state.
     */
    /**
     * What GetTreasuryLog() found wrong with mapTreasury on the way past.
     *
     * All three lists are empty on a healthy database. They exist because the
     * returned vector cannot report any of this: it is built to be correct, so
     * anything reading it sees a clean log whether or not the two maps agreed.
     * A caller that wants to KNOW has to look here - see the definition.
     */
    struct TreasuryLogAudit {
        //! Slots holding a pointer with no log entry at all.
        std::vector<uint8_t> vMissing;
        //! Log entries for slots that hold no pointer. Dropped, not emitted.
        std::vector<uint8_t> vStale;
        //! Log entries whose outpoint or amount disagreed with the pointer.
        //! The pointer wins; the entry's claim is discarded.
        std::vector<uint8_t> vMismatched;

        bool IsClean() const
        {
            return vMissing.empty() && vStale.empty() && vMismatched.empty();
        }
    };

    /**
     * The treasury pointers as a per-block record states them.
     *
     * A PROJECTION OF mapCTIP, not a dump of mapTreasury. Every slot that holds
     * a pointer is stated, its outpoint and amount always come from the pointer
     * itself, and mapTreasury supplies only nSeq and amountPrev - which are
     * node-local metadata that nothing hashes. So a record cannot omit a slot
     * that has a pointer, cannot carry a slot that does not, and cannot state an
     * outpoint or amount the pointer disagrees with.
     *
     * That matters because ApplyLDBData INSTALLS mapCTIP from these entries:
     * a stale or divergent one would become this node's treasury pointer on the
     * next replay. Building from mapCTIP makes all three shapes unrepresentable
     * rather than merely unlikely.
     *
     * pAudit, when given, receives what was wrong with mapTreasury on the way
     * past. Clean on a healthy database, always.
     */
    std::vector<SidechainTreasuryEntry> GetTreasuryLog(TreasuryLogAudit* pAudit = nullptr) const;

    bool GetCachedWithdrawalTx(const uint256& hash, CMutableTransaction& mtx) const;

    /** Return vector of cached custom withdrawal votes */
    std::vector<std::string> GetVotes() const;

    /** Return vector of cached deposits for nSidechain. */
    std::vector<SidechainDeposit> GetDeposits(uint8_t nSidechain) const;

    /** Return the hash of the last block SCDB processed */
    uint256 GetHashBlockLastSeen();

    /** For testing purposes - return the hash of everything that SCDB is
     * tracking. This includes members used for consensus as well as user
     * data like which sidechain(s) they have set votes for and their own
     * sidechain proposals. */
    //! nHeight selects the withdrawal-state width, exactly as it does for
    //! GetCommitmentHash and GetConsensusHash. Diagnostic only, but the value is
    //! compared ACROSS BINARIES in the census, so it must not change form below
    //! the flag day.
    uint256 GetTestHash(int nHeight) const;

    //! Hash of the state that block validity actually depends on.
    //!
    //! Two honest nodes at the same block must produce the same value. It is a
    //! measurement tool: if it differs, this node and that node disagree about
    //! something consensus reads, and one of them will reject a block the other
    //! accepts. GetTestHash() cannot be used for that - it mixes in the deposit
    //! cache and the raw withdrawal transactions, which are node-local and
    //! legitimately differ between honest nodes.
    //!
    //! NOT the consensus serialisation: the coinbase commits to
    //! GetCommitmentHash, which is specified separately.
    //! nHeight selects the withdrawal-state width, exactly as it does for
    //! GetCommitmentHash - see there. This is the CENSUS instrument (operators
    //! compare it across nodes), so it must not silently change form: below
    //! SidechainParamsHeight it is byte-identical to every build back to
    //! 0.44.08, and a mixed network still agrees.
    uint256 GetConsensusHash(int nHeight) const;

    //! One named group of leaves making up the consensus hash.
    struct ConsensusSection {
        std::string name;
        std::vector<uint256> vLeaf;
    };

    //! The leaves of GetConsensusHash(), grouped and in hash order.
    //!
    //! Exists so that a report of the state and the hash of the state cannot
    //! describe different things: GetConsensusHash() is the merkle root of
    //! these sections concatenated in the order returned, and nothing else
    //! builds that leaf set. Adding a field to the hash therefore adds it to
    //! every report of the hash, and the two cannot drift apart.
    void GetConsensusSections(std::vector<ConsensusSection>& vSection, int nHeight) const;

    //! The form of the state that a block's coinbase commits to from
    //! SCDBCommitmentHeight - the leaf order is the hash, and from activation
    //! the serialisation is consensus forever.
    //!
    //! This is GetConsensusHash() minus everything that depends on the
    //! committing block's own hash, which cannot exist yet when the miner
    //! builds the coinbase. Committed as-is, the consensus hash would be
    //! circular twice over: the block section leaf IS the committing block's
    //! hash, and the spent-withdrawal section hashes both the map key (the
    //! hash of the block each spend landed in) and the full entry, whose
    //! hashBlock field repeats it. So this form drops the block section
    //! entirely, and reduces the spent section to the (nSidechain, blind hash)
    //! pairs - exactly what HaveSpentWithdrawal reads - sorted, because map
    //! order was ordered by spending-block hash and would smuggle the
    //! committing block's hash back in through the leaf order.
    //!
    //! The result is invariant under nonce iteration and extranonce rolling,
    //! which is what lets the miner compute it before the block hash exists.
    //!
    //! Deliberately NOT built from GetConsensusSections(): the sections may be
    //! renamed, resplit or extended freely, this form may not. A change here
    //! is a new commitment tag and a second coordinated fork, not a v2.
    //!
    //! The encoding is the SCDB_COMMITMENT_* stream declared at the top of this
    //! header - one tagged, length-prefixed CHashWriter pass, not a merkle root
    //! - and the warning there is the contract. Read it before touching this.
    //!
    //! Deliberate asymmetry with GetConsensusHash() / GetConsensusSections():
    //! this form commits a failed bundle's (nSidechain, hash) pair, which is
    //! what HaveFailedWithdrawal matches on, and deduplicates the spent pairs,
    //! because HaveSpentWithdrawal is a set-membership test. The consensus
    //! sections still hash the raw failed-map key and still keep spent
    //! multiplicity. That is NOT an oversight to "fix": the consensus hash is a
    //! census instrument, and readings recorded by earlier releases (and
    //! comparisons of consensushash across binaries)
    //! must stay comparable to future readings of the same name. No
    //! block carries the consensus hash; every block from SCDBCommitmentHeight
    //! carries this one. The cost of the asymmetry is that two nodes differing
    //! only in a failed entry's slot agree on consensushash and differ on
    //! commitmenthash, which is why the comparison tool must read both.
    //! nHeight is the height of the block this state belongs to, and it
    //! selects the withdrawal-state WIDTH: the legacy 37-byte form below
    //! Consensus::Params::SidechainParamsHeight, the widened 41-byte form at or
    //! after it. The width has to move with the WINDOW VALUES, because those
    //! are what stop fitting in uint16 - so both switch on the same height, and
    //! the commitment below that height is byte-identical to every build back
    //! to 0.44.08.
    //!
    //! Passed rather than read from a global on purpose: this function is the
    //! consensus hash, and a height it took from ambient state would be a
    //! height a reader cannot see at the call site.
    uint256 GetCommitmentHash(int nHeight) const;

    /** Get the sidechain that relates to nSidechain if it exists */
    bool GetSidechain(const uint8_t nSidechain, Sidechain& sidechain) const;

    /** Get sidechain activation status */
    std::vector<SidechainActivationStatus> GetSidechainActivationStatus() const;

    /** The slots whose withdrawal
     *  bundles the activation step of a block at nHeight clears, for a block
     *  that commits to activating vActivationHash. Miner policy only.
     *  ApplyUpdate runs that step BEFORE it parses the M4 vote bytes, so a
     *  replacement that activates in the block takes its slot out of the
     *  state the bytes are read against. Runs the real step on a copy;
     *  *this is not changed. */
    std::set<uint8_t> GetSlotsClearedByActivation(const std::vector<uint256>& vActivationHash, int nHeight) const;

    /** The active slots with a replacement proposal that reaches its period
     *  in a block at nHeight - it activates there unless it fails or the
     *  escrow rule refuses it. A superset of GetSlotsClearedByActivation.
     *  Miner policy only. */
    std::set<uint8_t> GetSlotsWithReplacementDue(int nHeight) const;

    /** Get the name of a sidechain */
    std::string GetSidechainName(uint8_t nSidechain) const;

    /** Get list of this node's uncommitted sidechain proposals */
    std::vector<Sidechain> GetSidechainProposals() const;

    /** Get the scriptPubKey that relates to nSidechain if it exists */
    bool GetSidechainScript(const uint8_t nSidechain, CScript& scriptPubKey) const;

    /** Get list of sidechains that we have set to ACK */
    std::vector<uint256> GetSidechainsToActivate() const;

    /** Get a list of withdrawals spent in a given block */
    std::vector<SidechainSpentWithdrawal> GetSpentWithdrawalsForBlock(const uint256& hashBlock) const;

    /** Get status of nSidechain's withdrawals (public for unit tests) */
    std::vector<SidechainWithdrawalState> GetState(uint8_t nSidechain) const;

    /** Was this bundle displaced from its full slot
     *  (and not back, paid or expired since)? Node-local, miner policy only. */
    bool WasWithdrawalDisplaced(uint8_t nSidechain, const uint256& hash) const;

    /** Does this node's custom vote (setwithdrawalvote) upvote this bundle? */
    bool IsWithdrawalUpvotedHere(uint8_t nSidechain, const uint256& hash) const;

    std::vector<std::vector<SidechainWithdrawalState>> GetState() const;

    /** Return cached but uncommitted withdrawal transaction hash(s) for nSidechain */
    std::vector<uint256> GetUncommittedWithdrawalCache(uint8_t nSidechain) const;

    /** A number that is different whenever the sidechain state a block
     *  template is built from may be different: the cached withdrawal
     *  bundles, the withdrawal status and the spent and failed records, the
     *  withdrawal votes, the sidechain list, the proposals, their activation
     *  status and the acks. getblocktemplate compares it with the number its
     *  cached template was built at, which costs nothing, where hashing that
     *  state cost a serialization and a double SHA256 of every cached bundle
     *  on every call (with cs_main held).
     *
     *  Each value comes from one process-wide sequence and is handed out by a
     *  single change to a single database, and a copy of the database carries
     *  the number with the state it describes (ConnectBlock works on a copy
     *  and installs it, DisconnectBlock and the verification guard put a
     *  saved copy back). So two equal numbers always mean the same state,
     *  whichever object they are read from; two different numbers may mean
     *  the same state, which costs one rebuild and nothing else. Not
     *  serialized and not part of any hash of the database. */
    uint64_t GetTemplateStateSeq() const { return nTemplateStateSeq; }

    /** Return cached withdrawal transaction(s) */
    std::vector<std::pair<uint8_t, CMutableTransaction>> GetWithdrawalTxCache() const;

    /** Return cached spent withdrawals as a vector for dumping to disk */
    std::vector<SidechainSpentWithdrawal> GetSpentWithdrawalCache() const;

    /** Return cached failed withdrawals^ as a vector for dumping to disk */
    std::vector<SidechainFailedWithdrawal> GetFailedWithdrawalCache() const;

    //! This block's failures / spends only - the delta a delta-key record
    //! carries. See the definitions for why nothing extra has to be tracked.
    std::vector<SidechainFailedWithdrawal> GetBlockFailedWithdrawals(const uint256& hashBlock) const;
    std::vector<SidechainSpentWithdrawal> GetBlockSpentWithdrawals(const uint256& hashBlock) const;

    //! Reconstruction primitives. MergeFailedAndSpentWithdrawals MUST be driven
    //! ASCENDING BY HEIGHT - it is last-write-wins, not a commutative union.
    void ClearFailedAndSpentWithdrawals();
    void MergeFailedAndSpentWithdrawals(const SidechainBlockData& data);

    /** Return which block failed each withdrawal, for dumping to disk, so that
     * a reorg across a restart can still undo the failure */
    std::vector<std::pair<uint256, SidechainFailedWithdrawal>> GetFailedWithdrawalBlocks() const;

    /** Is there anything being tracked by the SCDB? */
    bool HasState() const;

    /** Return true if the deposit transaction is cached */
    bool HaveDepositCached(const uint256& txid) const;

    /** Return true if the withdrawal has been spent */
    bool HaveSpentWithdrawal(const uint256& hash, const uint8_t nSidechain) const;

    /** Return true if the withdrawal failed */
    bool HaveFailedWithdrawal(const uint256& hash, const uint8_t nSidechain) const;

    /** Return true if the withdrawal tx is cached */
    bool HaveWithdrawalTxCached(const uint256& hash) const;

    /** Is the raw bundle with this hash cached for this slot? */
    bool HaveWithdrawalTxCachedForSlot(uint8_t nSidechain, const uint256& hash) const;

    /** Check if SCDB is tracking the work score of a withdrawal */
    bool HaveWorkScore(const uint256& hash, uint8_t nSidechain) const;

    /** Whether a block's sidechain proposal would NOT be tracked again: one
     * with the same hash is already pending in vActivationStatus, or it is
     * identical to the sidechain active in its slot. CONSENSUS from the fork
     * (max(EscrowRulesHeight, SCDBCommitmentHeight), validation.cpp's
     * nCTIPRulesHeight) - ApplyUpdate asks it only from there; the block stays
     * valid either way. The miner asks it at every height, so it never spends
     * a coinbase output on a proposal that is pending or already active.
     * Consensus rule from the fork height. */
    bool IsSidechainProposalKnown(const Sidechain& proposal) const;

    /** Check if a sidechain slot number has active sidechain */
    bool IsSidechainActive(uint8_t nSidechain) const;

    /** Remove withdrawals that are too old to pass with their current score.
     * hashBlock is the block being connected: expiring a withdrawal writes a
     * failure record, and the record has to be attributed to a block so that
     * disconnecting that block can remove it again. */
    void RemoveExpiredWithdrawals(int nHeight, const uint256& hashBlock);

    /** Remove sidechain-to-be-activated hash from cache, because the user
     * changed their mind */
    void RemoveSidechainHashToAck(const uint256& u);

    /** Reset SCDB and clear out all data tracked by SidechainDB */
    void ResetWithdrawalState();

    /** Clear out the custom vote cache */
    void ResetWithdrawalVotes();

    /** Reset everything */
    void Reset();

    /** Spend a withdrawal bundle (if we can) */
    bool SpendWithdrawal(uint8_t nSidechain, const uint256& hashBlock, const CTransaction& tx, const int nTx, int nHeight, bool fJustCheck = false,  bool fDebug = false);

    /** Get SidechainDeposit from deposit CTransaction. Part of SCDB because
     * we need the list of active sidechains to find deposit outputs. */
    bool TxnToDeposit(const CTransaction& tx, const int nTx, const uint256& hashBlock, SidechainDeposit& deposit);

    /** Print SCDB withdrawal verification status */
    std::string ToString() const;

    /** Check the updates in a block and then apply them */
    bool Update(int nHeight, const uint256& hashBlock, const uint256& hashPrevBlock, const std::vector<CTxOut>& vout, bool fJustCheck = false, bool fDebug = false);

    /** Undo the changes to SCDB of a block - for block is disconnection */
    bool Undo(int nHeight, const uint256& hashBlock, const uint256& hashPrevBlock, const std::vector<CTransactionRef>& vtx, bool fDebug = false);

    /** Update / add multiple withdrawals to SCDB */
    bool UpdateSCDBIndex(const std::vector<std::string>& vVote, int nHeight, const uint256& hashBlock, bool fDebug = false, const std::map<uint8_t /* nSidechain */, uint256 /* withdrawal hash */>& mapNewWithdrawal = {});

private:
    /**
     * Apply default abstain vote for all sidechain withdrawals. Used when a new
     * block does not contain a valid update. */
    void ApplyDefaultUpdate(int nHeight, const uint256& hashBlock);

    /** Apply the changes in a block to SCDB */
    bool ApplyUpdate(int nHeight, const uint256& hashBlock, const uint256& hashPrevBlock, const std::vector<CTxOut>& vout, bool fJustCheck = false, bool fDebug = false);

    /** Takes a list of sidechain hashes to upvote */
    void UpdateActivationStatus(const std::vector<uint256>& vHash, int nHeight);

    /** Update CTIP from the deposit cache for the given slots only - called
     * after sorting / undo with the slots whose deposits actually changed.
     *
     * Per-slot on purpose. The pointer of a slot this call did not touch can
     * be one the per-block record supplied and the local deposit cache cannot
     * reproduce - a working copy resynced from a parent's record starts with
     * every pointer correct and no deposits at all. A full sweep here would
     * derive those pointers from the cache anyway, erasing the treasury of
     * every slot the cache is empty for and writing the erasure into the next
     * block's record. Where the record supplies the pointer, the deposit cache
     * does not get to overrule it; Undo learned the same lesson from the other
     * side. */
    bool UpdateCTIP(const std::set<uint8_t>& setSlot);

    /** Calls SortDeposits for all of SCDB's deposit cache */
    bool SortSCDBDeposits();

    /** Take a new number for GetTemplateStateSeq. Every member function that
     *  changes state named there calls this. The ones that do NOT are those
     *  that run while a template is built or a transaction is relayed and
     *  touch none of that state (AddRemovedBMM, AddRemovedDeposit, the
     *  fJustCheck paths): a call from there would make every getblocktemplate
     *  rebuild. */
    void TemplateStateChanged();

    /** All sidechain slots, their activation status, and params if active */
    std::vector<Sidechain> vSidechain;

    /**
     * The CTIP of nSidechain up to the latest connected block (does not include
     * mempool txns). */
    std::map<uint8_t, SidechainCTIP> mapCTIP;

    /**
     * The treasury log: the current entry for each sidechain whose pointer has
     * moved, carrying the movement counter and the value the pointer held
     * before. Maintained beside mapCTIP by UpdateCTIP, written into the
     * per-block record by ConnectBlock, and restored by ApplyLDBData - which is
     * what makes the treasury survive an unclean shutdown.
     *
     * Node-local. See SidechainTreasuryEntry: nSeq counts what this node saw,
     * so it is not comparable between nodes and is not hashed by
     * GetConsensusSections.
     */
    std::map<uint8_t, SidechainTreasuryEntry> mapTreasury;

    /**
     * Whether the treasury currently held was installed from a per-block record
     * rather than accumulated from the deposit cache.
     *
     * Set by ApplyLDBData. Read by Undo, which is only ever called on a copy
     * immediately after a resync, to decide whether recomputing the pointer
     * from the deposit cache would be an improvement or a regression: when the
     * pointer came from the record it is already the parent's, and recomputing
     * it from a cache that may have been pruned or may be short after an
     * unclean shutdown could replace a correct pointer with a wrong one.
     *
     * Also read by LoadWithdrawalCache, because the same ApplyLDBData branch
     * reinstalls mapFailedWithdrawal from the record: where it is set, the file
     * has nothing left to contribute to that map and must not be allowed to add
     * to it.
     */
    bool fTreasuryFromRecord;

    /**
     * Whether the spent withdrawal map currently held was installed from a
     * per-block record rather than read from withdrawal.dat.
     *
     * Set by ApplyLDBData from the spent key, which is the only thing that
     * promises the record's vSpent was written rather than left empty. Read by
     * LoadWithdrawalCache for the same reason the flag above is read there: the
     * record states the whole spent set as of its own block, so a file written
     * at some earlier shutdown can only disagree with it, never improve on it.
     */
    bool fSpentFromRecord;

    /** The most recent block that SCDB has processed */
    uint256 hashBlockLastSeen;

    /** Activation status of proposed sidechains */
    std::vector<SidechainActivationStatus> vActivationStatus;

    /** Cache of withdrawal vote settings created by the user */
    std::vector<std::string> vVoteCache;

    /** Cache of deposits for each sidechain. TODO optimize with caching
     * so that we don't have to keep all of these in memory.
     * x = nSidechain
     * y = list of deposits for nSidechain */
    std::vector<std::vector<SidechainDeposit>> vDepositCache;

    /** Cache of sidechain hashes, for sidechains which this node has been
     * configured to activate by the user */
    std::vector<uint256> vSidechainHashAck;

    /** Cache of proposals for new sidechains created by this node,
     * which should be included in the next block that this node mines. */
    std::vector<Sidechain> vSidechainProposal;

    /** Cache of potential withdrawal transactions
     * TODO consider refactoring to use CTransactionRef */
    std::vector<std::pair<uint8_t, CMutableTransaction>> vWithdrawalTxCache;

    //! NODE-LOCAL: bundles AddWithdrawal displaced
    //! from a full slot that have not re-entered, been paid or expired since.
    //! Read only by the miner (NewWithdrawalsToCommit). Not consensus state:
    //! in no record, commitment or hash, and lost on restart (each bundle may
    //! then displace once more - bounded).
    //! 0.45.2: only bundles whose raw transaction is in
    //! vWithdrawalTxCache are marked, so this set is never larger than that
    //! cache; it used to gain an entry for every displaced hash, without bound.
    std::set<std::pair<uint8_t, uint256>> setDisplacedWithdrawal;

    /** Undo helper: re-cache the raw bundle of
     * every withdrawal payout in a disconnected block that the parent state
     * still holds as pending. NODE-LOCAL, like vWithdrawalTxCache itself. */
    void RestorePaidWithdrawalTx(const std::vector<CTransactionRef>& vtx);

    /** Tracks verification status of withdrawals
     * x = nSidechain
     * y = state of withdrawals for nSidechain */
    std::vector<std::vector<SidechainWithdrawalState>> vWithdrawalStatus;

    /** See GetTemplateStateSeq. */
    uint64_t nTemplateStateSeq = 0;

    /** See GetFailedPrunedLastUpdate. Node-local, never hashed. */
    int nFailedPrunedLastUpdate = 0;

    /** Map of spent withdrawals. Key: block hash Value: Spent withdrawals from block */
    std::map<uint256, std::vector<SidechainSpentWithdrawal>> mapSpentWithdrawal;

    /** Map of failed withdrawals. Key: withdrawal hash Value: spent withdrawal */
    std::map<uint256, SidechainFailedWithdrawal> mapFailedWithdrawal;

    /**
     * Which block recorded each failure, so that disconnecting the block can
     * take the failure back out of mapFailedWithdrawal.
     *
     * This is not bookkeeping. AddWithdrawal refuses a bundle that is already
     * recorded failed, so a node that keeps a failure belonging to a branch the
     * network abandoned will reject a block the rest of the network accepts,
     * and stop following the chain.
     *
     * Key: block hash  Value: failures that block created
     */
    std::map<uint256, std::vector<SidechainFailedWithdrawal>> mapFailedWithdrawalBlock;

    /** List of BMM request txid that the miner removed from the mempool. */
    std::set<uint256> setRemovedBMM;
    //! Insertion order of setRemovedBMM, so the oldest entry is dropped first
    //! once the cap is reached.
    std::deque<uint256> dequeRemovedBMMOrder;

    /** List of deposit txids that are cached by SCDB */
    std::set<uint256> setDepositTXID;

    /** List of sidechain deposits that were removed from the mempool for one
     * of a few reasons. The deposit could have been replaced by another deposit
     * that made it to the mempool first, spending the same CTIP. Or the deposit
     * may have been in the mempool when a withdrawal payout was created,
     * spending the same CTIP as the deposit. */
    std::vector<uint256> vRemovedDeposit;
};

/** Read encoded sum of withdrawal fees output script */
bool DecodeWithdrawalFees(const CScript& script, CAmount& amount);

/** Sort deposits by CTIP UTXO spending order */
bool SortDeposits(const std::vector<SidechainDeposit>& vDeposit, std::vector<SidechainDeposit>& vDepositSorted);

/**
 * Build the change-return deposit that paying out a withdrawal bundle creates.
 *
 * A bundle spends the whole treasury and returns the remainder to the sidechain
 * script, and that return is cached as a deposit like any other - which is why
 * the deposit cache cannot be reconstructed from deposit transactions alone.
 *
 * Shared for the same reason as GetBlockDeposits: SpendWithdrawal builds this
 * on the connect path and a rebuild has to arrive at a byte-identical object,
 * so there is one construction and both call it. Returns false unless the
 * transaction has exactly one sidechain output to return the change to, which
 * SpendWithdrawal has already established for any block that was accepted.
 */
bool GetWithdrawalChangeDeposit(const CTransaction& tx, int nTx, const uint256& hashBlock,
                                uint8_t nSidechain, SidechainDeposit& deposit);

bool ParseSCDBBytes(const CScript& script, const std::vector<std::vector<SidechainWithdrawalState>>& vOldScores, std::vector<std::string>& vVote);

#endif // BITCOIN_SIDECHAINDB_H
