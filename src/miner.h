// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_MINER_H
#define BITCOIN_MINER_H

#include <primitives/block.h>
#include <txmempool.h>

#include <stdint.h>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>

class CBlockIndex;
class CChainParams;
class CScript;
struct Sidechain;

namespace Consensus { struct Params; };

/** A flat upper bound on the drivechain commitment bytes of a coinbase at
 *  nHeight: SMALL_BLOCK_PER_SIDECHAIN_RESERVE_BYTES per active sidechain, an
 *  activation commitment per proposal waiting to activate, the largest
 *  proposal commitment, and the SCDB hash commitment. The assembler reserves
 *  it as WEIGHT in every block, and SmallBlockPayoutRoomBytes subtracts it;
 *  the assembler's small-block BYTE budget uses the measured
 *  SmallBlockCoinbaseCommitmentBytes instead. Reads the sidechain database;
 *  call with cs_main held. pnSlots, if given, receives the number of
 *  commitments the sigop reserve is sized for. */
uint64_t SmallBlockCommitmentReserveBytes(int nHeight, size_t* pnSlots);
/** The most bytes a withdrawal BUNDLE may occupy and still be paid out in a
 *  small block this node assembles at nHeight: the cap less the coinbase
 *  reserve, the commitment reserve above and the payout's own overhead. It
 *  shrinks as sidechains activate, which is why receivewithdrawalbundle
 *  checks it and not only the fixed SIDECHAIN_MAX_WITHDRAWAL_BUNDLE_BYTES.
 *  Zero when the reserves alone fill the block. */
uint64_t SmallBlockPayoutRoomBytes(int nHeight);

static const bool DEFAULT_PRINTPRIORITY = false;

/** Flat coinbase figure behind SmallBlockPayoutRoomBytes, the bound
 *  receivewithdrawalbundle holds a bundle to. It is NO LONGER what the block
 *  assembler holds back while it selects transactions: that is computed from
 *  what the coinbase will actually carry (SmallBlockCoinbaseCommitmentBytes
 *  and SMALL_BLOCK_MINER_ALLOWANCE_BYTES below), which is never more than
 *  this, so a bundle admitted against this figure still fits when it is paid. */
static const uint64_t SMALL_BLOCK_COINBASE_RESERVE_BYTES = 6000;
/** Per-active-sidechain figure behind SmallBlockPayoutRoomBytes, and the
 *  per-sidechain WEIGHT reserve of the assembler (weight does not bind a small
 *  block). The assembler's byte budget no longer uses it: a sidechain's vote
 *  bytes are 2 and its withdrawal-hash commitment, when it has one, 47. */
static const uint64_t SMALL_BLOCK_PER_SIDECHAIN_RESERVE_BYTES = 112;
/** Bytes the assembler leaves free in a small block for whoever finishes the
 *  template: outputs a pool adds to the coinbase beside the payout. Everything
 *  this node itself puts in the coinbase is budgeted separately and exactly
 *  (the scriptSig at its consensus maximum, the payout output, the witness
 *  commitment, every drivechain commitment), so this is free space, not
 *  slack for our own arithmetic. 2000 is twice upstream's allowance for the whole
 *  coinbase (4000 weight), about 58 P2PKH outputs. It is the one tunable left: every byte of it is a
 *  byte no transaction can use. */
static const uint64_t SMALL_BLOCK_MINER_ALLOWANCE_BYTES = 2000;
/** The coinbase scriptSig is budgeted at the most consensus allows
 *  (bad-cb-length above 100): the template carries the height and OP_0, and
 *  the miner grows it with an extra nonce and its tag afterwards. */
static const uint64_t SMALL_BLOCK_COINBASE_SCRIPTSIG_BYTES = 100;
/** The largest title plus description a sidechain proposal may carry and still
 *  be committed. The proposal commitment is the one coinbase append whose size
 *  an operator picks freely, and a coinbase that outgrows its reserve is a
 *  block consensus rejects - which aborts the template and stops this node
 *  producing blocks at all, until the proposal is removed. Skip the proposal
 *  instead. Sized to sit inside the coinbase reserve in both regimes. */
static const size_t SIDECHAIN_PROPOSAL_MAX_COMMIT_BYTES = 2000;
/** Bytes a withdrawal payout adds to the bundle it is built from: the
 *  treasury (CTIP) input and the sidechain change-return output. */
static const uint64_t SMALL_BLOCK_PAYOUT_OVERHEAD_BYTES = 41 + 64;
/** Serialized bytes a critical data (BMM) transaction adds to a small block
 *  beside itself: its coinbase h* commitment, built by the helper the miner
 *  appends it with, plus one input in the critical fee collection transaction
 *  for each bare OP_TRUE output it carries. Zero for any other transaction.
 *  (Was a flat 160; the measured need of a stock request is 54 + 41.) */
uint64_t SmallBlockCriticalTxReserveBytes(const CTransaction& tx);
/** Serialized bytes of the drivechain commitments the coinbase of a block at
 *  nHeight will carry apart from the per-transaction h* commitments: one
 *  withdrawal-hash commitment for each active sidechain that has a new bundle
 *  to announce, the SCDB update (vote) bytes, the proposal and activation
 *  commitments and the SCDB hash commitment. Built on a scratch block with
 *  the predicates and helpers CreateNewBlock appends them with, so the figure
 *  is exact. mapNewWithdrawal is the bundle hash each sidechain announces in
 *  this block, which CreateNewBlock looks up once and commits from the same
 *  map. Only meaningful for a block bound by the small-block rule. Reads
 *  the sidechain database; call with cs_main held. */
uint64_t SmallBlockCoinbaseCommitmentBytes(int nHeight, const std::vector<Sidechain>& vActiveSidechain, const std::map<uint8_t, uint256>& mapNewWithdrawal, bool fDrivechainEnabled);
/** Weight still to be added to the coinbase after the last point the assembler
 *  can measure the block: the witness commitment output, the SCDB hash
 *  commitment once its height is reached, and the extra nonce the miner grows
 *  in the coinbase scriptSig once it has the template. The serialized-size
 *  margin beside it in the fee-tx room check grows by SCDB_COMMITMENT_BYTES
 *  from that height, because a fixed figure sized before the commitment
 *  existed cannot cover it. */
static const int64_t COINBASE_FINALIZE_RESERVE_WEIGHT = 700;
/** Serialized bytes of one sidechain activation commitment: a zero value, a
 *  one byte script length and a 37 byte OP_RETURN script. */
static const uint64_t SIDECHAIN_ACTIVATION_COMMITMENT_BYTES = 46;
/** Serialized bytes of the SCDB hash commitment output, required in every
 *  coinbase from SCDBCommitmentHeight: a zero value, a one byte script length
 *  and a 37 byte OP_RETURN script - the activation commitment's shape. */
static const uint64_t SCDB_COMMITMENT_BYTES = 46;
/** Serialized bytes of one critical fee transaction input: a 36 byte outpoint,
 *  a one byte (empty) scriptSig length and a 4 byte sequence. The bid output it
 *  spends is a bare OP_TRUE, so no signature rides along. */
static const uint64_t CRITICAL_FEE_TX_INPUT_BYTES = 41;
/** Further addPackageTxs passes CreateNewBlock may run to place a fallback
 *  BMM request for a slot whose chosen request did not fit (0.45.2). Each pass
 *  walks the memory pool again, so they are capped. */
static const int MAX_BMM_FALLBACK_PASSES = 3;
/** Coinbase sigop cost reserved per active sidechain. That sidechain's SCDB
 *  update bytes and withdrawal-hash commitment are OP_RETURN outputs carrying
 *  32-byte hashes, and CScript::GetSigOpCount reads past OP_RETURN, so hash
 *  bytes equal to OP_CHECKSIG or OP_CHECKMULTISIG are charged to the block.
 *  Unlike a critical data transaction's commitment, the bytes here are hash
 *  outputs nobody can choose, so this covers a generous typical rather than
 *  the unreachable maximum. */
static const int64_t PER_SIDECHAIN_COINBASE_SIGOPS_RESERVE = 100;

struct CBlockTemplate
{
    CBlock block;
    std::vector<CAmount> vTxFees;
    std::vector<int64_t> vTxSigOpsCost;
    std::vector<unsigned char> vchCoinbaseCommitment;
};

// Container for tracking updates to ancestor feerate as we include (parent)
// transactions in a block
struct CTxMemPoolModifiedEntry {
    explicit CTxMemPoolModifiedEntry(CTxMemPool::txiter entry)
    {
        iter = entry;
        nSizeWithAncestors = entry->GetSizeWithAncestors();
        nModFeesWithAncestors = entry->GetModFeesWithAncestors();
        nSigOpCostWithAncestors = entry->GetSigOpCostWithAncestors();
    }

    int64_t GetModifiedFee() const { return iter->GetModifiedFee(); }
    uint64_t GetSizeWithAncestors() const { return nSizeWithAncestors; }
    CAmount GetModFeesWithAncestors() const { return nModFeesWithAncestors; }
    size_t GetTxSize() const { return iter->GetTxSize(); }
    const CTransaction& GetTx() const { return iter->GetTx(); }

    CTxMemPool::txiter iter;
    uint64_t nSizeWithAncestors;
    CAmount nModFeesWithAncestors;
    int64_t nSigOpCostWithAncestors;
};

/** Comparator for CTxMemPool::txiter objects.
 *  It simply compares the internal memory address of the CTxMemPoolEntry object
 *  pointed to. This means it has no meaning, and is only useful for using them
 *  as key in other indexes.
 */
struct CompareCTxMemPoolIter {
    bool operator()(const CTxMemPool::txiter& a, const CTxMemPool::txiter& b) const
    {
        return &(*a) < &(*b);
    }
};

struct modifiedentry_iter {
    typedef CTxMemPool::txiter result_type;
    result_type operator() (const CTxMemPoolModifiedEntry &entry) const
    {
        return entry.iter;
    }
};

// A comparator that sorts transactions based on number of ancestors.
// This is sufficient to sort an ancestor package in an order that is valid
// to appear in a block.
struct CompareTxIterByAncestorCount {
    bool operator()(const CTxMemPool::txiter &a, const CTxMemPool::txiter &b) const
    {
        if (a->GetCountWithAncestors() != b->GetCountWithAncestors())
            return a->GetCountWithAncestors() < b->GetCountWithAncestors();
        return CTxMemPool::CompareIteratorByHash()(a, b);
    }
};

typedef boost::multi_index_container<
    CTxMemPoolModifiedEntry,
    boost::multi_index::indexed_by<
        boost::multi_index::ordered_unique<
            modifiedentry_iter,
            CompareCTxMemPoolIter
        >,
        // sorted by modified ancestor fee rate
        boost::multi_index::ordered_non_unique<
            // Reuse same tag from CTxMemPool's similar index
            boost::multi_index::tag<ancestor_score>,
            boost::multi_index::identity<CTxMemPoolModifiedEntry>,
            CompareTxMemPoolEntryByAncestorFee
        >
    >
> indexed_modified_transaction_set;

typedef indexed_modified_transaction_set::nth_index<0>::type::iterator modtxiter;
typedef indexed_modified_transaction_set::index<ancestor_score>::type::iterator modtxscoreiter;

struct update_for_parent_inclusion
{
    explicit update_for_parent_inclusion(CTxMemPool::txiter it) : iter(it) {}

    void operator() (CTxMemPoolModifiedEntry &e)
    {
        e.nModFeesWithAncestors -= iter->GetFee();
        e.nSizeWithAncestors -= iter->GetTxSize();
        e.nSigOpCostWithAncestors -= iter->GetSigOpCost();
    }

    CTxMemPool::txiter iter;
};

/** -bmmfeescript. When set, the critical (BMM) fee
 *  transaction a template carries pays this script instead of the coinbase
 *  script - which in getblocktemplate is a dummy OP_TRUE, so the bids went to
 *  anyone. A pool cannot rewrite that output itself: the fee transaction is
 *  added before the witness commitment, so changing it breaks that. Empty =
 *  unchanged behaviour. Miner policy only. */
extern CScript g_bmm_fee_script;

/** Generate a new block, without valid proof-of-work */
class BlockAssembler
{
private:
    // The constructed block template
    std::unique_ptr<CBlockTemplate> pblocktemplate;
    // A convenience pointer that always refers to the CBlock in pblocktemplate
    CBlock* pblock;

    // Configuration parameters for the block size
    bool fIncludeWitness;
    unsigned int nBlockMaxWeight;
    CFeeRate blockMinFeeRate;

    // Information on the current status of the block
    uint64_t nBlockWeight;
    uint64_t nBlockTx;
    uint64_t nBlockSigOpsCost;
    // Small-block soft fork: whether the block being assembled is bound by
    // MAX_SMALL_BLOCK_SERIALIZED_SIZE, and the exact serialized bytes
    // consumed so far (including reservations for the coinbase, withdrawal
    // payouts and the critical fee tx).
    bool fEnforceSmallBlock;
    uint64_t nBlockSerializedSize;
    CAmount nFees;
    CTxMemPool::setEntries inBlock;

    // Chain context for the block
    int nHeight;
    int64_t nLockTimeCutoff;
    const CChainParams& chainparams;

public:
    struct Options {
        Options();
        size_t nBlockMaxWeight;
        CFeeRate blockMinFeeRate;
    };

    explicit BlockAssembler(const CChainParams& params);
    BlockAssembler(const CChainParams& params, const Options& options);

    /** Construct a new block template with coinbase to scriptPubKeyIn */
    std::unique_ptr<CBlockTemplate> CreateNewBlock(const CScript& scriptPubKeyIn, bool fMineWitnessTx=true);
    std::unique_ptr<CBlockTemplate> CreateNewBlock(const CScript& scriptPubKeyIn, bool fMineWitnessTx, bool& fAddedBMM);

    /** Set while retrying a template after a hand-placed -blockplacetx
     *  transaction turned out to make the block invalid, so the retry does not
     *  place it again and recurse. */
    bool fPlacementDisabled = false;

private:
    // utility functions
    /** Clear the block's state and prepare for assembling a new block */
    void resetBlock();
    /** Add a tx to the block */
    void AddToBlock(CTxMemPool::txiter iter);

    // Methods for how to add transactions to a block.
    /** Add transactions based on feerate including unconfirmed ancestors
      * Increments nPackagesSelected / nDescendantsUpdated with corresponding
      * statistics from the package selection (for logging statistics). */
    void addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated, bool fDrivechainEnabled, bool& fNeedCriticalFeeTx, const std::set<uint8_t>& setSidechainsWithWithdrawal, const std::set<uint256>& setBMMChosen, std::set<uint8_t>& setBMMSlotTaken);

    /** The BMM request each slot not yet in setBMMSlotTaken may carry in this
      * block: the best-ranked candidate not in setBMMTried whose whole
      * package - its own and its unconfirmed ancestors' bytes, the h*
      * commitment and one collection input per OP_TRUE bid output - still
      * fits what is left of the block.
      * Returns slot -> txid. Call with cs_main and mempool.cs held. */
    std::map<uint8_t, uint256> PickBMMRequests(const std::map<uint8_t, std::vector<uint256>>& mapBMMRanked,
                                               const std::set<uint8_t>& setBMMSlotTaken,
                                               const std::set<uint256>& setBMMTried);

    // helper functions for addPackageTxs()
    /** Remove confirmed (inBlock) entries from given set */
    void onlyUnconfirmed(CTxMemPool::setEntries& testSet);
    /** Test if a new package would "fit" in the block */
    bool TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const;
    /** Perform checks on each transaction in a package:
      * locktime, premature-witness, serialized size (if necessary)
      * These checks should always succeed, and they're here
      * only as an extra check in case of suboptimal node configuration */
    bool TestPackageTransactions(const CTxMemPool::setEntries& package);
    /** Return true if given transaction from mapTx has already been evaluated,
      * or if the transaction's cached data in mapTx is incorrect. */
    bool SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx);
    /** Sort the package in an order that is valid to appear in a block */
    void SortForBlock(const CTxMemPool::setEntries& package, CTxMemPool::txiter entry, std::vector<CTxMemPool::txiter>& sortedEntries);
    /** Add descendants of given transactions to mapModifiedTx with ancestor
      * state updated assuming given transactions are inBlock. Returns number
      * of updated descendants. */
    int UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded, indexed_modified_transaction_set &mapModifiedTx);

    // SidechainDB
    /** Create withdrawal payout transaction for nSidechain if needed */
    bool CreateWithdrawalPayout(uint8_t nSidechain, CMutableTransaction& tx, CAmount& nFees);
};

/** Miner functions restored from Bitcoin 0.12 */

/** Run the miner threads */
void GenerateBitcoins(bool fGenerate, int nThreads, const CChainParams& chainparams);
/** Modify the extranonce in a block */
void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce);
int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev);

/** -acksidechainproposal: the sidechain proposals this node's miner acks
 *  because the operator NAMED them, by exact proposal hash. MINER POLICY ONLY:
 *  no consensus rule reads any of this; it only decides which activation
 *  commitments this node writes into the blocks it builds.
 *
 *  A value is the 64-hex-digit proposal hash exactly as
 *  getsidechainactivationstatus prints it in "proposalhash" (uint256 display
 *  order, the form acksidechain also takes). The "Hash" entries of
 *  listhashsidechain are the same hash BYTE-REVERSED and will not match.
 *
 *  Parse the values of the option. Returns false, with strError naming the
 *  first bad value, if any value is not 64 hex digits or is all zero. */
bool ParseSidechainProposalAcks(const std::vector<std::string>& vArg, std::set<uint256>& setOut, std::string& strError);
/** Install the parsed -acksidechainproposal set (init; tests). It lives
 *  outside the SCDB, so no SCDB reset or rebuild can drop it. */
void SetConfiguredSidechainProposalAcks(const std::set<uint256>& setAck);
std::set<uint256> GetConfiguredSidechainProposalAcks();
/** True if this node acks the pending proposal by configuration. */
bool IsConfiguredSidechainProposalAck(const uint256& hashProposal);
/** True if a block template built now acks this pending proposal: because
 *  -activatesidechains is set (acks EVERY proposal), because the acksidechain
 *  RPC list holds it, or because -acksidechainproposal names it. The one test
 *  both template code paths use. Caller holds cs_main (reads scdb). */
bool MinerAcksSidechainProposal(const uint256& hashProposal);

/** what each -acksidechainproposal value matches right now.
 *  Diagnostic only - no consensus or template code reads it. */
struct ConfiguredSidechainAckStatus {
    enum Status {
        PENDING,   //!< names a pending proposal: the miner acks it
        ACTIVE,    //!< names a proposal that has since activated: nothing left to ack
        REVERSED,  //!< matches nothing, but its BYTE-REVERSED form is a pending proposal
        NOMATCH,   //!< matches no pending proposal and no active sidechain
    };
    uint256 hash;        //!< the configured value
    Status status;
    uint256 hashMatch;   //!< REVERSED: the proposalhash it should have been
};
/** One entry per -acksidechainproposal value. Caller holds cs_main (reads scdb). */
std::vector<ConfiguredSidechainAckStatus> GetConfiguredSidechainProposalAckStatus();
std::string ConfiguredSidechainAckStatusName(ConfiguredSidechainAckStatus::Status status);
/** Log a WARNING for every configured value that names no pending proposal
 *  (and say so exactly when the byte-reversed form does). ACTIVE is logged
 *  once per change, not every block. Returns the number of values that name
 *  no pending proposal (REVERSED + NOMATCH). Caller holds cs_main. */
int LogConfiguredSidechainProposalAckStatus(bool fStartup);

#endif // BITCOIN_MINER_H

