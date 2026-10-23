// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <validation.h>

#include <addressbook.h>
#include <arith_uint256.h>
#include <chain.h>
#include <chainparams.h>
#include <checkpoints.h>
#include <checkqueue.h>
#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <consensus/tx_verify.h>
#include <consensus/validation.h>
#include <cuckoocache.h>
#include <hash.h>
#include <init.h>
#include <merkleblock.h>
#include <miner.h>

#include <policy/fees.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <random.h>
#include <reverse_iterator.h>
#include <script/script.h>
#include <script/sigcache.h>
#include <script/standard.h>
#include <sidechain.h>
#include <sidechaindb.h>
#include <timedata.h>
#include <tinyformat.h>
#include <txdb.h>
#include <txmempool.h>
#include <ui_interface.h>
#include <undo.h>
#include <util.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h>
#include <validationinterface.h>
#include <versionbits.h>
#include <warnings.h>

#include <future>
#include <sstream>
#include <tuple>

#include <boost/algorithm/string/replace.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/thread.hpp>
#include <boost/bind/placeholders.hpp>

using namespace boost::placeholders;

#if defined(NDEBUG)
# error "Skydoge cannot be compiled without assertions."
#endif

#define MICRO 0.000001
#define MILLI 0.001

/**
 * Global state
 */
namespace {
    struct CBlockIndexWorkComparator
    {
        bool operator()(const CBlockIndex *pa, const CBlockIndex *pb) const {
            // First sort by most total work, ...
            if (pa->nChainWork > pb->nChainWork) return false;
            if (pa->nChainWork < pb->nChainWork) return true;

            // ... then by earliest time received, ...
            if (pa->nSequenceId < pb->nSequenceId) return false;
            if (pa->nSequenceId > pb->nSequenceId) return true;

            // Use pointer address as tie breaker (should only happen with blocks
            // loaded from disk, as those all have id 0).
            if (pa < pb) return false;
            if (pa > pb) return true;

            // Identical blocks.
            return false;
        }
    };
} // anon namespace

enum DisconnectResult
{
    DISCONNECT_OK,      // All good.
    DISCONNECT_UNCLEAN, // Rolled back, but UTXO set was inconsistent with block.
    DISCONNECT_FAILED   // Something else went wrong.
};

class ConnectTrace;

/**
 * CChainState stores and provides an API to update our local knowledge of the
 * current best chain and header tree.
 *
 * It generally provides access to the current block tree, as well as functions
 * to provide new data, which it will appropriately validate and incorporate in
 * its state as necessary.
 *
 * Eventually, the API here is targeted at being exposed externally as a
 * consumable libconsensus library, so any functions added must only call
 * other class member functions, pure functions in other parts of the consensus
 * library, callbacks via the validation interface, or read/write-to-disk
 * functions (eventually this will also be via callbacks).
 */
class CChainState {
private:
    /**
     * The set of all CBlockIndex entries with BLOCK_VALID_TRANSACTIONS (for itself and all ancestors) and
     * as good as our current tip or better. Entries may be failed, though, and pruning nodes may be
     * missing the data for the block.
     */
    std::set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexCandidates;

    /**
     * Every received block is assigned a unique and increasing identifier, so we
     * know which one to give priority in case of a fork.
     */
    CCriticalSection cs_nBlockSequenceId;
    /** Blocks loaded from disk are assigned id 0, so start the counter at 1. */
    int32_t nBlockSequenceId = 1;
    /** Decreasing counter (used by subsequent preciousblock calls). */
    int32_t nBlockReverseSequenceId = -1;
    /** chainwork for the last block that preciousblock has been applied to. */
    arith_uint256 nLastPreciousChainwork = 0;

    /**
     * What ConnectBlock found wrong with this node's own SCDB caches, carried
     * out to ConnectTip so the alert is raised only once the block is really on
     * the chain.
     *
     * ConnectBlock is not the end of acceptance: ConnectTip can still fail its
     * flush afterwards, and chainActive does not move until SetTip. It is also
     * called by VerifyDB to re-verify historical blocks, which are not being
     * accepted at all. Alerting from inside it therefore claimed things that
     * were not true yet and sometimes never became true. Reset on entry to the
     * SCDB section of every ConnectBlock, so a VerifyDB pass cannot leave a
     * finding behind for the next real connect to report.
     */
    struct SCDBCacheFinding {
        bool fCacheUnsound = false;
        uint8_t nSlotUnsupported = 0;
        size_t nStated = 0;
        bool fRecordNewlyWritten = false;
        SidechainDB::TreasuryLogAudit audit;

        bool IsClean() const { return !fCacheUnsound && audit.IsClean(); }
        void Reset() { *this = SCDBCacheFinding(); }
    };
    SCDBCacheFinding m_scdb_finding;

    /** In order to efficiently track invalidity of headers, we keep the set of
      * blocks which we tried to connect and found to be invalid here (ie which
      * were set to BLOCK_FAILED_VALID since the last restart). We can then
      * walk this set and check if a new header is a descendant of something in
      * this set, preventing us from having to walk mapBlockIndex when we try
      * to connect a bad block and fail.
      *
      * While this is more complicated than marking everything which descends
      * from an invalid block as invalid at the time we discover it to be
      * invalid, doing so would require walking all of mapBlockIndex to find all
      * descendants. Since this case should be very rare, keeping track of all
      * BLOCK_FAILED_VALID blocks in a set should be just fine and work just as
      * well.
      *
      * Because we already walk mapBlockIndex in height-order at startup, we go
      * ahead and mark descendants of invalid blocks as FAILED_CHILD at that time,
      * instead of putting things in this set.
      */
    std::set<CBlockIndex*> g_failed_blocks;

public:
    CChain chainActive;
    BlockMap mapBlockIndex;
    std::multimap<CBlockIndex*, CBlockIndex*> mapBlocksUnlinked;
    CBlockIndex *pindexBestInvalid = nullptr;

    bool LoadBlockIndex(const Consensus::Params& consensus_params, CBlockTreeDB& blocktree);

    bool ActivateBestChain(CValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock);

    bool AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex);
    bool AcceptBlock(const std::shared_ptr<const CBlock>& pblock, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested,  const CDiskBlockPos* dbp, bool* fNewBlock, bool fFromDisk = false);

    // Block (dis)connection on a given view:
    DisconnectResult DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view);
    bool ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex,
                    CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck = false);

    // Block disconnection on our pcoinsTip:
    bool DisconnectTip(CValidationState& state, const CChainParams& chainparams, DisconnectedBlockTransactions *disconnectpool);

    // Manual block validity manipulation:
    bool PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex *pindex);
    bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex);
    bool ResetBlockFailureFlags(CBlockIndex *pindex);

    bool ReplayBlocks(const CChainParams& params, CCoinsView* view);
    bool RewindBlockIndex(const CChainParams& params);
    bool LoadGenesisBlock(const CChainParams& chainparams);

    void PruneBlockIndexCandidates();

    void UnloadBlockIndex();
    void UnloadWBlockIndex();

private:
    bool ActivateBestChainStep(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace);
    bool ConnectTip(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool);

    CBlockIndex* AddToBlockIndex(const CBlockHeader& block);
    /** Create a new block index entry for a given block hash */
    CBlockIndex * InsertBlockIndex(const uint256& hash);
    void CheckBlockIndex(const Consensus::Params& consensusParams);

    void InvalidBlockFound(CBlockIndex *pindex, const CValidationState &state);
    CBlockIndex* FindMostWorkChain();
    bool ReceivedBlockTransactions(const CBlock &block, CValidationState& state, CBlockIndex *pindexNew, const CDiskBlockPos& pos, const Consensus::Params& consensusParams);


    bool RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs, const CChainParams& params);
} g_chainstate;



CCriticalSection cs_main;

BlockMap& mapBlockIndex = g_chainstate.mapBlockIndex;
CChain& chainActive = g_chainstate.chainActive;
CBlockIndex *pindexBestHeader = nullptr;
CWaitableCriticalSection csBestBlock;
CConditionVariable cvBlockChange;
int nScriptCheckThreads = 0;
std::atomic_bool fImporting(false);
std::atomic_bool fReindex(false);
bool fTxIndex = false;
bool fHavePruned = false;
bool fPruneMode = false;
bool fIsBareMultisigStd = DEFAULT_PERMIT_BAREMULTISIG;
bool fRequireStandard = true;
bool fCheckBlockIndex = false;
bool fCheckpointsEnabled = DEFAULT_CHECKPOINTS_ENABLED;
size_t nCoinCacheUsage = 5000 * 300;
uint64_t nPruneTarget = 0;
int64_t nMaxTipAge = DEFAULT_MAX_TIP_AGE;
bool fEnableReplacement = DEFAULT_ENABLE_REPLACEMENT;
bool fDrivechainPolicyBypass = false;

uint256 hashAssumeValid;
arith_uint256 nMinimumChainWork;

CFeeRate minRelayTxFee = CFeeRate(DEFAULT_MIN_RELAY_TX_FEE);
CAmount maxTxFee = DEFAULT_TRANSACTION_MAXFEE;

CBlockPolicyEstimator feeEstimator;
CTxMemPool mempool(&feeEstimator);

AddressBook addressBook;

SidechainDB scdb;

//! Set for the lifetime of a SidechainVerifyGuard, i.e. while VerifyDB walks
//! blocks down and back up. DisconnectBlock and ConnectBlock consult it before
//! touching the mempool's sidechain bookkeeping: a verification walk has to
//! leave the mempool as it found it, and a transaction it evicted could not be
//! put back.
static bool fSidechainVerifying = false;

/** Constant stuff for coinbase transactions we create: */
CScript COINBASE_FLAGS;

const std::string strMessageMagic = "Bitcoin Signed Message:\n";

// Internal stuff
namespace {
    CBlockIndex *&pindexBestInvalid = g_chainstate.pindexBestInvalid;

    /** All pairs A->B, where A (or one of its ancestors) misses transactions, but B has transactions.
     * Pruned nodes may have entries where B is missing data.
     */
    std::multimap<CBlockIndex*, CBlockIndex*>& mapBlocksUnlinked = g_chainstate.mapBlocksUnlinked;

    CCriticalSection cs_LastBlockFile;
    std::vector<CBlockFileInfo> vinfoBlockFile;
    int nLastBlockFile = 0;
    /** Global flag to indicate we should check to see if there are
     *  block/undo files that should be deleted.  Set on startup
     *  or if we allocate more file space when we're in prune mode
     */
    bool fCheckForPruning = false;

    /** Dirty block index entries. */
    std::set<CBlockIndex*> setDirtyBlockIndex;

    /** Dirty block file entries. */
    std::set<int> setDirtyFileInfo;
} // anon namespace

CBlockIndex* FindForkInGlobalIndex(const CChain& chain, const CBlockLocator& locator)
{
    // Find the first block the caller has in the main chain
    for (const uint256& hash : locator.vHave) {
        BlockMap::iterator mi = mapBlockIndex.find(hash);
        if (mi != mapBlockIndex.end())
        {
            CBlockIndex* pindex = (*mi).second;
            if (chain.Contains(pindex))
                return pindex;
            if (pindex->GetAncestor(chain.Height()) == chain.Tip()) {
                return chain.Tip();
            }
        }
    }
    return chain.Genesis();
}

std::unique_ptr<CCoinsViewDB> pcoinsdbview;
std::unique_ptr<CCoinsViewCache> pcoinsTip;
std::unique_ptr<CBlockTreeDB> pblocktree;
std::unique_ptr<CSidechainTreeDB> psidechaintree;
std::unique_ptr<OPReturnDB> popreturndb;

enum FlushStateMode {
    FLUSH_STATE_NONE,
    FLUSH_STATE_IF_NEEDED,
    FLUSH_STATE_PERIODIC,
    FLUSH_STATE_ALWAYS
};

// See definition for documentation
static bool FlushStateToDisk(const CChainParams& chainParams, CValidationState &state, FlushStateMode mode, int nManualPruneHeight=0);
static void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight);
static void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight);
static bool ResyncSCDBInto(SidechainDB& db, const CBlockIndex* pindex);
bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks = nullptr);
static FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly = false);

bool CheckFinalTx(const CTransaction &tx, int flags)
{
    AssertLockHeld(cs_main);

    // By convention a negative value for flags indicates that the
    // current network-enforced consensus rules should be used. In
    // a future soft-fork scenario that would mean checking which
    // rules would be enforced for the next block and setting the
    // appropriate flags. At the present time no soft-forks are
    // scheduled, so no flags are set.
    flags = std::max(flags, 0);

    // CheckFinalTx() uses chainActive.Height()+1 to evaluate
    // nLockTime because when IsFinalTx() is called within
    // CBlock::AcceptBlock(), the height of the block *being*
    // evaluated is what is used. Thus if we want to know if a
    // transaction can be part of the *next* block, we need to call
    // IsFinalTx() with one more than chainActive.Height().
    const int nBlockHeight = chainActive.Height() + 1;

    // BIP113 requires that time-locked transactions have nLockTime set to
    // less than the median time of the previous block they're contained in.
    // When the next block is created its previous block will be the current
    // chain tip, so we use that to calculate the median time passed to
    // IsFinalTx() if LOCKTIME_MEDIAN_TIME_PAST is set.
    const int64_t nBlockTime = (flags & LOCKTIME_MEDIAN_TIME_PAST)
                             ? chainActive.Tip()->GetMedianTimePast()
                             : GetAdjustedTime();

    return IsFinalTx(tx, nBlockHeight, nBlockTime);
}

bool TestLockPointValidity(const LockPoints* lp)
{
    AssertLockHeld(cs_main);
    assert(lp);
    // If there are relative lock times then the maxInputBlock will be set
    // If there are no relative lock times, the LockPoints don't depend on the chain
    if (lp->maxInputBlock) {
        // Check whether chainActive is an extension of the block at which the LockPoints
        // calculation was valid.  If not LockPoints are no longer valid
        if (!chainActive.Contains(lp->maxInputBlock)) {
            return false;
        }
    }

    // LockPoints still valid
    return true;
}

bool CheckSequenceLocks(const CTransaction &tx, int flags, LockPoints* lp, bool useExistingLockPoints)
{
    AssertLockHeld(cs_main);
    AssertLockHeld(mempool.cs);

    CBlockIndex* tip = chainActive.Tip();
    assert(tip != nullptr);

    CBlockIndex index;
    index.pprev = tip;
    // CheckSequenceLocks() uses chainActive.Height()+1 to evaluate
    // height based locks because when SequenceLocks() is called within
    // ConnectBlock(), the height of the block *being*
    // evaluated is what is used.
    // Thus if we want to know if a transaction can be part of the
    // *next* block, we need to use one more than chainActive.Height()
    index.nHeight = tip->nHeight + 1;

    std::pair<int, int64_t> lockPair;
    if (useExistingLockPoints) {
        assert(lp);
        lockPair.first = lp->height;
        lockPair.second = lp->time;
    }
    else {
        // pcoinsTip contains the UTXO set for chainActive.Tip()
        CCoinsViewMemPool viewMemPool(pcoinsTip.get(), mempool);
        std::vector<int> prevheights;
        prevheights.resize(tx.vin.size());
        for (size_t txinIndex = 0; txinIndex < tx.vin.size(); txinIndex++) {
            const CTxIn& txin = tx.vin[txinIndex];
            Coin coin;
            if (!viewMemPool.GetCoin(txin.prevout, coin)) {
                return error("%s: Missing input", __func__);
            }
            if (coin.nHeight == MEMPOOL_HEIGHT) {
                // Assume all mempool transaction confirm in the next block
                prevheights[txinIndex] = tip->nHeight + 1;
            } else {
                prevheights[txinIndex] = coin.nHeight;
            }
        }
        lockPair = CalculateSequenceLocks(tx, flags, &prevheights, index);
        if (lp) {
            lp->height = lockPair.first;
            lp->time = lockPair.second;
            // Also store the hash of the block with the highest height of
            // all the blocks which have sequence locked prevouts.
            // This hash needs to still be on the chain
            // for these LockPoint calculations to be valid
            // Note: It is impossible to correctly calculate a maxInputBlock
            // if any of the sequence locked inputs depend on unconfirmed txs,
            // except in the special case where the relative lock time/height
            // is 0, which is equivalent to no sequence lock. Since we assume
            // input height of tip+1 for mempool txs and test the resulting
            // lockPair from CalculateSequenceLocks against tip+1.  We know
            // EvaluateSequenceLocks will fail if there was a non-zero sequence
            // lock on a mempool input, so we can use the return value of
            // CheckSequenceLocks to indicate the LockPoints validity
            int maxInputHeight = 0;
            for (int height : prevheights) {
                // Can ignore mempool inputs since we'll fail if they had non-zero locks
                if (height != tip->nHeight+1) {
                    maxInputHeight = std::max(maxInputHeight, height);
                }
            }
            lp->maxInputBlock = tip->GetAncestor(maxInputHeight);
        }
    }
    return EvaluateSequenceLocks(index, lockPair);
}

// Returns the script flags which should be checked for a given block
//! The block's serialized size AS COMMITTED - i.e. excluding criticalData.
//!
//! criticalData is written to the wire on version-3 transactions but is
//! suppressed from BOTH the txid and the witness hash by
//! SERIALIZE_TRANSACTION_NO_DRIVECHAIN (see CTransaction::ComputeHash and
//! GetWitnessHash). Those bytes are therefore covered by NOTHING the block
//! commits to, and enforcing a size limit that counts them means enforcing a
//! limit on a quantity a third party can change without invalidating any
//! commitment: pad a relayed copy, and a node rejects it under the HONEST
//! block's hash.
//!
//! Measuring with the same flag the wtxid uses makes the enforced quantity a
//! function of committed data only, so the cap cannot be moved by anyone but
//! the miner who built the block. The suppressed span is small today - vBytes
//! is bounded to MAX_CRITICAL_DATA_BYTES (21) at parse - but the property is
//! what matters, and it stops being small if that bound is ever relaxed.
//!
//! Committing the field instead was considered and rejected: it would mean
//! changing the txid and the witness hash, which are computed in
//! CTransaction's constructor with no chain context, so it cannot be gated on
//! a height - and every historical merkle root and witness commitment was
//! built from the current values.
//!
//! Excluding the field is necessary but not sufficient: on its own it means
//! 50,000 committed bytes bound neither the wire nor the disk size of a block
//! (consensus/consensus.h derives ~1.9x). So every nVersion==3 transaction is
//! charged SMALL_BLOCK_V3_TX_CHARGE_BYTES on top, whatever its criticalData
//! holds. nVersion is committed, so the measure is still a function of
//! committed data only, and the charge is the most the suppressed span can
//! be, so the enforced number is an upper bound on the wire size again.
//!
//! The MINER measures this same charged quantity everywhere it budgets or
//! checks a small block (miner.cpp, via GetChargedSerializedSize), so it can
//! never build a block that passes its own check and fails this one. Keep
//! both sides in step.
uint64_t GetCommittedSerializedSize(const CBlock& block)
{
    uint64_t nSize = ::GetSerializeSize(block, SER_NETWORK,
                                        PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_DRIVECHAIN);
    for (const CTransactionRef& tx : block.vtx) {
        if (tx && tx->nVersion == 3)
            nSize += SMALL_BLOCK_V3_TX_CHARGE_BYTES;
    }
    return nSize;
}

uint64_t GetChargedSerializedSize(const CTransaction& tx)
{
    uint64_t nSize = ::GetSerializeSize(tx, SER_NETWORK,
                                        PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_DRIVECHAIN);
    if (tx.nVersion == 3)
        nSize += SMALL_BLOCK_V3_TX_CHARGE_BYTES;
    return nSize;
}

static unsigned int GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& chainparams);

static void LimitMempoolSize(CTxMemPool& pool, size_t limit, unsigned long age) {
    int expired = pool.Expire(GetTime() - age);
    if (expired != 0) {
        LogPrint(BCLog::MEMPOOL, "Expired %i transactions from the memory pool\n", expired);
    }

    std::vector<COutPoint> vNoSpendsRemaining;
    pool.TrimToSize(limit, &vNoSpendsRemaining);
    for (const COutPoint& removed : vNoSpendsRemaining)
        pcoinsTip->Uncache(removed);
}

/** Convert CValidationState to a human-readable message for logging */
std::string FormatStateMessage(const CValidationState &state)
{
    return strprintf("%s%s (code %i)",
        state.GetRejectReason(),
        state.GetDebugMessage().empty() ? "" : ", "+state.GetDebugMessage(),
        state.GetRejectCode());
}

static bool IsCurrentForFeeEstimation()
{
    AssertLockHeld(cs_main);
    if (IsInitialBlockDownload())
        return false;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - MAX_FEE_ESTIMATION_TIP_AGE))
        return false;
    if (chainActive.Height() < pindexBestHeader->nHeight - 1)
        return false;
    return true;
}

/* Make mempool consistent after a reorg, by re-adding or recursively erasing
 * disconnected block transactions from the mempool, and also removing any
 * other transactions from the mempool that are no longer valid given the new
 * tip/height.
 *
 * Note: we assume that disconnectpool only contains transactions that are NOT
 * confirmed in the current chain nor already in the mempool (otherwise,
 * in-mempool descendants of such transactions would be removed).
 *
 * Passing fAddToMempool=false will skip trying to add the transactions back,
 * and instead just erase from the mempool as needed.
 */

void UpdateMempoolForReorg(DisconnectedBlockTransactions &disconnectpool, bool fAddToMempool)
{
    AssertLockHeld(cs_main);
    std::vector<uint256> vHashUpdate;
    // disconnectpool's insertion_order index sorts the entries from
    // oldest to newest, but the oldest entry will be the last tx from the
    // latest mined block that was disconnected.
    // Iterate disconnectpool in reverse, so that we add transactions
    // back to the mempool starting with the earliest transaction that had
    // been previously seen in a block.
    auto it = disconnectpool.queuedTx.get<insertion_order>().rbegin();
    while (it != disconnectpool.queuedTx.get<insertion_order>().rend()) {
        // ignore validation errors in resurrected transactions
        CValidationState stateDummy;
        if (!fAddToMempool || (*it)->IsCoinBase() ||
            !AcceptToMemoryPool(mempool, stateDummy, *it, nullptr /* pfMissingInputs */,
                                nullptr /* plTxnReplaced */, true /* bypass_limits */, 0 /* nAbsurdFee */)) {
            // If the transaction doesn't make it in to the mempool, remove any
            // transactions that depend on it (which would now be orphans).
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
        } else if (mempool.exists((*it)->GetHash())) {
            vHashUpdate.push_back((*it)->GetHash());
        }
        ++it;
    }
    disconnectpool.queuedTx.clear();
    // AcceptToMemoryPool/addUnchecked all assume that new mempool entries have
    // no in-mempool children, which is generally not true when adding
    // previously-confirmed transactions back to the mempool.
    // UpdateTransactionsFromBlock finds descendants of any transactions in
    // the disconnectpool that were added back and cleans up the mempool state.
    mempool.UpdateTransactionsFromBlock(vHashUpdate);

    // We also need to remove any now-immature transactions
    mempool.removeForReorg(pcoinsTip.get(), chainActive.Tip()->nHeight + 1, STANDARD_LOCKTIME_VERIFY_FLAGS);
    // Re-limit mempool size, in case we added any transactions
    LimitMempoolSize(mempool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
}

// Used to avoid mempool polluting consensus critical paths if CCoinsViewMempool
// were somehow broken and returning the wrong scriptPubKeys
static bool CheckInputsFromMempoolAndCache(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &view, CTxMemPool& pool,
                 unsigned int flags, bool cacheSigStore, PrecomputedTransactionData& txdata) {
    AssertLockHeld(cs_main);

    // pool.cs should be locked already, but go ahead and re-take the lock here
    // to enforce that mempool doesn't change between when we check the view
    // and when we actually call through to CheckInputs
    LOCK(pool.cs);

    assert(!tx.IsCoinBase());
    for (const CTxIn& txin : tx.vin) {
        const Coin& coin = view.AccessCoin(txin.prevout);

        // At this point we haven't actually checked if the coins are all
        // available (or shouldn't assume we have, since CheckInputs does).
        // So we just return failure if the inputs are not available here,
        // and then only have to check equivalence for available inputs.
        if (coin.IsSpent()) return false;

        const CTransactionRef& txFrom = pool.get(txin.prevout.hash);
        if (txFrom) {
            assert(txFrom->GetHash() == txin.prevout.hash);
            assert(txFrom->vout.size() > txin.prevout.n);
            assert(txFrom->vout[txin.prevout.n] == coin.out);
        } else {
            const Coin& coinFromDisk = pcoinsTip->AccessCoin(txin.prevout);
            assert(!coinFromDisk.IsSpent());
            assert(coinFromDisk.out == coin.out);
        }
    }

    return CheckInputs(tx, state, view, true, flags, cacheSigStore, true, txdata);
}

bool GetDrivechainAmounts(const CCoinsView& coins, const CTransaction &tx,
        CAmount& amountSidechainIn, CAmount& amountIn,
        CAmount& amountSidechainOut, CAmount& amountWithdrawn,
        std::string& strFail)
{
    // Collect coins from inputs
    std::vector<Coin> vCoin;
    for (const CTxIn& in : tx.vin) {
        Coin coin;

        if (!coins.GetCoin(in.prevout, coin)) {
            strFail = "Coin missing!\n";
            return false;
        }

        vCoin.push_back(coin);
    }

    // Count value of inputs and make sure there is only 1 CTIP input
    bool fSidechainInputFound = false;
    uint8_t nSidechainIn;
    for (const Coin& c : vCoin) {
        const CTxOut& out = c.out;
        const CScript& scriptPubKey = out.scriptPubKey;
        if (scriptPubKey.IsDrivechain(nSidechainIn)) {
            if (fSidechainInputFound) {
                strFail = "Multiple sidechain inputs!";
                return false;
            } else {
                fSidechainInputFound = true;
            }
            amountSidechainIn += out.nValue;
        } else {
            amountIn += out.nValue;
        }
    }

    // Count value of outputs
    bool fSidechainOutputFound = false;
    uint8_t nSidechainOut;
    for (const CTxOut& out : tx.vout) {
        const CScript scriptPubKey = out.scriptPubKey;
        uint8_t nSidechainOutScript;
        if (scriptPubKey.IsDrivechain(nSidechainOutScript)) {
            if (fSidechainInputFound && nSidechainOutScript != nSidechainIn) {
                strFail = "Output to different sidechain than input!";
                return false;
            }
            else
            if (fSidechainOutputFound && nSidechainOutScript != nSidechainOut) {
                strFail = "Output to multiple sidechains!";
                return false;
            }
            fSidechainOutputFound = true;
            nSidechainOut = nSidechainOutScript;

            amountSidechainOut += out.nValue;
        } else {
            amountWithdrawn += out.nValue;
        }
    }

    return true;
}

// Does the transaction spend a sidechain treasury (OP_DRIVECHAIN) coin at
// all, whatever its value? The relay guard below keys on this, not only on
// the value spent.
static bool SpendsDrivechainCoin(const CCoinsView& coins, const CTransaction& tx)
{
    for (const CTxIn& in : tx.vin) {
        Coin coin;
        uint8_t nSidechainIn = 0;
        if (coins.GetCoin(in.prevout, coin) && coin.out.scriptPubKey.IsDrivechain(nSidechainIn))
            return true;
    }
    return false;
}

static bool AcceptToMemoryPoolWorker(const CChainParams& chainparams, CTxMemPool& pool, CValidationState& state, const CTransactionRef& ptx,
                              bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                              bool bypass_limits, const CAmount& nAbsurdFee, std::vector<COutPoint>& coins_to_uncache)
{
    const CTransaction& tx = *ptx;
    const uint256 hash = tx.GetHash();
    AssertLockHeld(cs_main);
    LOCK(pool.cs); // mempool "read lock" (held through GetMainSignals().TransactionAddedToMempool())
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!CheckTransaction(tx, state))
        return false; // state filled in by CheckTransaction

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "coinbase");

    // Reject transactions with witness before segregated witness activates (override with -prematurewitness)
    bool witnessEnabled = IsWitnessEnabled(chainActive.Tip(), chainparams.GetConsensus());
    if (!gArgs.GetBoolArg("-prematurewitness", false) && tx.HasWitness() && !witnessEnabled) {
        return state.DoS(0, false, REJECT_NONSTANDARD, "no-witness-yet", true);
    }

    // Reject critical data / Skydoge BMM transactions before Skydoge are activated (override with -prematureskydoges)
    bool fCriticalData = !tx.criticalData.IsNull();
    bool skydogeEnabled = IsSkydogeEnabled(chainActive.Tip(), chainparams.GetConsensus());
    if (!gArgs.GetBoolArg("-prematureskydoges", false) && fCriticalData && !skydogeEnabled) {
        return state.DoS(0, false, REJECT_NONSTANDARD, "no-skydoges-yet", true);
    }

    // Reject critical data that no block can ever commit to. ContextualCheckBlock
    // demands a coinbase commit for every critical data transaction and finds it
    // with IsCriticalHashCommit, which refuses to parse a commit whose hash is
    // null. The miner writes the commit from the transaction's own hash, so a
    // null one produces a commit that cannot be matched back: the assembled block
    // is rejected as bad-critical-data-no-commit and template creation fails for
    // as long as the transaction is held. It relays and pays a fee like any other
    // transaction, so it must not be admitted in the first place.
    if (fCriticalData && tx.criticalData.hashCritical.IsNull()) {
        return state.DoS(0, false, REJECT_INVALID, "critical-data-null-hash", true);
    }

    // Reject BMM requests with invalid prevBytes
    if (skydogeEnabled && fCriticalData) {
        uint8_t nSidechain;
        std::string strPrevBlock = "";
        if (tx.criticalData.IsBMMRequest(nSidechain, strPrevBlock)) {
            std::string strTip = chainActive.Tip()->GetBlockHash().ToString();
            strTip = strTip.substr(strTip.size() - 8, strTip.size() - 1);
            if (strPrevBlock != strTip)
                return state.DoS(0, false, REJECT_INVALID, "bmm-invalid-prev-bytes", true);
        }
    }

    // A BMM bid whose signed outputs commit to an h* must carry that same h*
    // in its criticalData. criticalData is excluded from the txid, the witness
    // hash and every signature, so anyone can relay a copy of an honest bid
    // with their own h* swapped in; the copy has the SAME txid, and whichever
    // version a miner sees first is the one it commits - the bidder pays for
    // a proof of the attacker's block. The commitment (BMMBidCommitScript, put
    // there by createbmmcriticaldatatx) is inside what the bidder signed, so a
    // swapped copy fails here at every upgraded node and never reaches a
    // mempool it can be mined from. Requests without a commitment are
    // accepted exactly as before. fCorruptionPossible=true: the txid must NOT
    // enter recentRejects, or the honest version arriving later by inv would
    // be ignored as already-rejected - the very lockout this closes.
    //
    // criticalData is outside the txid, so a copy of an honest bid with
    // different criticalData has the SAME txid. The commitment is inside what
    // the bidder signed, so a transaction carrying it is a BMM request and
    // nothing else: it must carry criticalData that parses as one, and whose
    // h* matches. Corruption-possible for the same reason as the mismatch
    // reject.
    {
        uint256 hashCommit;
        bool fBidCommit = false;
        for (const CTxOut& txout : tx.vout) {
            if (txout.scriptPubKey.IsBMMBidCommit(hashCommit)) {
                fBidCommit = true;
                break;
            }
        }
        if (fBidCommit) {
            uint8_t nCommitSlot;
            std::string strCommitPrev = "";
            if (!fCriticalData || !tx.criticalData.IsBMMRequest(nCommitSlot, strCommitPrev))
                return state.DoS(0, false, REJECT_INVALID, "bmm-bid-commit-mismatch", true);
            if (hashCommit != tx.criticalData.hashCritical)
                return state.DoS(0, false, REJECT_INVALID, "bmm-critical-data-mismatch", true);
        }
    }

    // TODO enable after fixing unit tests to properly activate sidechain for
    // mempool tests.
    // Reject BMM request with invalid nSidechain

    // Rather not work on nonstandard transactions (unless -testnet/-regtest)
    //
    // The small-block flag is keyed on the height of the NEXT block - the
    // earliest one this transaction could be mined in - not on the tip, so a
    // transaction is held to the rule of the first block that could carry it.
    // That is the same height the miner and getblocktemplate use.
    const bool smallBlockEnabled =
        (chainActive.Height() + 1) >= chainparams.GetConsensus().SmallBlockHeight;
    std::string reason;
    // the small-block size is measured on the wire,
    // criticalData included, but criticalData is outside the txid. A peer
    // can pad an honest v3 transaction's criticalData over the limit; if
    // that reject were cached in recentRejects by txid, the honest copy
    // would be locked out until the next block. So a size reject of a
    // transaction that carries criticalData is corruption-possible (never
    // cached); every other reject is unchanged.
    const bool fSizeRejectMalleable = !tx.criticalData.IsNull();
    if (fRequireStandard && !IsStandardTx(tx, reason, witnessEnabled, skydogeEnabled, smallBlockEnabled))
        return state.DoS(0, false, REJECT_NONSTANDARD, reason,
                         reason == "tx-size-small-block" && fSizeRejectMalleable);

    // The small-block size cap is not a matter of standardness: once the next
    // block is bound by MAX_SMALL_BLOCK_SERIALIZED_SIZE a transaction over
    // MAX_STANDARD_TX_SMALL_BLOCK_SIZE cannot be mined at any fee, so it is
    // refused on every node, including those that run with fRequireStandard
    // off (the testnet and regtest default, -acceptnonstdtxn). Living only in
    // IsStandardTx it was skipped there: such a node took the transaction
    // back after the flag-day purge and reloaded it from mempool.dat on every
    // restart, until the 14-day expiry. Same measure, same limit, same reject
    // reason and score as the IsStandardTx test above, which already answered
    // for a node that requires standard transactions - so nothing changes
    // there. LoadMempool and the reorg resurrection path come through here
    // too. Mempool policy only: block validity does not consult this.
    if (smallBlockEnabled &&
            ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION) > MAX_STANDARD_TX_SMALL_BLOCK_SIZE)
        return state.DoS(0, false, REJECT_NONSTANDARD, "tx-size-small-block", fSizeRejectMalleable);

    // Only accept nLockTime-using transactions that can be mined in the next
    // block; we don't want our mempool filled up with transactions that can't
    // be mined yet.
    if (!CheckFinalTx(tx, STANDARD_LOCKTIME_VERIFY_FLAGS))
        return state.DoS(0, false, REJECT_NONSTANDARD, "non-final");

    // is it already in the memory pool?
    if (pool.exists(hash)) {
        return state.Invalid(false, REJECT_DUPLICATE, "txn-already-in-mempool");
    }

    // Sidechain deposit / withdraw checks
    bool fCTIPUpdated = false;
    std::map<uint8_t, SidechainCTIP> mapCTIPCopy;
    mapCTIPCopy = mempool.mapLastSidechainDeposit;
    bool fBurnFound = false;
    // Initialised because it is copied into the mempool entry below whether or
    // not this transaction turns out to be a deposit. The entry only reads it
    // back when the deposit flag beside it is set, so the value is never used
    // - but it is passed by value on every accept, and reading an
    // uninitialised one to do that is undefined however harmless the result.
    uint8_t nSidechain = 0;
    if (skydogeEnabled)
    {
        // Get values to and from sidechain
        CCoinsViewMemPool poolCoins(pcoinsTip.get(), pool);
        CAmount amountSidechainIn = CAmount(0);
        CAmount amountIn = CAmount(0);
        CAmount amountSidechainOut = CAmount(0);
        CAmount amountWithdrawn = CAmount(0);
        std::string strFail = "";
        if (!GetDrivechainAmounts(poolCoins, tx, amountSidechainIn, amountIn,
                    amountSidechainOut, amountWithdrawn, strFail)) {
            return state.DoS(0, false, REJECT_INVALID, "get-drivechain-amounts: " + strFail);
        }

        // A treasury output worth ZERO is refused at relay, and from the fork
        // height by consensus as well (bad-sidechain-zero-value-escrow).
        if (!fDrivechainPolicyBypass) {
            for (const CTxOut& out : tx.vout) {
                uint8_t nSidechainOut = 0;
                if (out.scriptPubKey.IsDrivechain(nSidechainOut) && out.nValue == 0)
                    return state.DoS(0, false, REJECT_NONSTANDARD, "sidechain-zero-value-escrow");
            }
        }

        if (amountSidechainIn > amountSidechainOut) {
            // M6 Withdrawal

            // Block sidechain withdrawals (Withdrawal(s)) from the memory pool.
            // When a Withdrawal has sufficient workscore it can be added to a block
            // by miners. Workscore is verified when the block is connected.
            return state.DoS(100, false, REJECT_INVALID, "sidechain-withdraw-loose");
        } else if (amountSidechainOut > amountSidechainIn) {
            // M5 Deposit

            // Find deposit burn output & OP_RETURN output with destination.
            // Note that the first OP_RETURN output in a deposit txn will always
            // be taken as the destination and others should be ignored.
            COutPoint outpoint;
            bool fDestOutput = false;
            for (size_t i = 0; i < tx.vout.size(); i++) {
                const CScript &scriptPubKey = tx.vout[i].scriptPubKey;
                if (!scriptPubKey.size())
                    continue;

                if (scriptPubKey.IsDrivechain(nSidechain)) {
                    if (fBurnFound) {
                        // If we already found the burn output, finding another
                        // makes the transaction invalid
                        return state.DoS(0, false, REJECT_INVALID, "sidechain-deposit-invalid-multiple-burn-outputs");
                    }

                    // We found the deposit burn output
                    fBurnFound = true;

                    // Copy output index of deposit and move on
                    outpoint.n = i;
                    outpoint.hash = tx.GetHash();

                    continue;
                }

                if (!fDestOutput && scriptPubKey.front() == OP_RETURN) {
                    if (scriptPubKey.size() < 3)
                        return state.DoS(0, false, REJECT_INVALID, "sidechain-deposit-invalid-dest-op-return-too-short");

                    if (scriptPubKey.size() > MAX_DEPOSIT_DESTINATION_BYTES)
                        return state.DoS(0, false, REJECT_INVALID, "sidechain-deposit-invalid-dest-op-return-too-large");

                    CScript::const_iterator pDest = scriptPubKey.begin() + 1;
                    opcodetype opcode;
                    std::vector<unsigned char> vch;
                    if (!scriptPubKey.GetOp(pDest, opcode, vch) || vch.empty())
                        return state.DoS(0, false, REJECT_INVALID, "sidechain-deposit-invalid-dest-getop-failed");

                    std::string strDest((const char*)vch.data(), vch.size());
                    if (strDest == SIDECHAIN_WITHDRAWAL_RETURN_DEST)
                        return state.DoS(0, false, REJECT_INVALID, "sidechain-deposit-invalid-dest-sidechain-withdrawal-return-dest");

                    fDestOutput = true;
                }
            }

            if (!fBurnFound)
                return state.DoS(0, false, REJECT_INVALID, "sidechain-deposit-invalid-no-sidechain-output");

            if (!fDestOutput)
                return state.DoS(0, false, REJECT_INVALID, "sidechain-deposit-invalid-no-destination-opreturn-output");

            // Check nSidechain
            if (!scdb.IsSidechainActive(nSidechain))
                return state.DoS(0, false, REJECT_INVALID, "sidechain-deposit-invalid-sidechain-number");

            // Check that CTIP input was spent if there is one.
            //
            // The mempool copy is absent whenever this node's deposit cache is
            // empty or stale, and skipping the check in that case fails open:
            // a deposit that does not extend the treasury relays, is mined, and
            // starts a second treasury chain that can never be merged back,
            // because a transaction may carry only one sidechain input. Fall
            // back to the sidechain database so the rule fails closed. This is
            // the relay-side copy; from the fork height consensus enforces
            // continuity too (CheckDepositContinuity).
            SidechainCTIP ctipKnown;
            bool fHaveCTIP = false;
            auto it = mempool.mapLastSidechainDeposit.find(nSidechain);
            if (it != mempool.mapLastSidechainDeposit.end()) {
                ctipKnown = it->second;
                fHaveCTIP = true;
            } else if (scdb.GetCTIP(nSidechain, ctipKnown)) {
                fHaveCTIP = true;
            }
            if (fHaveCTIP) {
                int nCTIPSpent = 0;
                const COutPoint out = ctipKnown.out;
                for (const CTxIn& in : tx.vin) {
                    if (in.prevout == out)
                        nCTIPSpent++;
                }
                // -drivechainpolicybypass lets this through, and only this
                // node's own copy of the rule: a deposit that does not extend
                // the treasury is exactly what a test needs in a block to
                // find out whether consensus catches it, and no other route
                // into a block exists in-tree. Regtest only, refused at
                // startup everywhere else.
                if (nCTIPSpent != 1 && !fDrivechainPolicyBypass) {
                    LogPrintf("%s: Reject sidechain deposit - invalid CTIP spend!\n", __func__);
                    return state.DoS(0, false, REJECT_INVALID, "sidechain-deposit-invalid-ctip-unspent");
                }
            }

            // Track new sidechain CTIP - but don't actually update the mempool
            // until all other checks have passed.
            SidechainCTIP ctip;
            ctip.out = outpoint;
            ctip.amount = amountSidechainOut;
            mapCTIPCopy[nSidechain] = ctip;
            fCTIPUpdated = true;
        } else if (!fDrivechainPolicyBypass && (amountSidechainIn > 0 || SpendsDrivechainCoin(poolCoins, tx))) {
            // A transaction whose drivechain input and output values are EQUAL
            // is neither a withdrawal nor a deposit, and ConnectBlock's whole
            // drivechain branch is behind a strict inequality that such a
            // transaction fails; relay refuses it here, and from the fork
            // height consensus does too (the destination and continuity
            // rules). -drivechainpolicybypass lets it through on regtest only,
            // so a test can see what consensus does with it; the flag is
            // refused at startup on every other network.
            //
            // DoS(100) bans the peer that relayed it.
            // That was right for the case this rule always covered (drivechain
            // value in, every release refuses it, so no honest peer relays
            // one). This release added the ZERO-value treasury-coin spend, which every
            // earlier release accepts and relays as an ordinary transaction -
            // banning for it would cut each upgraded node off from every
            // not-yet-upgraded peer that forwards one (a network split during the
            // fork window). That case is refused as non-standard, no ban.
            if (amountSidechainIn == 0)
                return state.DoS(0, false, REJECT_NONSTANDARD, "sidechain-invalid-ctip-spend");
            return state.DoS(100, false, REJECT_INVALID, "sidechain-invalid-ctip-spend");
        }
    }

    // Check for conflicts with in-memory transactions
    std::set<uint256> setConflicts;
    for (const CTxIn &txin : tx.vin)
    {
        auto itConflicting = pool.mapNextTx.find(txin.prevout);
        if (itConflicting != pool.mapNextTx.end())
        {
            const CTransaction *ptxConflicting = itConflicting->second;
            if (!setConflicts.count(ptxConflicting->GetHash()))
            {
                // Allow opt-out of transaction replacement by setting
                // nSequence > MAX_BIP125_RBF_SEQUENCE (SEQUENCE_FINAL-2) on all inputs.
                //
                // SEQUENCE_FINAL-1 is picked to still allow use of nLockTime by
                // non-replaceable transactions. All inputs rather than just one
                // is for the sake of multi-party protocols, where we don't
                // want a single party to be able to disable replacement.
                //
                // The opt-out ignores descendants as anyone relying on
                // first-seen mempool behavior should be checking all
                // unconfirmed ancestors anyway; doing otherwise is hopelessly
                // insecure.
                bool fReplacementOptOut = true;
                if (fEnableReplacement)
                {
                    for (const CTxIn &_txin : ptxConflicting->vin)
                    {
                        if (_txin.nSequence <= MAX_BIP125_RBF_SEQUENCE)
                        {
                            fReplacementOptOut = false;
                            break;
                        }
                    }
                }
                if (fReplacementOptOut) {
                    return state.Invalid(false, REJECT_DUPLICATE, "txn-mempool-conflict");
                }

                setConflicts.insert(ptxConflicting->GetHash());
            }
        }
    }

    {
        CCoinsView dummy;
        CCoinsViewCache view(&dummy);

        LockPoints lp;
        CCoinsViewMemPool viewMemPool(pcoinsTip.get(), pool);
        view.SetBackend(viewMemPool);

        // do all inputs exist?
        for (const CTxIn txin : tx.vin) {
            if (!pcoinsTip->HaveCoinInCache(txin.prevout)) {
                coins_to_uncache.push_back(txin.prevout);
            }
            if (!view.HaveCoin(txin.prevout)) {
                // Are inputs missing because we already have the tx?
                for (size_t out = 0; out < tx.vout.size(); out++) {
                    // Optimistically just do efficient check of cache for outputs
                    if (pcoinsTip->HaveCoinInCache(COutPoint(hash, out))) {
                        return state.Invalid(false, REJECT_DUPLICATE, "txn-already-known");
                    }
                }
                // Otherwise assume this might be an orphan tx for which we just haven't seen parents yet
                if (pfMissingInputs) {
                    *pfMissingInputs = true;
                    LogPrintf("%s: Transaction missing inputs. Hash=%s\n", __func__, hash.ToString());
                }
                return false; // fMissingInputs and !state.IsInvalid() is used to detect this condition, don't set state.Invalid()
            }
        }

        // Bring the best block into scope
        view.GetBestBlock();

        // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
        view.SetBackend(dummy);

        // Only accept BIP68 sequence locked transactions that can be mined in the next
        // block; we don't want our mempool filled up with transactions that can't
        // be mined yet.
        // Must keep pool.cs for this unless we change CheckSequenceLocks to take a
        // CoinsViewCache instead of create its own
        if (!CheckSequenceLocks(tx, STANDARD_LOCKTIME_VERIFY_FLAGS, &lp))
            return state.DoS(0, false, REJECT_NONSTANDARD, "non-BIP68-final");

        CAmount nFees = 0;
        if (!Consensus::CheckTxInputs(tx, state, view, GetSpendHeight(view), nFees)) {
            return error("%s: Consensus::CheckTxInputs: %s, %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (fRequireStandard && !AreInputsStandard(tx, view))
            return state.Invalid(false, REJECT_NONSTANDARD, "bad-txns-nonstandard-inputs");

        // Check for non-standard witness in P2WSH
        if (tx.HasWitness() && fRequireStandard && !IsWitnessStandard(tx, view))
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-witness-nonstandard", true);

        int64_t nSigOpsCost = GetTransactionSigOpCost(tx, view, STANDARD_SCRIPT_VERIFY_FLAGS);

        // nModifiedFees includes any fee deltas from PrioritiseTransaction
        CAmount nModifiedFees = nFees;
        pool.ApplyDelta(hash, nModifiedFees);

        // Keep track of transactions that spend a coinbase, which we re-scan
        // during reorgs to ensure COINBASE_MATURITY is still met.
        bool fSpendsCoinbase = false;
        for (const CTxIn &txin : tx.vin) {
            const Coin &coin = view.AccessCoin(txin.prevout);
            if (coin.IsCoinBase()) {
                fSpendsCoinbase = true;
                break;
            }
        }


        CTxMemPoolEntry entry(ptx, nFees, nAcceptTime, chainActive.Height(),
                              fSpendsCoinbase, fBurnFound, nSidechain,
                              nSigOpsCost, lp);
        unsigned int nSize = entry.GetTxSize();

        // Check that the transaction doesn't have an excessive number of
        // sigops, making it impossible to mine. Since the coinbase transaction
        // itself can contain sigops MAX_STANDARD_TX_SIGOPS is less than
        // MAX_BLOCK_SIGOPS; we still consider this an invalid rather than
        // merely non-standard transaction.
        if (nSigOpsCost > MAX_STANDARD_TX_SIGOPS_COST)
            return state.DoS(0, false, REJECT_NONSTANDARD, "bad-txns-too-many-sigops", false,
                strprintf("%d", nSigOpsCost));

        CAmount mempoolRejectFee = pool.GetMinFee(gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFee(nSize);
        if (!bypass_limits && mempoolRejectFee > 0 && nModifiedFees < mempoolRejectFee) {
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool min fee not met", false, strprintf("%d < %d", nFees, mempoolRejectFee));
        }

        // No transactions are allowed below minRelayTxFee except from disconnected blocks
        if (!bypass_limits && nModifiedFees < ::minRelayTxFee.GetFee(nSize)) {
            return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "min relay fee not met");
        }

        if (nAbsurdFee && nFees > nAbsurdFee)
            return state.Invalid(false,
                REJECT_HIGHFEE, "absurdly-high-fee",
                strprintf("%d > %d", nFees, nAbsurdFee));

        // Calculate in-mempool ancestors, up to a limit.
        CTxMemPool::setEntries setAncestors;
        size_t nLimitAncestors = gArgs.GetArg("-limitancestorcount", DEFAULT_ANCESTOR_LIMIT);
        size_t nLimitAncestorSize = gArgs.GetArg("-limitancestorsize", DEFAULT_ANCESTOR_SIZE_LIMIT)*1000;
        size_t nLimitDescendants = gArgs.GetArg("-limitdescendantcount", DEFAULT_DESCENDANT_LIMIT);
        size_t nLimitDescendantSize = gArgs.GetArg("-limitdescendantsize", DEFAULT_DESCENDANT_SIZE_LIMIT)*1000;
        std::string errString;
        if (!pool.CalculateMemPoolAncestors(entry, setAncestors, nLimitAncestors, nLimitAncestorSize, nLimitDescendants, nLimitDescendantSize, errString)) {
            return state.DoS(0, false, REJECT_NONSTANDARD, "too-long-mempool-chain", false, errString);
        }

        // A transaction that spends outputs that would be replaced by it is invalid. Now
        // that we have the set of all ancestors we can detect this
        // pathological case by making sure setConflicts and setAncestors don't
        // intersect.
        for (CTxMemPool::txiter ancestorIt : setAncestors)
        {
            const uint256 &hashAncestor = ancestorIt->GetTx().GetHash();
            if (setConflicts.count(hashAncestor))
            {
                return state.DoS(10, false,
                                 REJECT_INVALID, "bad-txns-spends-conflicting-tx", false,
                                 strprintf("%s spends conflicting transaction %s",
                                           hash.ToString(),
                                           hashAncestor.ToString()));
            }
        }

        // Check if it's economically rational to mine this transaction rather
        // than the ones it replaces.
        CAmount nConflictingFees = 0;
        size_t nConflictingSize = 0;
        uint64_t nConflictingCount = 0;
        CTxMemPool::setEntries allConflicting;

        // If we don't hold the lock allConflicting might be incomplete; the
        // subsequent RemoveStaged() and addUnchecked() calls don't guarantee
        // mempool consistency for us.
        const bool fReplacementTransaction = setConflicts.size();
        if (fReplacementTransaction)
        {
            CFeeRate newFeeRate(nModifiedFees, nSize);
            std::set<uint256> setConflictsParents;
            const int maxDescendantsToVisit = 100;
            CTxMemPool::setEntries setIterConflicting;
            for (const uint256 &hashConflicting : setConflicts)
            {
                CTxMemPool::txiter mi = pool.mapTx.find(hashConflicting);
                if (mi == pool.mapTx.end())
                    continue;

                // Save these to avoid repeated lookups
                setIterConflicting.insert(mi);

                // Don't allow the replacement to reduce the feerate of the
                // mempool.
                //
                // We usually don't want to accept replacements with lower
                // feerates than what they replaced as that would lower the
                // feerate of the next block. Requiring that the feerate always
                // be increased is also an easy-to-reason about way to prevent
                // DoS attacks via replacements.
                //
                // The mining code doesn't (currently) take children into
                // account (CPFP) so we only consider the feerates of
                // transactions being directly replaced, not their indirect
                // descendants. While that does mean high feerate children are
                // ignored when deciding whether or not to replace, we do
                // require the replacement to pay more overall fees too,
                // mitigating most cases.
                CFeeRate oldFeeRate(mi->GetModifiedFee(), mi->GetTxSize());
                if (newFeeRate <= oldFeeRate)
                {
                    return state.DoS(0, false,
                            REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                            strprintf("rejecting replacement %s; new feerate %s <= old feerate %s",
                                  hash.ToString(),
                                  newFeeRate.ToString(),
                                  oldFeeRate.ToString()));
                }

                for (const CTxIn &txin : mi->GetTx().vin)
                {
                    setConflictsParents.insert(txin.prevout.hash);
                }

                nConflictingCount += mi->GetCountWithDescendants();
            }
            // This potentially overestimates the number of actual descendants
            // but we just want to be conservative to avoid doing too much
            // work.
            if (nConflictingCount <= maxDescendantsToVisit) {
                // If not too many to replace, then calculate the set of
                // transactions that would have to be evicted
                for (CTxMemPool::txiter it : setIterConflicting) {
                    pool.CalculateDescendants(it, allConflicting);
                }
                for (CTxMemPool::txiter it : allConflicting) {
                    nConflictingFees += it->GetModifiedFee();
                    nConflictingSize += it->GetTxSize();
                }
            } else {
                return state.DoS(0, false,
                        REJECT_NONSTANDARD, "too many potential replacements", false,
                        strprintf("rejecting replacement %s; too many potential replacements (%d > %d)\n",
                            hash.ToString(),
                            nConflictingCount,
                            maxDescendantsToVisit));
            }

            for (unsigned int j = 0; j < tx.vin.size(); j++)
            {
                // We don't want to accept replacements that require low
                // feerate junk to be mined first. Ideally we'd keep track of
                // the ancestor feerates and make the decision based on that,
                // but for now requiring all new inputs to be confirmed works.
                if (!setConflictsParents.count(tx.vin[j].prevout.hash))
                {
                    // Rather than check the UTXO set - potentially expensive -
                    // it's cheaper to just check if the new input refers to a
                    // tx that's in the mempool.
                    if (pool.mapTx.find(tx.vin[j].prevout.hash) != pool.mapTx.end())
                        return state.DoS(0, false,
                                         REJECT_NONSTANDARD, "replacement-adds-unconfirmed", false,
                                         strprintf("replacement %s adds unconfirmed input, idx %d",
                                                  hash.ToString(), j));
                }
            }

            // The replacement must pay greater fees than the transactions it
            // replaces - if we did the bandwidth used by those conflicting
            // transactions would not be paid for.
            if (nModifiedFees < nConflictingFees)
            {
                return state.DoS(0, false,
                                 REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                                 strprintf("rejecting replacement %s, less fees than conflicting txs; %s < %s",
                                          hash.ToString(), FormatMoney(nModifiedFees), FormatMoney(nConflictingFees)));
            }

            // Finally in addition to paying more fees than the conflicts the
            // new transaction must pay for its own bandwidth.
            CAmount nDeltaFees = nModifiedFees - nConflictingFees;
            if (nDeltaFees < ::incrementalRelayFee.GetFee(nSize))
            {
                return state.DoS(0, false,
                        REJECT_INSUFFICIENTFEE, "insufficient fee", false,
                        strprintf("rejecting replacement %s, not enough additional fees to relay; %s < %s",
                              hash.ToString(),
                              FormatMoney(nDeltaFees),
                              FormatMoney(::incrementalRelayFee.GetFee(nSize))));
            }
        }

        unsigned int scriptVerifyFlags = STANDARD_SCRIPT_VERIFY_FLAGS;
        if (!chainparams.RequireStandard()) {
            scriptVerifyFlags = gArgs.GetArg("-promiscuousmempoolflags", scriptVerifyFlags);
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        PrecomputedTransactionData txdata(tx);
        if (!CheckInputs(tx, state, view, true, scriptVerifyFlags, true, false, txdata)) {
            // SCRIPT_VERIFY_CLEANSTACK requires SCRIPT_VERIFY_WITNESS, so we
            // need to turn both off, and compare against just turning off CLEANSTACK
            // to see if the failure is specifically due to witness validation.
            CValidationState stateDummy; // Want reported failures to be from first CheckInputs
            if (!tx.HasWitness() && CheckInputs(tx, stateDummy, view, true, scriptVerifyFlags & ~(SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_CLEANSTACK), true, false, txdata) &&
                !CheckInputs(tx, stateDummy, view, true, scriptVerifyFlags & ~SCRIPT_VERIFY_CLEANSTACK, true, false, txdata)) {
                // Only the witness is missing, so the transaction itself may be fine.
                state.SetCorruptionPossible();
            }
            return false; // state filled in by CheckInputs
        }

        // Check again against the current block tip's script verification
        // flags to cache our script execution flags. This is, of course,
        // useless if the next block has different script flags from the
        // previous one, but because the cache tracks script flags for us it
        // will auto-invalidate and we'll just have a few blocks of extra
        // misses on soft-fork activation.
        //
        // This is also useful in case of bugs in the standard flags that cause
        // transactions to pass as valid when they're actually invalid. For
        // instance the STRICTENC flag was incorrectly allowing certain
        // CHECKSIG NOT scripts to pass, even though they were invalid.
        //
        // There is a similar check in CreateNewBlock() to prevent creating
        // invalid blocks (using TestBlockValidity), however allowing such
        // transactions into the mempool can be exploited as a DoS attack.
        unsigned int currentBlockScriptVerifyFlags = GetBlockScriptFlags(chainActive.Tip(), Params().GetConsensus());
        if (!CheckInputsFromMempoolAndCache(tx, state, view, pool, currentBlockScriptVerifyFlags, true, txdata))
        {
            // If we're using promiscuousmempoolflags, we may hit this normally
            // Check if current block has some flags that scriptVerifyFlags
            // does not before printing an ominous warning
            if (!(~scriptVerifyFlags & currentBlockScriptVerifyFlags)) {
                return error("%s: BUG! PLEASE REPORT THIS! ConnectInputs failed against latest-block but not STANDARD flags %s, %s",
                    __func__, hash.ToString(), FormatStateMessage(state));
            } else {
                if (!CheckInputs(tx, state, view, true, MANDATORY_SCRIPT_VERIFY_FLAGS, true, false, txdata)) {
                    return error("%s: ConnectInputs failed against MANDATORY but not STANDARD flags due to promiscuous mempool %s, %s",
                        __func__, hash.ToString(), FormatStateMessage(state));
                } else {
                    LogPrintf("Warning: -promiscuousmempool flags set to not include currently enforced soft forks, this may break mining or otherwise cause instability!\n");
                }
            }
        }

        // Remove conflicting transactions from the mempool
        for (const CTxMemPool::txiter it : allConflicting)
        {
            LogPrint(BCLog::MEMPOOL, "replacing tx %s with %s for %s SKYDOGE additional fees, %d delta bytes\n",
                    it->GetTx().GetHash().ToString(),
                    hash.ToString(),
                    FormatMoney(nModifiedFees - nConflictingFees),
                    (int)nSize - (int)nConflictingSize);
            if (plTxnReplaced)
                plTxnReplaced->push_back(it->GetSharedTx());
        }
        pool.RemoveStaged(allConflicting, false, MemPoolRemovalReason::REPLACED);

        // This transaction should only count for fee estimation if:
        // - it isn't a BIP 125 replacement transaction (may not be widely supported)
        // - it's not being readded during a reorg which bypasses typical mempool fee limits
        // - the node is not behind
        // - the transaction is not dependent on any other transactions in the mempool
        bool validForFeeEstimation = !fReplacementTransaction && !bypass_limits && IsCurrentForFeeEstimation() && pool.HasNoInputsOf(tx);

        // Store transaction in memory
        pool.addUnchecked(hash, entry, setAncestors, validForFeeEstimation);

        // trim mempool and check if tx was trimmed
        if (!bypass_limits) {
            LimitMempoolSize(pool, gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000, gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60);
            if (!pool.exists(hash))
                return state.DoS(0, false, REJECT_INSUFFICIENTFEE, "mempool full");
        }
    }
    if (fCTIPUpdated) {
        LogPrintf("%s: mapLastSidechainDeposit updated!\n", __func__);
        mempool.UpdateCTIPFromMempool(mapCTIPCopy);
    }

    GetMainSignals().TransactionAddedToMempool(ptx);

    return true;
}

/** (try to) add transaction to memory pool with a specified acceptance time **/
static bool AcceptToMemoryPoolWithTime(const CChainParams& chainparams, CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx,
                        bool* pfMissingInputs, int64_t nAcceptTime, std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee)
{
    std::vector<COutPoint> coins_to_uncache;
    bool res = AcceptToMemoryPoolWorker(chainparams, pool, state, tx, pfMissingInputs, nAcceptTime, plTxnReplaced, bypass_limits, nAbsurdFee, coins_to_uncache);
    if (!res) {
        for (const COutPoint& hashTx : coins_to_uncache)
            pcoinsTip->Uncache(hashTx);
    }
    // After we've (potentially) uncached entries, ensure our coins cache is still within its size limits
    CValidationState stateDummy;
    FlushStateToDisk(chainparams, stateDummy, FLUSH_STATE_PERIODIC);
    return res;
}

bool AcceptToMemoryPool(CTxMemPool& pool, CValidationState &state, const CTransactionRef &tx,
                        bool* pfMissingInputs, std::list<CTransactionRef>* plTxnReplaced,
                        bool bypass_limits, const CAmount nAbsurdFee)
{
    const CChainParams& chainparams = Params();
    return AcceptToMemoryPoolWithTime(chainparams, pool, state, tx, pfMissingInputs, GetTime(), plTxnReplaced, bypass_limits, nAbsurdFee);
}

/**
 * Return transaction in txOut, and if it was found inside a block, its hash is placed in hashBlock.
 * If blockIndex is provided, the transaction is fetched from the corresponding block.
 */
bool GetTransaction(const uint256& hash, CTransactionRef& txOut, const Consensus::Params& consensusParams, uint256& hashBlock, bool fAllowSlow, CBlockIndex* blockIndex)
{
    CBlockIndex* pindexSlow = blockIndex;

    LOCK(cs_main);

    if (!blockIndex) {
        CTransactionRef ptx = mempool.get(hash);
        if (ptx) {
            txOut = ptx;
            return true;
        }

        if (fTxIndex) {
            CDiskTxPos postx;
            if (pblocktree->ReadTxIndex(hash, postx)) {
                CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
                if (file.IsNull())
                    return error("%s: OpenBlockFile failed", __func__);
                CBlockHeader header;
                try {
                    file >> header;
                    fseek(file.Get(), postx.nTxOffset, SEEK_CUR);
                    file >> txOut;
                } catch (const std::exception& e) {
                    return error("%s: Deserialize or I/O error - %s", __func__, e.what());
                }
                hashBlock = header.GetHash();
                if (txOut->GetHash() != hash)
                    return error("%s: txid mismatch", __func__);
                return true;
            }

            // transaction not found in index, nothing more can be done
            return false;
        }

        if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
            const Coin& coin = AccessByTxid(*pcoinsTip, hash);
            if (!coin.IsSpent()) pindexSlow = chainActive[coin.nHeight];
        }
    }

    if (pindexSlow) {
        CBlock block;
        if (ReadBlockFromDisk(block, pindexSlow, consensusParams)) {
            for (const auto& tx : block.vtx) {
                if (tx->GetHash() == hash) {
                    txOut = tx;
                    hashBlock = pindexSlow->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}






//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static bool WriteBlockToDisk(const CBlock& block, CDiskBlockPos& pos, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenBlockFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("WriteBlockToDisk: OpenBlockFile failed");

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, block);
    fileout << FLATDATA(messageStart) << nSize;

    // Write block
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("WriteBlockToDisk: ftell failed");
    pos.nPos = (unsigned int)fileOutPos;
    fileout << block;

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CDiskBlockPos& pos, const Consensus::Params& consensusParams)
{
    block.SetNull();

    // Open history file to read
    CAutoFile filein(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("ReadBlockFromDisk: OpenBlockFile failed for %s", pos.ToString());

    // Read block
    try {
        filein >> block;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s at %s", __func__, e.what(), pos.ToString());
    }

    // Check the header
    if (!CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return error("ReadBlockFromDisk: Errors in block header at %s", pos.ToString());

    return true;
}

bool ReadBlockFromDisk(CBlock& block, const CBlockIndex* pindex, const Consensus::Params& consensusParams)
{
    CDiskBlockPos blockPos;
    {
        LOCK(cs_main);
        blockPos = pindex->GetBlockPos();
    }

    if (!ReadBlockFromDisk(block, blockPos, consensusParams))
        return false;
    if (block.GetHash() != pindex->GetBlockHash())
        return error("ReadBlockFromDisk(CBlock&, CBlockIndex*): GetHash() doesn't match index for %s at %s",
                pindex->ToString(), pindex->GetBlockPos().ToString());
    return true;
}

CAmount GetBlockSubsidy(int nHeight, const Consensus::Params& consensusParams)
{
    int halvings = nHeight / consensusParams.nSubsidyHalvingInterval;
    // Force block reward to zero when right shift is undefined.
    if (halvings >= 64)
        return 0;

    if(halvings > 4){
        halvings = 4;
    }
    if(nHeight == 2){
        return 10000000000 * COIN;
    }
    if(nHeight > 9450000){
        return 0;
    }

    CAmount nSubsidy = 50000 * COIN;
    // Subsidy is cut in half every 2.100,000 blocks which will occur approximately every 4 years.
    nSubsidy >>= halvings;
    return nSubsidy;
}
bool IsInitialBlockDownload()
{
    // Once this function has returned false, it must remain false.
    static std::atomic<bool> latchToFalse{false};
    // Optimization: pre-test latch before taking the lock.
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;

    LOCK(cs_main);
    if (latchToFalse.load(std::memory_order_relaxed))
        return false;
    if (fImporting || fReindex)
        return true;
    if (chainActive.Tip() == nullptr)
        return true;
    if (chainActive.Tip()->nChainWork < nMinimumChainWork)
        return true;
    if (chainActive.Tip()->GetBlockTime() < (GetTime() - nMaxTipAge))
        return true;
    LogPrintf("Leaving InitialBlockDownload (latching to false)\n");
    latchToFalse.store(true, std::memory_order_relaxed);
    return false;
}

CBlockIndex *pindexBestForkTip = nullptr, *pindexBestForkBase = nullptr;

static void AlertNotify(const std::string& strMessage)
{
    uiInterface.NotifyAlertChanged();
    std::string strCmd = gArgs.GetArg("-alertnotify", "");
    if (strCmd.empty()) return;

    // Alert text should be plain ascii coming from a trusted source, but to
    // be safe we first strip anything not in safeChars, then add single quotes around
    // the whole string before passing it to the shell:
    std::string singleQuote("'");
    std::string safeStatus = SanitizeString(strMessage);
    safeStatus = singleQuote+safeStatus+singleQuote;
    boost::replace_all(strCmd, "%s", safeStatus);

    boost::thread t(runCommand, strCmd); // thread runs free
}

/** Warn the operator that a block was rejected on SCDB state.
 *
 * The three ConnectBlock rejects tagged bad-withdrawal-spend,
 * bad-withdrawal-spend-final and bad-scdb-update depend on this node's
 * sidechain database, not only on the block itself. If the local database is
 * what is wrong, the block still gets marked permanently invalid while the
 * rest of the network accepts it, and this node quietly stops following the
 * chain while otherwise appearing healthy. This makes that condition loud and
 * actionable; it is diagnostics only and changes nothing about the rejection.
 *
 * Callers skip this under fJustCheck: a template test rejects the proposed
 * block without marking anything in the block index, so there is nothing for
 * an operator to recover.
 *
 * The log line fires on every occurrence. The -alertnotify alert (which
 * spawns a shell per call) is rate-limited: a diverged node can hit these
 * rejects once per block arriving on the majority branch, and a burst of
 * blocks must not become a process per block. The latch is guarded by
 * cs_main, which every caller already holds.
 */
//! Log an SCDB operator alert and, at most once an hour PER KEY, raise it
//! externally.
//!
//! Rate-limited per key, not globally. A single shared latch let the first
//! divergence of any kind mute every other kind for an hour - so a
//! bad-withdrawal-spend alert would suppress a bad-scdb-commitment alert, which
//! is exactly the distinction a flag day needs an operator to see. Keys are
//! compile-time string literals, so the map holds a handful of entries at most.
//! The LogPrintf is unconditional; only the external AlertNotify is throttled.
static void AlertSCDBNotify(const char* pszKey, const std::string& strMessage)
{
    AssertLockHeld(cs_main);

    LogPrintf("%s\n", strMessage);

    static std::map<std::string, int64_t> mapLastAlert;
    const int64_t nNow = GetTime();
    int64_t& nLast = mapLastAlert[pszKey];
    if (nNow >= nLast + 60 * 60) {
        nLast = nNow;
        AlertNotify(strMessage);
    }
}

//! For a block this node REJECTED on SCDB state. Says the node may have stopped
//! following the chain, and how to recover.
//!
//! Do NOT call this from an accept path. Its text asserts a rejection, tells the
//! operator the node has stopped following the chain, and recommends
//! reconsiderblock - all three false for a block that is being connected. Use
//! AlertSCDBUnsoundRecord for that; a diagnostic that describes the wrong event
//! is worse than none, because an operator acts on it.
static void AlertSCDBDivergence(const uint256& hashBlock, const char* pszReject)
{
    AssertLockHeld(cs_main);

    const std::string strMessage = strprintf(
        "Warning: SCDB DIVERGENCE POSSIBLE: rejected block %s (%s): the sidechain "
        "database on this node disagrees with the block. If the rest of the network "
        "accepts this block, this node has stopped following the chain and will "
        "not recover on its own. Recovery: upgrade to the latest release, then "
        "run reconsiderblock %s and check getchaintips to confirm this block is "
        "no longer marked invalid (reconsiderblock returns null whether or not "
        "the block stayed reconsidered). If it is still marked invalid, restart "
        "with -reindex - a FULL -reindex: -reindex-chainstate keeps the sidechain "
        "records this node disagrees about.",
        hashBlock.ToString(), pszReject, hashBlock.ToString());

    AlertSCDBNotify(pszReject, strMessage);
}

//! For a block this node ACCEPTED while its own caches were already unsound.
//!
//! Nothing was rejected and the node is still following the chain, so this says
//! neither. What it warns about is the record just written: it states the
//! treasury of the slots this node holds a pointer for, and a slot it omits
//! loses that pointer on any later replay of this block.
//! Turn a list of slot numbers into "3" or "3, 7, 12".
static std::string SlotList(const std::vector<uint8_t>& vSlot)
{
    std::string str;
    for (size_t i = 0; i < vSlot.size(); i++)
        str += strprintf("%s%u", i ? ", " : "", vSlot[i]);
    return str;
}

//! For a block this node ACCEPTED while its own SCDB caches were already
//! inconsistent. Raised from ConnectTip, after chainActive has moved.
//!
//! Nothing was rejected and the node is still following the chain, so this says
//! neither. It reports TWO independent conditions, because they have different
//! causes and different severities and conflating them is a false diagnosis:
//!
//!  - the deposit cache does not account for the treasury pointers. The record
//!    is written from the pointers, NOT from the deposit cache, so the record
//!    is very likely fine; what is unsound is this node's deposit history.
//!  - mapTreasury disagreed with mapCTIP. That is an internal invariant break,
//!    it is repaired in the record before it can do damage, and it should be
//!    impossible - so it is reported at higher volume than the first.
static void AlertSCDBUnsoundRecord(const uint256& hashBlock, bool fCacheUnsound,
                                   uint8_t nSlotUnsupported, size_t nStated,
                                   bool fRecordNewlyWritten,
                                   const SidechainDB::TreasuryLogAudit& audit)
{
    AssertLockHeld(cs_main);

    std::string strWhat;

    if (!audit.IsClean()) {
        // The serious one, and it is reported on its own merits rather than
        // only when the deposit-cache check happens to fail as well. The two
        // conditions are independent: the lockstep can break on a node whose
        // deposit history is perfectly good, and gating this behind the other
        // check meant exactly that case produced nothing but a log line.
        strWhat += "THE TREASURY LOG DISAGREED WITH THE TREASURY POINTERS, which should be "
                   "impossible and means this node's SCDB has been corrupted in memory or by "
                   "a code defect. The record was built from the POINTERS, so it is correct "
                   "and nothing was lost - but the disagreement itself is the finding. ";
        if (!audit.vMissing.empty())
            strWhat += strprintf("No log entry for slot(s) %s. ", SlotList(audit.vMissing));
        if (!audit.vStale.empty())
            strWhat += strprintf("Log entries for slot(s) %s hold no pointer and were dropped. ",
                                 SlotList(audit.vStale));
        if (!audit.vMismatched.empty())
            strWhat += strprintf("Log entries for slot(s) %s named a different outpoint or "
                                 "amount than the pointer and were overruled. ",
                                 SlotList(audit.vMismatched));
    }

    if (fCacheUnsound) {
        strWhat += strprintf(
            "This node's deposit cache does not account for the treasury of sidechain %u. The "
            "record states %u treasury pointer(s) and is written from those pointers, not from "
            "the deposit cache, so it is NOT necessarily wrong - what is unsound is this node's "
            "deposit history behind them. Withdrawal payout selection and any rebuild read that "
            "history. ",
            nSlotUnsupported, (unsigned)nStated);
    }

    const std::string strMessage = strprintf(
        "Warning: SCDB STATE UNSOUND: this node ACCEPTED and connected block %s%s. The block is "
        "fine and this node is still following the chain - do NOT run reconsiderblock. %s"
        "Recovery: run rebuildscdb, or -reindex if that cannot repair it. Do not treat this node "
        "as a reference for a pre-flag-day SCDB census until it is clean.",
        hashBlock.ToString(),
        fRecordNewlyWritten ? " and wrote its sidechain record" : " (its sidechain record was already on disk)",
        strWhat);

    AlertSCDBNotify("scdb-state-unsound", strMessage);
}

static void CheckForkWarningConditions()
{
    AssertLockHeld(cs_main);
    // Before we get past initial download, we cannot reliably alert about forks
    // (we assume we don't get stuck on a fork before finishing our initial sync)
    if (IsInitialBlockDownload())
        return;

    // If our best fork is no longer within 72 blocks (+/- 12 hours if no one mines it)
    // of our head, drop it
    if (pindexBestForkTip && chainActive.Height() - pindexBestForkTip->nHeight >= 72)
        pindexBestForkTip = nullptr;

    if (pindexBestForkTip || (pindexBestInvalid && pindexBestInvalid->nChainWork > chainActive.Tip()->nChainWork + (GetBlockProof(*chainActive.Tip()) * 6)))
    {
        if (!GetfLargeWorkForkFound() && pindexBestForkBase)
        {
            std::string warning = std::string("'Warning: Large-work fork detected, forking after block ") +
                pindexBestForkBase->phashBlock->ToString() + std::string("'");
            AlertNotify(warning);
        }
        if (pindexBestForkTip && pindexBestForkBase)
        {
            LogPrintf("%s: Warning: Large valid fork found\n  forking the chain at height %d (%s)\n  lasting to height %d (%s).\nChain state database corruption likely.\n", __func__,
                   pindexBestForkBase->nHeight, pindexBestForkBase->phashBlock->ToString(),
                   pindexBestForkTip->nHeight, pindexBestForkTip->phashBlock->ToString());
            SetfLargeWorkForkFound(true);
        }
        else
        {
            LogPrintf("%s: Warning: Found invalid chain at least ~6 blocks longer than our best chain.\nChain state database corruption likely.\n", __func__);
            SetfLargeWorkInvalidChainFound(true);
        }
    }
    else
    {
        SetfLargeWorkForkFound(false);
        SetfLargeWorkInvalidChainFound(false);
    }
}

static void CheckForkWarningConditionsOnNewFork(CBlockIndex* pindexNewForkTip)
{
    AssertLockHeld(cs_main);
    // If we are on a fork that is sufficiently large, set a warning flag
    CBlockIndex* pfork = pindexNewForkTip;
    CBlockIndex* plonger = chainActive.Tip();
    while (pfork && pfork != plonger)
    {
        while (plonger && plonger->nHeight > pfork->nHeight)
            plonger = plonger->pprev;
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
    }

    // We define a condition where we should warn the user about as a fork of at least 7 blocks
    // with a tip within 72 blocks (+/- 12 hours if no one mines it) of ours
    // We use 7 blocks rather arbitrarily as it represents just under 10% of sustained network
    // hash rate operating on the fork.
    // or a chain that is entirely longer than ours and invalid (note that this should be detected by both)
    // We define it this way because it allows us to only store the highest fork tip (+ base) which meets
    // the 7-block condition and from this always have the most-likely-to-cause-warning fork
    if (pfork && (!pindexBestForkTip || pindexNewForkTip->nHeight > pindexBestForkTip->nHeight) &&
            pindexNewForkTip->nChainWork - pfork->nChainWork > (GetBlockProof(*pfork) * 7) &&
            chainActive.Height() - pindexNewForkTip->nHeight < 72)
    {
        pindexBestForkTip = pindexNewForkTip;
        pindexBestForkBase = pfork;
    }

    CheckForkWarningConditions();
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (!pindexBestInvalid || pindexNew->nChainWork > pindexBestInvalid->nChainWork)
        pindexBestInvalid = pindexNew;

    LogPrintf("%s: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight,
      log(pindexNew->nChainWork.getdouble())/log(2.0), DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
      pindexNew->GetBlockTime()));
    CBlockIndex *tip = chainActive.Tip();
    assert (tip);
    LogPrintf("%s:  current best=%s  height=%d  log2_work=%.8g  date=%s\n", __func__,
      tip->GetBlockHash().ToString(), chainActive.Height(), log(tip->nChainWork.getdouble())/log(2.0),
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", tip->GetBlockTime()));
    CheckForkWarningConditions();
}

void CChainState::InvalidBlockFound(CBlockIndex *pindex, const CValidationState &state) {
    if (!state.CorruptionPossible()) {
        pindex->nStatus |= BLOCK_FAILED_VALID;
        g_failed_blocks.insert(pindex);
        setDirtyBlockIndex.insert(pindex);
        setBlockIndexCandidates.erase(pindex);
        InvalidChainFound(pindex);
    }
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, CTxUndo &txundo, int nHeight, bool fJustCheck)
{
    // mark inputs spent
    if (!tx.IsCoinBase()) {
        txundo.vprevout.reserve(tx.vin.size());
        for (const CTxIn &txin : tx.vin) {
            txundo.vprevout.emplace_back();
            bool is_spent = inputs.SpendCoin(txin.prevout, fJustCheck, &txundo.vprevout.back());
            assert(is_spent);
        }
    }
    // add outputs
    AddCoins(inputs, tx, nHeight);
}

void UpdateCoins(const CTransaction& tx, CCoinsViewCache& inputs, int nHeight, bool fJustCheck)
{
    CTxUndo txundo;
    UpdateCoins(tx, inputs, txundo, nHeight, fJustCheck);
}

bool CScriptCheck::operator()() {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    const CScriptWitness *witness = &ptxTo->vin[nIn].scriptWitness;

    return VerifyScript(scriptSig, m_tx_out.scriptPubKey, witness, nFlags, CachingTransactionSignatureChecker(ptxTo, nIn, m_tx_out.nValue, cacheStore, *txdata), &error);
}

int GetSpendHeight(const CCoinsViewCache& inputs)
{
    LOCK(cs_main);
    CBlockIndex* pindexPrev = mapBlockIndex.find(inputs.GetBestBlock())->second;
    return pindexPrev->nHeight + 1;
}


static CuckooCache::cache<uint256, SignatureCacheHasher> scriptExecutionCache;
static uint256 scriptExecutionCacheNonce(GetRandHash());

void InitScriptExecutionCache() {
    // nMaxCacheSize is unsigned. If -maxsigcachesize is set to zero,
    // setup_bytes creates the minimum possible cache (2 elements).
    size_t nMaxCacheSize = std::min(std::max((int64_t)0, gArgs.GetArg("-maxsigcachesize", DEFAULT_MAX_SIG_CACHE_SIZE) / 2), MAX_MAX_SIG_CACHE_SIZE) * ((size_t) 1 << 20);
    size_t nElems = scriptExecutionCache.setup_bytes(nMaxCacheSize);
    LogPrintf("Using %zu MiB out of %zu/2 requested for script execution cache, able to store %zu elements\n",
            (nElems*sizeof(uint256)) >>20, (nMaxCacheSize*2)>>20, nElems);
}

/**
 * Check whether all inputs of this transaction are valid (no double spends, scripts & sigs, amounts)
 * This does not modify the UTXO set.
 *
 * If pvChecks is not nullptr, script checks are pushed onto it instead of being performed inline. Any
 * script checks which are not necessary (eg due to script execution cache hits) are, obviously,
 * not pushed onto pvChecks/run.
 *
 * Setting cacheSigStore/cacheFullScriptStore to false will remove elements from the corresponding cache
 * which are matched. This is useful for checking blocks where we will likely never need the cache
 * entry again.
 *
 * Non-static (and re-declared) in src/test/txvalidationcache_tests.cpp
 */
bool CheckInputs(const CTransaction& tx, CValidationState &state, const CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, bool cacheSigStore, bool cacheFullScriptStore, PrecomputedTransactionData& txdata, std::vector<CScriptCheck> *pvChecks)
{
    if (!tx.IsCoinBase())
    {
        if (pvChecks)
            pvChecks->reserve(tx.vin.size());

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip script verification when connecting blocks under the
        // assumevalid block. Assuming the assumevalid block is valid this
        // is safe because block merkle hashes are still computed and checked,
        // Of course, if an assumed valid block is invalid due to false scriptSigs
        // this optimization would allow an invalid chain to be accepted.
        if (fScriptChecks) {
            // First check if script executions have been cached with the same
            // flags. Note that this assumes that the inputs provided are
            // correct (ie that the transaction hash which is in tx's prevouts
            // properly commits to the scriptPubKey in the inputs view of that
            // transaction).
            uint256 hashCacheEntry;
            // We only use the first 19 bytes of nonce to avoid a second SHA
            // round - giving us 19 + 32 + 4 = 55 bytes (+ 8 + 1 = 64)
            static_assert(55 - sizeof(flags) - 32 >= 128/8, "Want at least 128 bits of nonce for script execution cache");
            CSHA256().Write(scriptExecutionCacheNonce.begin(), 55 - sizeof(flags) - 32).Write(tx.GetWitnessHash().begin(), 32).Write((unsigned char*)&flags, sizeof(flags)).Finalize(hashCacheEntry.begin());
            AssertLockHeld(cs_main); //TODO: Remove this requirement by making CuckooCache not require external locks
            if (scriptExecutionCache.contains(hashCacheEntry, !cacheFullScriptStore)) {
                return true;
            }

            //bool fSkydogeEnabled = IsSkydogeEnabled(chainActive.Tip(), Params().GetConsensus());

            for (unsigned int i = 0; i < tx.vin.size(); i++) {
                const COutPoint &prevout = tx.vin[i].prevout;
                const Coin& coin = inputs.AccessCoin(prevout);
                assert(!coin.IsSpent());

                // Check Critical Data tx maturity - Critical Data outputs must
                // have a block depth greater than CRITICAL_DATA_MATURITY.
                //if (fSkydogeEnabled) {
                //    if (coin.IsCriticalData()) {
                //        if ((chainActive.Height() - coin.nHeight) < CRITICAL_DATA_MATURITY) {
                //        LogPrintf("KYLO: %u\n", chainActive.Height() - coin.nHeight);
                //            return state.Invalid(false, REJECT_INVALID, "bad-block-txn-immature-critical-data");
                //        }
                //    }
                //}

                // We very carefully only pass in things to CScriptCheck which
                // are clearly committed to by tx' witness hash. This provides
                // a sanity check that our caching is not introducing consensus
                // failures through additional data in, eg, the coins being
                // spent being checked as a part of CScriptCheck.

                // Verify signature
                CScriptCheck check(coin.out, tx, i, flags, cacheSigStore, &txdata);
                if (pvChecks) {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                } else if (!check()) {
                    if (flags & STANDARD_NOT_MANDATORY_VERIFY_FLAGS) {
                        // Check whether the failure was caused by a
                        // non-mandatory script verification check, such as
                        // non-standard DER encodings or non-null dummy
                        // arguments; if so, don't trigger DoS protection to
                        // avoid splitting the network between upgraded and
                        // non-upgraded nodes.
                        CScriptCheck check2(coin.out, tx, i,
                                flags & ~STANDARD_NOT_MANDATORY_VERIFY_FLAGS, cacheSigStore, &txdata);
                        if (check2())
                            return state.Invalid(false, REJECT_NONSTANDARD, strprintf("non-mandatory-script-verify-flag (%s)", ScriptErrorString(check.GetScriptError())));
                    }
                    // Failures of other flags indicate a transaction that is
                    // invalid in new blocks, e.g. an invalid P2SH. We DoS ban
                    // such nodes as they are not following the protocol. That
                    // said during an upgrade careful thought should be taken
                    // as to the correct behavior - we may want to continue
                    // peering with non-upgraded nodes even after soft-fork
                    // super-majority signaling has occurred.
                    return state.DoS(100,false, REJECT_INVALID, strprintf("mandatory-script-verify-flag-failed (%s)", ScriptErrorString(check.GetScriptError())));
                }
            }

            if (cacheFullScriptStore && !pvChecks) {
                // We executed all of the provided scripts, and were told to
                // cache the result. Do so now.
                scriptExecutionCache.insert(hashCacheEntry);
            }
        }
    }

    return true;
}

namespace {

bool UndoWriteToDisk(const CBlockUndo& blockundo, CDiskBlockPos& pos, const uint256& hashBlock, const CMessageHeader::MessageStartChars& messageStart)
{
    // Open history file to append
    CAutoFile fileout(OpenUndoFile(pos), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Write index header
    unsigned int nSize = GetSerializeSize(fileout, blockundo);
    fileout << FLATDATA(messageStart) << nSize;

    // Write undo data
    long fileOutPos = ftell(fileout.Get());
    if (fileOutPos < 0)
        return error("%s: ftell failed", __func__);
    pos.nPos = (unsigned int)fileOutPos;
    fileout << blockundo;

    // calculate & write checksum
    CHashWriter hasher(SER_GETHASH, PROTOCOL_VERSION);
    hasher << hashBlock;
    hasher << blockundo;
    fileout << hasher.GetHash();

    return true;
}

static bool UndoReadFromDisk(CBlockUndo& blockundo, const CBlockIndex *pindex)
{
    CDiskBlockPos pos = pindex->GetUndoPos();
    if (pos.IsNull()) {
        return error("%s: no undo data available", __func__);
    }

    // Open history file to read
    CAutoFile filein(OpenUndoFile(pos, true), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull())
        return error("%s: OpenUndoFile failed", __func__);

    // Read block
    uint256 hashChecksum;
    CHashVerifier<CAutoFile> verifier(&filein); // We need a CHashVerifier as reserializing may lose data
    try {
        verifier << pindex->pprev->GetBlockHash();
        verifier >> blockundo;
        filein >> hashChecksum;
    }
    catch (const std::exception& e) {
        return error("%s: Deserialize or I/O error - %s", __func__, e.what());
    }

    // Verify checksum
    if (hashChecksum != verifier.GetHash())
        return error("%s: Checksum mismatch", __func__);

    return true;
}

/** Abort with a message */
bool AbortNode(const std::string& strMessage, const std::string& userMessage="")
{
    SetMiscWarning(strMessage);
    LogPrintf("*** %s\n", strMessage);
    uiInterface.ThreadSafeMessageBox(
        userMessage.empty() ? _("Error: A fatal internal error occurred, see debug.log for details") : userMessage,
        "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

bool AbortNode(CValidationState& state, const std::string& strMessage, const std::string& userMessage="")
{
    AbortNode(strMessage, userMessage);
    return state.Error(strMessage);
}

} // namespace

/**
 * Restore the UTXO in a Coin at a given COutPoint
 * @param undo The Coin to be restored.
 * @param view The coins view to which to apply the changes.
 * @param out The out point that corresponds to the tx input.
 * @return A DisconnectResult as an int
 */
int ApplyTxInUndo(Coin&& undo, CCoinsViewCache& view, const COutPoint& out)
{
    bool fClean = true;

    if (view.HaveCoin(out)) fClean = false; // overwriting transaction output
    if (undo.nHeight == 0) {
        // Missing undo metadata (height and coinbase). Older versions included this
        // information only in undo records for the last spend of a transactions'
        // outputs. This implies that it must be present for some other output of the same tx.
        const Coin& alternate = AccessByTxid(view, out.hash);
        if (!alternate.IsSpent()) {
            undo.nHeight = alternate.nHeight;
            undo.fCoinBase = alternate.fCoinBase;
        } else {
            return DISCONNECT_FAILED; // adding output for transaction without known metadata
        }
    }

    // The potential_overwrite parameter to AddCoin is only allowed to be false if we know for
    // sure that the coin did not already exist in the cache. As we have queried for that above
    // using HaveCoin, we don't need to guess. When fClean is false, a coin already existed and
    // it is an overwrite.
    view.AddCoin(out, std::move(undo), !fClean);

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

/** Undo the effects of this block (with given index) on the UTXO set represented by coins.
 *  When FAILED is returned, view is left in an indeterminate state. */
DisconnectResult CChainState::DisconnectBlock(const CBlock& block, const CBlockIndex* pindex, CCoinsViewCache& view)
{
    bool fClean = true;

    CBlockUndo blockUndo;
    if (!UndoReadFromDisk(blockUndo, pindex)) {
        error("DisconnectBlock(): failure reading undo data");
        return DISCONNECT_FAILED;
    }

    if (blockUndo.vtxundo.size() + 1 != block.vtx.size()) {
        error("DisconnectBlock(): block and undo data inconsistent");
        return DISCONNECT_FAILED;
    }

    // undo transactions in reverse order
    for (int i = block.vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = *(block.vtx[i]);
        uint256 hash = tx.GetHash();
        bool is_coinbase = tx.IsCoinBase();

        // Check that all outputs are available and match the outputs in the block itself
        // exactly.
        for (size_t o = 0; o < tx.vout.size(); o++) {
            if (!tx.vout[o].scriptPubKey.IsUnspendable()) {
                COutPoint out(hash, o);
                Coin coin;
                bool is_spent = view.SpendCoin(out, false, &coin);
                if (!is_spent || tx.vout[o] != coin.out || pindex->nHeight != coin.nHeight || is_coinbase != coin.fCoinBase) {
                    fClean = false; // transaction output mismatch
                }
            }
        }

        // restore inputs
        if (i > 0) { // not coinbases
            CTxUndo &txundo = blockUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size()) {
                error("DisconnectBlock(): transaction and undo data inconsistent");
                return DISCONNECT_FAILED;
            }
            for (unsigned int j = tx.vin.size(); j-- > 0;) {
                const COutPoint &out = tx.vin[j].prevout;
                int res = ApplyTxInUndo(std::move(txundo.vprevout[j]), view, out);
                if (res == DISCONNECT_FAILED) return DISCONNECT_FAILED;
                fClean = fClean && res != DISCONNECT_UNCLEAN;
            }
            // At this point, all of txundo.vprevout should have been moved out.
        }
    }

    // Roll the sidechain database back on a copy and install it only once both
    // halves have succeeded.
    //
    // Two steps are needed: load the record for the previous block, then undo
    // what this block did to the parts that record does not cover. Applied
    // straight to the global database, a failure in the second step would leave
    // it describing neither block - the coins view is still being rolled back
    // here, so the two would end up naming different blocks, and a node in that
    // state can disagree with the network about whether a later block is valid.
    // ConnectBlock already works this way, through the copy SidechainDB::Update
    // takes; this is the same discipline on the way out.
    //
    // The copy is a full one, as it is on the connect side, because Undo reads
    // the deposit cache and the sidechain table to decide what to remove.
    SidechainDB scdbCopy = scdb;

    if (!ResyncSCDBInto(scdbCopy, pindex->pprev)) {
        error("%s: Failed to re-sync SCDB for disconnected block: %s!", __func__, block.GetHash().ToString());
        return DISCONNECT_FAILED;
    }

    if (!scdbCopy.Undo(pindex->nHeight, block.GetHash(), block.GetPrevHash(), block.vtx, true /* fDebug */)) {
        error("%s: Failed to undo SCDB data for block: %s!", __func__, block.GetHash().ToString());
        return DISCONNECT_FAILED;
    }

    // The copy is only worth taking if the coins rollback agreed. DisconnectTip
    // throws its coins view away on any result other than DISCONNECT_OK and
    // leaves the tip where it was, so installing the rolled-back database here
    // would leave the two describing different blocks - which is the state this
    // copy exists to prevent, and it survives a restart. Return before the
    // install instead. The other two callers replay or verify and then re-sync
    // the database from the tip, so they lose nothing by it.
    // Move the best block pointer to the prevout block. This is the COINS
    // view's own bookkeeping and it must happen on BOTH paths, which is why
    // upstream sets it unconditionally. VerifyDB disconnects blocks in a loop
    // and opens each iteration with
    //     assert(coins.GetBestBlock() == pindex->GetBlockHash());
    // so leaving the view pointing at the block we just rolled back makes the
    // NEXT iteration abort the process - instead of letting VerifyDB report
    // the very inconsistency it exists to find. Only the SCDB install below is
    // what this early return means to withhold.
    view.SetBestBlock(pindex->pprev->GetBlockHash());

    if (!fClean)
        return DISCONNECT_UNCLEAN;

    scdb = scdbCopy;

    // Update mempool CTIP - unless this is a verification walk, which the
    // guard in VerifyDB unwinds afterwards and which must not evict anything.
    if (!fSidechainVerifying)
        mempool.UpdateCTIPFromBlock(scdb.GetCTIP(), true /* fDisconnect */);

    // Log that we have disconnected a block
    LogPrintf("%s: Block disconnected:\n%s\n", __func__, block.ToString());

    return fClean ? DISCONNECT_OK : DISCONNECT_UNCLEAN;
}

//! Flush the block and undo files, and say whether the data actually reached
//! the disk.
//!
//! The caller writes the block index and then the chainstate on the strength of
//! this having worked: both of those refer to block and undo data by file and
//! offset. If the flush is reported as done when it was not, a crash can leave a
//! chainstate that names block data the file does not contain, which no restart
//! can reconcile - only a reindex. The two steps that follow this one already
//! stop the node when they fail; this one used to be the exception.
//!
//! A file that will not open is left as it was: an empty datadir has no block
//! file to flush, and refusing to start over that would be worse than the case
//! being guarded against.
static bool FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    bool fFlushed = true;
    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE *fileOld = OpenBlockFile(posOld);
    if (fileOld) {
        if (fFinalize && !TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nSize)) {
            LogPrintf("%s: Failed to truncate block file %i\n", __func__, nLastBlockFile);
            fFlushed = false;
        }
        if (!FileCommit(fileOld)) {
            LogPrintf("%s: Failed to flush block file %i to disk\n", __func__, nLastBlockFile);
            fFlushed = false;
        }
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize && !TruncateFile(fileOld, vinfoBlockFile[nLastBlockFile].nUndoSize)) {
            LogPrintf("%s: Failed to truncate undo file %i\n", __func__, nLastBlockFile);
            fFlushed = false;
        }
        if (!FileCommit(fileOld)) {
            LogPrintf("%s: Failed to flush undo file %i to disk\n", __func__, nLastBlockFile);
            fFlushed = false;
        }
        fclose(fileOld);
    }

    return fFlushed;
}

static bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize);

static bool WriteUndoDataForBlock(const CBlockUndo& blockundo, CValidationState& state, CBlockIndex* pindex, const CChainParams& chainparams)
{
    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull()) {
        CDiskBlockPos _pos;
        if (!FindUndoPos(state, pindex->nFile, _pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
            return error("ConnectBlock(): FindUndoPos failed");
        if (!UndoWriteToDisk(blockundo, _pos, pindex->pprev->GetBlockHash(), chainparams.MessageStart()))
            return AbortNode(state, "Failed to write undo data");

        // update nUndoPos in block index
        pindex->nUndoPos = _pos.nPos;
        pindex->nStatus |= BLOCK_HAVE_UNDO;
        setDirtyBlockIndex.insert(pindex);
    }

    return true;
}

static bool WriteTxIndexDataForBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex)
{
    if (!fTxIndex) return true;

    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(block.vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(block.vtx.size());
    for (const CTransactionRef& tx : block.vtx)
    {
        vPos.push_back(std::make_pair(tx->GetHash(), pos));
        pos.nTxOffset += ::GetSerializeSize(*tx, SER_DISK, CLIENT_VERSION);
    }

    if (!pblocktree->WriteTxIndex(vPos)) {
        return AbortNode(state, "Failed to write transaction index");
    }

    return true;
}

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck() {
    RenameThread("bitcoin-scriptch");
    scriptcheckqueue.Thread();
}

// Protected by cs_main
VersionBitsCache versionbitscache;

int32_t ComputeBlockVersion(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    int32_t nVersion = VERSIONBITS_TOP_BITS;

    for (int i = 0; i < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; i++) {
        ThresholdState state = VersionBitsState(pindexPrev, params, static_cast<Consensus::DeploymentPos>(i), versionbitscache);
        if (state == THRESHOLD_LOCKED_IN || state == THRESHOLD_STARTED) {
            nVersion |= VersionBitsMask(params, static_cast<Consensus::DeploymentPos>(i));
        }
    }

    return nVersion;
}

/**
 * Threshold condition checker that triggers when unknown versionbits are seen on the network.
 */
class WarningBitsConditionChecker : public AbstractThresholdConditionChecker
{
private:
    int bit;

public:
    explicit WarningBitsConditionChecker(int bitIn) : bit(bitIn) {}

    int64_t BeginTime(const Consensus::Params& params) const override { return 0; }
    int64_t EndTime(const Consensus::Params& params) const override { return std::numeric_limits<int64_t>::max(); }
    int Period(const Consensus::Params& params) const override { return params.nMinerConfirmationWindow; }
    int Threshold(const Consensus::Params& params) const override { return params.nRuleChangeActivationThreshold; }

    bool Condition(const CBlockIndex* pindex, const Consensus::Params& params) const override
    {
        return ((pindex->nVersion & VERSIONBITS_TOP_MASK) == VERSIONBITS_TOP_BITS) &&
               ((pindex->nVersion >> bit) & 1) != 0 &&
               ((ComputeBlockVersion(pindex->pprev, params) >> bit) & 1) == 0;
    }
};

// Protected by cs_main
static ThresholdConditionCache warningcache[VERSIONBITS_NUM_BITS];

static unsigned int GetBlockScriptFlags(const CBlockIndex* pindex, const Consensus::Params& consensusparams) {
    AssertLockHeld(cs_main);

    unsigned int flags = SCRIPT_VERIFY_NONE;

    // Start enforcing P2SH (BIP16)
    if (pindex->nHeight >= consensusparams.BIP16Height) {
        flags |= SCRIPT_VERIFY_P2SH;
    }

    // Start enforcing the DERSIG (BIP66) rule
    if (pindex->nHeight >= consensusparams.BIP66Height) {
        flags |= SCRIPT_VERIFY_DERSIG;
    }

    // Start enforcing CHECKLOCKTIMEVERIFY (BIP65) rule
    if (pindex->nHeight >= consensusparams.BIP65Height) {
        flags |= SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY;
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    if (VersionBitsState(pindex->pprev, consensusparams, Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        flags |= SCRIPT_VERIFY_CHECKSEQUENCEVERIFY;
    }

    // Start enforcing WITNESS rules using versionbits logic.
    if (IsWitnessEnabled(pindex->pprev, consensusparams)) {
        flags |= SCRIPT_VERIFY_WITNESS;
        flags |= SCRIPT_VERIFY_NULLDUMMY;
    }

    return flags;
}



static int64_t nTimeCheck = 0;
static int64_t nTimeForks = 0;
static int64_t nTimeVerify = 0;
static int64_t nTimeConnect = 0;
static int64_t nTimeIndex = 0;
static int64_t nTimeCallbacks = 0;
static int64_t nTimeTotal = 0;
static int64_t nBlocksTotal = 0;

//! Collect the sidechain deposits a block carries.
//!
//! Shared on purpose rather than for tidiness. Anything that rebuilds the
//! deposit cache from block files has one way to do real harm: disagree with
//! what ConnectBlock recorded when the block was first connected. A second
//! implementation of connect-time semantics, drifting from this one, would
//! manufacture exactly the divergence such a rebuild exists to repair. So there
//! is one implementation and both paths call it.
//!
//! It needs no coins view. A deposit is identified by its own outputs, so this
//! is a function of the block alone - which is what lets a rebuild skip script
//! verification and the UTXO set entirely, and is the reason the sidechain-only
//! pass is cheap where a reindex is not.
//!
//! `db` is only ever used for TxnToDeposit, which reads no state from it, so
//! any instance gives the same answer.
//!
//! Returns false if a deposit transaction is malformed. ConnectBlock treats
//! that as invalidating the block.
static bool GetBlockDeposits(const CBlock& block, SidechainDB& db, std::vector<SidechainDeposit>& vDeposit)
{
    vDeposit.clear();

    for (size_t i = 0; i < block.vtx.size(); i++) {
        const CTransaction& tx = *(block.vtx[i]);

        if (tx.IsCoinBase())
            continue;

        // Check for possible sidechain deposits
        bool fSidechainOutput = false;
        uint8_t nSidechain;
        for (const CTxOut& out : tx.vout) {
            const CScript& scriptPubKey = out.scriptPubKey;
            if (scriptPubKey.IsDrivechain(nSidechain)) {
                fSidechainOutput = true;
                break;
            }
        }
        if (!fSidechainOutput)
            continue;

        SidechainDeposit deposit;
        if (!db.TxnToDeposit(tx, (int)i, block.GetHash(), deposit))
            return false;

        // Skip Withdrawal change return deposit, handled by SCDB::SpendWithdrawal
        if (deposit.strDest == SIDECHAIN_WITHDRAWAL_RETURN_DEST)
            continue;

        vDeposit.push_back(deposit);
    }

    return true;
}

//! Do a block's deposits chain from the treasury pointers they extend?
//!
//! The rule: within a slot, the first deposit spends that slot's pointer, and
//! each one after it spends the burn output of the one before - exactly once
//! each. A slot holding no pointer leaves its first deposit unconstrained,
//! because there is nothing for it to chain from and the alternative would
//! make a slot's first-ever deposit unmineable; deposits after it still chain.
//!
//! This is the consensus form of the relay rule the mempool has enforced for
//! years, and the rule whose absence let a deposit start a second treasury
//! lineage and strand the coins on the branch the pointer did not follow.
//!
//! `vDeposit` must be in block order, which is what GetBlockDeposits produces,
//! and `scdbIn` must hold the PARENT's pointers - the state before this block's
//! deposits are applied. A pure function of those two, so every node computes
//! the same answer; it reads no coins view.
//!
//! Written down as its own function rather than inline in ConnectBlock so that
//! the reject paths can be exercised directly. They cannot be reached through
//! a block: the wallet refuses to build a deposit that does not chain and the
//! mempool refuses to relay one, so producing the block a test would need
//! means a patched block producer.
bool CheckDepositContinuity(const std::vector<SidechainDeposit>& vDeposit,
        const SidechainDB& scdbIn, uint8_t& nSidechainFail, uint256& txidFail)
{
    std::map<uint8_t, COutPoint> mapExpected;

    for (const SidechainDeposit& d : vDeposit) {
        std::map<uint8_t, COutPoint>::iterator it = mapExpected.find(d.nSidechain);
        if (it == mapExpected.end()) {
            SidechainCTIP ctip;
            if (!scdbIn.GetCTIP(d.nSidechain, ctip)) {
                // Nothing to chain from; this deposit's own burn output is
                // what the next one in the slot must spend.
                mapExpected[d.nSidechain] = COutPoint(CTransaction(d.tx).GetHash(), d.nBurnIndex);
                continue;
            }
            it = mapExpected.insert(std::make_pair(d.nSidechain, ctip.out)).first;
        }

        int nSpent = 0;
        for (const CTxIn& in : d.tx.vin) {
            if (in.prevout == it->second)
                nSpent++;
        }
        if (nSpent != 1) {
            nSidechainFail = d.nSidechain;
            txidFail = CTransaction(d.tx).GetHash();
            return false;
        }

        it->second = COutPoint(CTransaction(d.tx).GetHash(), d.nBurnIndex);
    }

    return true;
}

/** Apply the effects of this block (with given index) on the UTXO set represented by coins.
 *  Validity checks that depend on the UTXO set are also done; ConnectBlock()
 *  can fail if those validity checks fail (among other reasons). */
bool CChainState::ConnectBlock(const CBlock& block, CValidationState& state, CBlockIndex* pindex,
                  CCoinsViewCache& view, const CChainParams& chainparams, bool fJustCheck)
{
    AssertLockHeld(cs_main);
    assert(pindex);
    // pindex->phashBlock can be null if called by CreateNewBlock/TestBlockValidity
    assert((pindex->phashBlock == nullptr) ||
           (*pindex->phashBlock == block.GetHash()));
    // The protective drivechain rules - the "D"
    // destination exclusivity, the withdrawal amount equations with the
    // non-zero-change rule, and deposit continuity - start at the FORK
    // instead of waiting for CTIPAnchorHeight, closing the 4,032-block window
    // between them in which a destination-"D" treasury spend can orphan a
    // pointer that the anchor then refuses EVERY block over.
    //
    // The gate is the later of EscrowRulesHeight and SCDBCommitmentHeight, and
    // it is network-safe by construction with no new consensus field: mainnet
    // sets them both to the fork height 1,976,112; testnet's EscrowRulesHeight
    // (188,640) is already in the past, and its compiled-in commitment gate is
    // parked at 1,000,000,000, so with the chainparams alone the maximum parks
    // these rules with the anchor there and nothing is applied retroactively to
    // testnet history. A testnet node that overrides the commitment height
    // (-scdbcommitmentheight) applies these rules from the later of the
    // two. Regtest sets both to 300. The anchor loop itself is unchanged and stays at CTIPAnchorHeight.
    const int nCTIPRulesHeight = std::max(chainparams.GetConsensus().EscrowRulesHeight,
                                          chainparams.GetConsensus().SCDBCommitmentHeight);

    int64_t nTimeStart = GetTimeMicros();

    // Check it again in case a previous version let a bad block in
    // NOTE: We don't currently (re-)invoke ContextualCheckBlock() or
    // ContextualCheckBlockHeader() here. This means that if we add a new
    // consensus rule that is enforced in one of those two functions, then we
    // may have let in a block that violates the rule prior to updating the
    // software, and we would NOT be enforcing the rule here. Fully solving
    // upgrade from one software version to the next after a consensus rule
    // change is potentially tricky and issue-specific (see RewindBlockIndex()
    // for one general approach that was used for BIP 141 deployment).
    // Also, currently the rule against blocks more than 2 hours in the future
    // is enforced in ContextualCheckBlockHeader(); we wouldn't want to
    // re-enforce that rule here (at least until we make it impossible for
    // GetAdjustedTime() to go backward).
    if (!CheckBlock(block, state, chainparams.GetConsensus(), !fJustCheck, !fJustCheck))
        return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));

    // Small-block soft fork: enforce the serialized size limit here as well
    // as in ContextualCheckBlock (see the NOTE above - new rules enforced
    // only there do not apply to blocks that were already stored before the
    // node upgraded, or during -reindex-chainstate). Unlike the witness
    // checks this needs no context beyond the height, so re-checking here is
    // cheap and closes that gap: an oversized block stored by an older
    // version fails to connect and its chain is abandoned.
    // Reported as a permanent failure, unlike the matching gate in
    // ContextualCheckBlock. That gate must tolerate malleation, because it sees
    // blocks as they arrive from the network and criticalData padding does not
    // change a block's hash. This one only ever sees blocks already written to
    // disk -- AcceptBlock runs ContextualCheckBlock before SaveBlockToDisk, so an
    // over-limit copy never gets stored -- meaning a failure here is a genuinely
    // oversized block from an older version, not a malleated copy. Marking it
    // invalid is therefore correct, and required: with corruptionPossible set,
    // InvalidBlockFound() does nothing, so the block would stay in
    // setBlockIndexCandidates and ActivateBestChain would retry it forever (this
    // fork has no equivalent of upstream's "Corrupt block found" AbortNode).
    if (pindex->nHeight >= chainparams.GetConsensus().SmallBlockHeight &&
            GetCommittedSerializedSize(block) > MAX_SMALL_BLOCK_SERIALIZED_SIZE) {
        return state.DoS(100, error("%s: serialized size limit failed", __func__),
                         REJECT_INVALID, "bad-blk-size");
    }

    // verify that the view's current state corresponds to the previous block
    uint256 hashPrevBlock = pindex->pprev == nullptr ? uint256() : pindex->pprev->GetBlockHash();
    assert(hashPrevBlock == view.GetBestBlock());

    // Special case for the genesis block, skipping connection of its transactions
    // (its coinbase is unspendable)
    if (block.GetHash() == chainparams.GetConsensus().hashGenesisBlock) {
        if (!fJustCheck)
            view.SetBestBlock(pindex->GetBlockHash());
        return true;
    }

    nBlocksTotal++;





    bool fScriptChecks = true;
    if (!hashAssumeValid.IsNull()) {
        // We've been configured with the hash of a block which has been externally verified to have a valid history.
        // A suitable default value is included with the software and updated from time to time.  Because validity
        //  relative to a piece of software is an objective fact these defaults can be easily reviewed.
        // This setting doesn't force the selection of any particular chain but makes validating some faster by
        //  effectively caching the result of part of the verification.
        BlockMap::const_iterator  it = mapBlockIndex.find(hashAssumeValid);
        if (it != mapBlockIndex.end()) {
            if (it->second->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->GetAncestor(pindex->nHeight) == pindex &&
                pindexBestHeader->nChainWork >= nMinimumChainWork) {
                // This block is a member of the assumed verified chain and an ancestor of the best header.
                // The equivalent time check discourages hash power from extorting the network via DOS attack
                //  into accepting an invalid block through telling users they must manually set assumevalid.
                //  Requiring a software change or burying the invalid block, regardless of the setting, makes
                //  it hard to hide the implication of the demand.  This also avoids having release candidates
                //  that are hardly doing any signature verification at all in testing without having to
                //  artificially set the default assumed verified block further back.
                // The test against nMinimumChainWork prevents the skipping when denied access to any chain at
                //  least as good as the expected chain.
                fScriptChecks = (GetBlockProofEquivalentTime(*pindexBestHeader, *pindex, *pindexBestHeader, chainparams.GetConsensus()) <= 60 * 60 * 24 * 7 * 2);
            }
        }
    }

    int64_t nTime1 = GetTimeMicros(); nTimeCheck += nTime1 - nTimeStart;
    LogPrint(BCLog::BENCH, "    - Sanity checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime1 - nTimeStart), nTimeCheck * MICRO, nTimeCheck * MILLI / nBlocksTotal);

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied to all blocks with a timestamp after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes during their
    // initial block download.
    bool fEnforceBIP30 = (!pindex->phashBlock) || // Enforce on CreateNewBlock invocations which don't have a hash.
                          !((pindex->nHeight==91842 && pindex->GetBlockHash() == uint256S("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
                           (pindex->nHeight==91880 && pindex->GetBlockHash() == uint256S("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")));

    // Once BIP34 activated it was not possible to create new duplicate coinbases and thus other than starting
    // with the 2 existing duplicate coinbase pairs, not possible to create overwriting txs.  But by the
    // time BIP34 activated, in each of the existing pairs the duplicate coinbase had overwritten the first
    // before the first had been spent.  Since those coinbases are sufficiently buried its no longer possible to create further
    // duplicate transactions descending from the known pairs either.
    // If we're on the known chain at height greater than where BIP34 activated, we can save the db accesses needed for the BIP30 check.
    assert(pindex->pprev);
    CBlockIndex *pindexBIP34height = pindex->pprev->GetAncestor(chainparams.GetConsensus().BIP34Height);
    //Only continue to enforce if we're below BIP34 activation height or the block hash at that height doesn't correspond.
    fEnforceBIP30 = fEnforceBIP30 && (!pindexBIP34height || !(pindexBIP34height->GetBlockHash() == chainparams.GetConsensus().BIP34Hash));

    if (fEnforceBIP30) {
        for (const auto& tx : block.vtx) {
            for (size_t o = 0; o < tx->vout.size(); o++) {
                if (view.HaveCoin(COutPoint(tx->GetHash(), o))) {
                    return state.DoS(100, error("ConnectBlock(): tried to overwrite transaction"),
                                     REJECT_INVALID, "bad-txns-BIP30");
                }
            }
        }
    }

    // Start enforcing BIP68 (sequence locks) and BIP112 (CHECKSEQUENCEVERIFY) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindex->pprev, chainparams.GetConsensus(), Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        nLockTimeFlags |= LOCKTIME_VERIFY_SEQUENCE;
    }

    // Consensus fix: key the drivechain gate to this block's own ancestry
    // (pindex->pprev), never the mutable active tip. ConnectBlock is also
    // reached for non-tip blocks (e.g. CVerifyDB level-4 replay), and a
    // block's validity must not depend on receive/connect order.
    bool skydogeEnabled = IsSkydogeEnabled(pindex->pprev, chainparams.GetConsensus());

    // Get the script flags for this block
    unsigned int flags = GetBlockScriptFlags(pindex, chainparams.GetConsensus());

    int64_t nTime2 = GetTimeMicros(); nTimeForks += nTime2 - nTime1;
    LogPrint(BCLog::BENCH, "    - Fork checks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime2 - nTime1), nTimeForks * MICRO, nTimeForks * MILLI / nBlocksTotal);

    // The working sidechain state this block is validated against, and the
    // deferred commit: every SCDB
    // read and mutation below goes to this copy, which is swapped into the
    // global scdb only after the last rejection/error point (below, before
    // view.SetBestBlock). A rejected block, a failed withdrawal spend / SCDB
    // update, or a failed disk write therefore leaves the global SCDB (deposit
    // cache + mapCTIP) unchanged instead of poisoning it. Copy cost is bounded
    // by SCDB_DEPOSIT_CACHE_MAX and matches the copy scdb.Update already makes
    // internally.
    //
    // Built by the shared seed helper - the copy of the global with the
    // parent's record overlaid where that record is complete - so it is the
    // same state the miner committed to (ComputeSCDBCommitment) and the
    // state getscdbhash/getscdbstate report. See GetSCDBConsensusSeed for
    // why and when the record stands in for the global.
    SidechainDB scdbCache = GetSCDBConsensusSeed(pindex->pprev, chainparams.GetConsensus());

    // a BMM request is valid only for a sidechain
    // active as of THIS block's parent. ContextualCheckBlock answers that from
    // the parent's record where it has one; without one it used to fall back
    // to the tip state, so for a branch forking below a slot's activation a
    // synced node and a fresh node judged the same block differently. Here the
    // parent is the connected tip and scdbCache is its state before this
    // block's own updates (an activation in this block does not count, as in
    // the record check). Needed because ContextualCheckBlock skips this
    // test for -reindex / -loadblock and never runs under -reindex-chainstate.
    // Gated at SCDBCommitmentHeight (the fork), so no stored or historical
    // block below it is judged by a new rule. IsSidechainActive equals the
    // record test: the SCDB tables are always sized for every slot.
    // NOT corruption-possible, deliberately: ContextualCheckBlock has already
    // required each request's bytes, slot byte included, to match a coinbase
    // commitment output (bad-critical-data-no-commit), so a relayed copy can
    // drop a request but never introduce a slot the block did not commit to,
    // and a reject here is a verdict on the block itself. Marking it failed
    // also avoids the re-request storm of a corruption-possible reject.
    if (pindex->nHeight >= chainparams.GetConsensus().SCDBCommitmentHeight) {
        for (const CTransactionRef& tx : block.vtx) {
            if (tx->criticalData.IsNull())
                continue;
            uint8_t nSidechain;
            std::string strPrevBlock = "";
            if (!tx->criticalData.IsBMMRequest(nSidechain, strPrevBlock))
                continue;
            if (!scdbCache.IsSidechainActive(nSidechain)) {
                return state.DoS(0, error("%s: BMM request %s for sidechain %u, which is not active as of the parent of block %s",
                                          __func__, tx->GetHash().ToString(), nSidechain, block.GetHash().ToString()),
                                 REJECT_INVALID, "bad-critical-bmm-nsidechain-inactive");
            }
        }
    }

    CBlockUndo blockundo;

    // Declared before `control` on purpose, and it must stay that way. The
    // queued script checks hold raw pointers into this vector, and local
    // objects are destroyed in reverse order of declaration: `control`'s
    // destructor is what waits for the worker threads to finish. If txdata were
    // declared after it, any early return from this function would free the
    // vector while those threads were still reading it. There are several such
    // returns between the point where checks are queued and where they are
    // waited on.
    std::vector<PrecomputedTransactionData> txdata;
    txdata.reserve(block.vtx.size()); // Required so that pointers to individual PrecomputedTransactionData don't get invalidated

    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : nullptr);

    std::vector<int> prevheights;
    CAmount nFees = 0;
    int nInputs = 0;
    int64_t nSigOpsCost = 0;
    blockundo.vtxundo.reserve(block.vtx.size() - 1);
    std::vector<std::tuple<uint8_t, CTransaction, int>> vWithdrawalToSpend;
    std::vector<OPReturnData> vOPReturnData;
    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        const CTransaction &tx = *(block.vtx[i]);

        nInputs += tx.vin.size();

        // Compute this transaction's fee and serialized size ONCE. These are
        // per-transaction values; the OP_RETURN indexing loop below previously
        // recomputed CheckTxInputs (O(inputs+outputs)) and GetSerializeSize
        // (O(tx size)) for EVERY OP_RETURN output, making block validation
        // O(outputs^2) - a cheap-to-mine, network-wide validation-stall DoS.
        // CheckTxInputs has no side effects on the UTXO view, so computing the
        // fee here (instead of once per OP_RETURN output and again below) is
        // behaviour-identical; the block is still rejected on the same failure.
        CAmount txfee = 0;
        if (!tx.IsCoinBase()) {
            if (!Consensus::CheckTxInputs(tx, state, view, pindex->nHeight, txfee)) {
                return error("%s: Consensus::CheckTxInputs: %s, %s", __func__, tx.GetHash().ToString(), FormatStateMessage(state));
            }
            nFees += txfee;
            if (!MoneyRange(nFees)) {
                return state.DoS(100, error("%s: accumulated fee in the block out of range.", __func__),
                                 REJECT_INVALID, "bad-txns-accumulated-fee-outofrange");
            }
        }
        const unsigned int nTxSize = ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);

        // Search for OP_RETURN outputs (index them for the OP_RETURN DB)
        for (const CTxOut& o : tx.vout) {
            const CScript& scriptPubKey = o.scriptPubKey;
            if (!scriptPubKey.size())
                continue;
            if (scriptPubKey[0] != OP_RETURN)
                continue;

            OPReturnData data;
            data.txid = tx.GetHash();
            data.script = scriptPubKey;
            data.nSize = nTxSize;
            data.fees = txfee; // 0 for coinbase
            vOPReturnData.push_back(data);
        }

        bool fSidechainInputs = false;
        uint8_t nSidechain = 0;
        if (!tx.IsCoinBase())
        {
            if (!view.HaveInputs(tx))
                return state.DoS(100, error("ConnectBlock(): inputs missing/spent"),
                                 REJECT_INVALID, "bad-txns-inputs-missingorspent");


            // Set fSidechainInputs & nSidechain
                if (skydogeEnabled) {
                    for (const CTxIn& in : tx.vin) {
                        Coin coin = view.AccessCoin(in.prevout);
                        if (coin.out.scriptPubKey.IsDrivechain(nSidechain)) {
                            fSidechainInputs = true;
                            break;
                        }
                    }
                }

            // Check that transaction is BIP68 final
            // BIP68 lock checks (as opposed to nLockTime checks) must
            // be in ConnectBlock because they require the UTXO set
            prevheights.resize(tx.vin.size());
            for (size_t j = 0; j < tx.vin.size(); j++) {
                prevheights[j] = view.AccessCoin(tx.vin[j].prevout).nHeight;
            }

            if (!SequenceLocks(tx, nLockTimeFlags, &prevheights, *pindex)) {
                return state.DoS(100, error("%s: contains a non-BIP68-final transaction", __func__),
                                 REJECT_INVALID, "bad-txns-nonfinal");
            }
        }

        // GetTransactionSigOpCost counts 3 types of sigops:
        // * legacy (always)
        // * p2sh (when P2SH enabled in flags and excludes coinbase)
        // * witness (when witness enabled in flags and excludes coinbase)
        nSigOpsCost += GetTransactionSigOpCost(tx, view, flags);
        if (nSigOpsCost > MAX_BLOCK_SIGOPS_COST)
            return state.DoS(100, error("ConnectBlock(): too many sigops"),
                             REJECT_INVALID, "bad-blk-sigops");

        txdata.emplace_back(tx);
        if (!tx.IsCoinBase())
        {
            std::vector<CScriptCheck> vChecks;
            bool fCacheResults = fJustCheck; /* Don't cache results if we're actually connecting blocks (still consult the cache, though) */
            if (!CheckInputs(tx, state, view, fScriptChecks, flags, fCacheResults, fCacheResults, txdata[i], nScriptCheckThreads ? &vChecks : nullptr))
                return error("ConnectBlock(): CheckInputs on %s failed with %s",
                    tx.GetHash().ToString(), FormatStateMessage(state));
            control.Add(vChecks);
        }

        /*
         * Note: While not commited to by miners in a coinbase, the messages
         * M5 & M6 also exist. These are regular Bitcoin transactions, which can
         * be identified by the outputs they are spending. M5 & M6 transactions
         * spend the outputs of Critical TxID-index Pairs (a "CTIP") owned by
         * sidechains to create deposits (M5) or withdrawals (M6).
         *
         * Also look at AcceptToMemoryPoolWorker() and GetSidechainValues()
         * functions to see how M5 and M6 are detected.
         *
         * M5: (Skydoge Deposit): A deposit will increase the amount of coins
         * held in the CTIP output of the sidechain.
         *
         * M6: (Skydoge Withdrawal): A withdrawal will decrease the amount of
         * coins held in the CTIP output of the sidechain.
         */

        // From the fork a ZERO-value escrow output is invalid in a block,
        // not only refused at relay (sidechain-zero-value-escrow, policy).
        // This protects a newly activated slot's treasury pointer. No
        // honest block changes: the miner and the
        // wallet never build such an output, and a withdrawal's zero
        // treasury change is already refused from the same height.
        // A pure function of the transaction's bytes, so DoS(100). Every
        // transaction, not only those spending a treasury: a first deposit
        // into a pointer-less slot spends none.
        if (skydogeEnabled && pindex->nHeight >= nCTIPRulesHeight) {
            for (const CTxOut& out : tx.vout) {
                uint8_t nSidechainZero = 0;
                if (out.scriptPubKey.IsDrivechain(nSidechainZero) && out.nValue == 0)
                    return state.DoS(100,
                        error("ConnectBlock(): bad-sidechain-zero-value-escrow: zero-value escrow output for sidechain %u: %s",
                              nSidechainZero, tx.GetHash().ToString()),
                        REJECT_INVALID, "bad-sidechain-zero-value-escrow");
            }
        }

        if (skydogeEnabled && fSidechainInputs) {
            // We must get the Withdrawal hash as work is applied to
            // Withdrawal before inputs and the change output are known.
            uint256 hashBlind;
            // Consensus failures below must be signalled through `state`. The
            // Drivechain helpers take no CValidationState and cannot set one
            // themselves (unlike CheckInputs above), so a bare error() would
            // leave the block unmarked and be handled as a local system error
            // rather than as an invalid block.
            if (!tx.GetBlindHash(hashBlind))
                return state.DoS(100,
                    error("ConnectBlock(): Withdrawal (full id): %s has invalid format",
                          tx.GetHash().ToString()),
                    REJECT_INVALID, "bad-withdrawal-format");

            // Get values to and from sidechain
            CAmount amountSidechainIn = CAmount(0);
            CAmount amountIn = CAmount(0);
            CAmount amountSidechainOut = CAmount(0);
            CAmount amountWithdrawn = CAmount(0);
            std::string strFail = "";
            if (!GetDrivechainAmounts(view, tx, amountSidechainIn, amountIn, amountSidechainOut, amountWithdrawn, strFail))
                return state.DoS(100,
                    error("ConnectBlock(): Calculating Drivechain amounts failed: %s txid: %s",
                          strFail, tx.GetHash().ToString()),
                    REJECT_INVALID, "bad-drivechain-amounts");

            if (amountSidechainIn > amountSidechainOut) {
                // Escrow rules (BIP300 796c80eb): from EscrowRulesHeight the
                // fee-commitment output of a withdrawal payout, vout[1], must
                // carry no value. Its value used to be counted into the blind
                // value out and so burnt from the treasury, on top of the fee
                // the output encodes. A pure function of the transaction's
                // bytes, so DoS(100); it runs before the SpendWithdrawal probe
                // below, which refuses the same thing at DoS(0). A payout with
                // fewer than two outputs is refused by that probe anyway.
                if (pindex->nHeight >= chainparams.GetConsensus().EscrowRulesHeight &&
                        tx.vout.size() >= 2 && tx.vout[1].nValue != 0)
                    return state.DoS(100,
                        error("ConnectBlock(): bad-withdrawal-fee-value: withdrawal fee output carries %d: %s",
                              tx.vout[1].nValue, tx.GetHash().ToString()),
                        REJECT_INVALID, "bad-withdrawal-fee-value");

                // Treasury anchor soft fork, the amount half: from
                // nCTIPRulesHeight (the fork, not the anchor)
                // a withdrawal's amounts must satisfy the
                // same two equations SpendWithdrawal checks below, but read
                // from the coin actually spent rather than from the recorded
                // treasury pointer. Every term is a pure function of the
                // block's bytes and the view, so every node computes the same
                // answer - which is what makes this DoS(100) where the probe
                // below has to stay at DoS(0). It must come first, or the
                // probe rejects at DoS(0) and the escalation never takes.
                //
                // Both legs are needed. The second restates the change
                // equation (sidechaindb.cpp, "Check change amount"); the first
                // restates the output equation, which independently pins the
                // LAST output's value to the treasury change - GetBlindValueOut
                // pops the final output, so the two agree only when that final
                // output is the change return. Carrying one leg without the
                // other would be objectively weaker than the probe it escalates.
                if (pindex->nHeight >= nCTIPRulesHeight) {
                    // Three outputs is the withdrawal format's own minimum -
                    // the destination marker, the fee total, and the treasury
                    // change - and the same bound SpendWithdrawal takes below.
                    // Fewer is not a withdrawal at all, which is a statement
                    // about the block's bytes rather than about this node.
                    // GetBlindValueOut joins the same reject rather than
                    // getting its own: it fails only on an empty vin or vout,
                    // which CheckTransaction has already refused, so this adds
                    // no reachable rejection - it just stops a failure
                    // arriving as a silent zero blind value.
                    CAmount amountBlind = 0;
                    CAmount amountFees = 0;
                    if (tx.vout.size() < 3 ||
                            !tx.GetBlindValueOut(amountBlind) ||
                            !DecodeWithdrawalFees(tx.vout[1].scriptPubKey, amountFees))
                        return state.DoS(100,
                            error("ConnectBlock(): withdrawal fee output unreadable: %s",
                                  tx.GetHash().ToString()),
                            REJECT_INVALID, "bad-withdrawal-amounts");

                    if (amountBlind != amountWithdrawn)
                        return state.DoS(100,
                            error("ConnectBlock(): withdrawal output amount does not match the change return: %s",
                                  tx.GetHash().ToString()),
                            REJECT_INVALID, "bad-withdrawal-amounts");

                    if (amountSidechainOut != amountSidechainIn - (amountBlind + amountFees))
                        return state.DoS(100,
                            error("ConnectBlock(): withdrawal change amount does not match the spent treasury: %s",
                                  tx.GetHash().ToString()),
                            REJECT_INVALID, "bad-withdrawal-amounts");

                    // The change return must carry value: a ZERO-value change
                    // coin would become a treasury pointer outside the
                    // drivechain rules and close the slot. Relay refuses this
                    // at receivewithdrawalbundle ("non-zero change") and the
                    // assembler declines to pay it; from this height consensus
                    // refuses it as well.
                    if (amountSidechainOut == 0)
                        return state.DoS(100,
                            error("ConnectBlock(): bad-withdrawal-zero-change: withdrawal leaves a zero-value treasury change return: %s",
                                  tx.GetHash().ToString()),
                            REJECT_INVALID, "bad-withdrawal-zero-change");
                }

                // Check if withdrawal bundle tx can be spent and track it.
                // Probed against the working state built above - where the
                // parent's record was complete this is the parent's state, so
                // the answer no longer depends on what order this node saw the
                // chain in. Probed before this block's deposits are added
                // (below), exactly as it always was.
                if (scdbCache.SpendWithdrawal(nSidechain, block.GetHash(), tx, i, pindex->nHeight, true /* fJustCheck */, true /* fDebug */)) {
                    vWithdrawalToSpend.push_back(std::make_tuple(nSidechain, tx, i));
                } else {
                    // DoS(0), not DoS(100). Validating from the
                    // parent's record makes this node's answer reproducible,
                    // but a ban asserts something about what every other node
                    // computed, and nodes that diverged before the record was
                    // complete - or whose records predate it - can still
                    // disagree. DoS(0) still marks the block invalid, without
                    // a peer ban.
                    if (!fJustCheck)
                        AlertSCDBDivergence(block.GetHash(), "bad-withdrawal-spend");
                    return state.DoS(0,
                        error("ConnectBlock(): Spend Withdrawal failed (blind Withdrawal hash : txid): %s : %s",
                              hashBlind.ToString(), tx.GetHash().ToString()),
                        REJECT_INVALID, "bad-withdrawal-spend");
                }
            } else if (pindex->nHeight >= nCTIPRulesHeight) {
                // Treasury anchor soft fork, the DESTINATION half.
                // (Activation height: see nCTIPRulesHeight above - the fork,
                // not the anchor.)
                //
                // "D" (SIDECHAIN_WITHDRAWAL_RETURN_DEST) marks a withdrawal's
                // change return, which SpendWithdrawal accounts for - which is
                // why GetBlockDeposits skips it rather than recording it as a
                // deposit. From this height "D" belongs to withdrawals only: a
                // treasury spend that is not a withdrawal may not claim it, so
                // every node's recorded treasury pointer stays the coin the
                // chain actually holds.
                //
                // A pure function of the block's bytes and the coins view -
                // no SCDB state - so every node computes the same answer and
                // DoS(100) is safe, unlike the DoS(0) reject above. The
                // destination sits in an OP_RETURN output committed by the
                // merkle root, so a relayed copy cannot be doctored into
                // failing this; not corruption-possible.
                //
                // This only brings consensus level with policy, which
                // already refuses both shapes: a strict deposit carrying "D"
                // on the destination test in AcceptToMemoryPoolWorker, and an
                // equal-value treasury spend on the
                // "sidechain-invalid-ctip-spend" branch beside it, whose own
                // comment notes it is the only thing standing in the way and
                // that a miner does not consult it. This is that rule, on the
                // side a miner cannot skip.
                SidechainDeposit depositDest;
                if (scdbCache.TxnToDeposit(tx, i, block.GetHash(), depositDest) &&
                        depositDest.strDest == SIDECHAIN_WITHDRAWAL_RETURN_DEST) {
                    return state.DoS(100,
                        error("ConnectBlock(): bad-deposit-withdrawal-dest: treasury spend claims the withdrawal-return destination without being a withdrawal: %s",
                              tx.GetHash().ToString()),
                        REJECT_INVALID, "bad-deposit-withdrawal-dest");
                }
            }
        }

        CTxUndo undoDummy;
        if (i > 0) {
            blockundo.vtxundo.push_back(CTxUndo());
        }
        UpdateCoins(tx, view, i == 0 ? undoDummy : blockundo.vtxundo.back(), pindex->nHeight, fJustCheck);
    }
    int64_t nTime3 = GetTimeMicros(); nTimeConnect += nTime3 - nTime2;
    LogPrint(BCLog::BENCH, "      - Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin) [%.2fs (%.2fms/blk)]\n", (unsigned)block.vtx.size(), MILLI * (nTime3 - nTime2), MILLI * (nTime3 - nTime2) / block.vtx.size(), nInputs <= 1 ? 0 : MILLI * (nTime3 - nTime2) / (nInputs-1), nTimeConnect * MICRO, nTimeConnect * MILLI / nBlocksTotal);

    CAmount blockReward = nFees + GetBlockSubsidy(pindex->nHeight, chainparams.GetConsensus());
    if (block.vtx[0]->GetValueOut() > blockReward)
        return state.DoS(100,
                         error("ConnectBlock(): coinbase pays too much (actual=%d vs limit=%d)",
                               block.vtx[0]->GetValueOut(), blockReward),
                               REJECT_INVALID, "bad-cb-amount");

    if (!control.Wait())
        return state.DoS(100, error("%s: CheckQueue failed", __func__), REJECT_INVALID, "block-validation-failed");
    int64_t nTime4 = GetTimeMicros(); nTimeVerify += nTime4 - nTime2;
    LogPrint(BCLog::BENCH, "    - Verify %u txins: %.2fms (%.3fms/txin) [%.2fs (%.2fms/blk)]\n", nInputs - 1, MILLI * (nTime4 - nTime2), nInputs <= 1 ? 0 : MILLI * (nTime4 - nTime2) / (nInputs-1), nTimeVerify * MICRO, nTimeVerify * MILLI / nBlocksTotal);

    // (scdbCache - the working sidechain state and deferred commit - was built
    // above, before the transaction loop, so the withdrawal probe in the loop
    // reads the same object the committing calls below do.)

    // Runs under fJustCheck too. The deposit conversion below is the only place
    // a malformed deposit is caught, and it rejects the whole block at DoS(100);
    // leaving it out of the template check let a miner assemble a block that
    // every node - including the miner's own - then refused, rebuild the same
    // template next block, and be banned by its own peers for it.
    //
    // This cannot make a valid block invalid. ConnectBlock is only ever called
    // with fJustCheck true from TestBlockValidity (below), and TestBlockValidity
    // has two callers, CreateNewBlock and the getblocktemplate proposal mode -
    // neither on the block acceptance path. A stricter check here can only stop
    // this node building a template that was going to be rejected anyway.
    if (skydogeEnabled) {
        // Collected here rather than inside the transaction loop above, so that
        // the rebuild pass can reach the same code with only a block in hand.
        // The scan is over outputs the loop has already touched and costs
        // nothing beside the script verification it sits next to.
        std::vector<SidechainDeposit> vDeposit;
        if (!GetBlockDeposits(block, scdbCache, vDeposit)) {
            LogPrintf("%s: Deposits invalid from block: %s\n", __func__, block.GetHash().ToString());
            return state.DoS(100,
                error("%s: Deposits invalid from block: %s", __func__, block.GetHash().ToString()),
                REJECT_INVALID, "bad-sidechain-deposit");
        }
        // Treasury anchor soft fork, the continuity half: from nCTIPRulesHeight
        // (the fork, not the anchor) a slot
        // that already holds a treasury pointer may only receive
        // deposits that chain from it - the first spends the pointer, each
        // one after it spends the burn output of the one before, and each
        // spends its predecessor exactly once. This is the consensus form of
        // the relay rule the mempool has enforced for years (the CTIP-spend
        // check in AcceptToMemoryPoolWorker), whose comment has named this
        // flag day since it was written; it is also the rule whose absence
        // let a deposit start a second treasury lineage and strand the coins
        // on the branch the pointer did not follow.
        //
        // The reference is the PARENT's pointer - scdbCache still holds it,
        // since this block's deposits are applied just below - so the check is
        // a pure function of (parent pointer, block bytes). Record-derived,
        // hence DoS(0) with the rest of that family rather than a ban.
        //
        // A slot holding no pointer leaves its first deposit unconstrained:
        // there is nothing for it to chain from, and the alternative would
        // make a slot's first-ever deposit unmineable. Deposits after it in
        // the same block still chain.
        //
        // Note what this forbids: a payout and a deposit for the SAME slot in
        // one block. The payout spends the pointer, so a deposit chaining from
        // that pointer would double-spend it, and one chaining from the
        // payout's change return does not chain from the parent pointer. No
        // relayable deposit can be in that position anyway - the mempool rule
        // makes deposits spend the current pointer - so this costs nothing a
        // miner could reach honestly. Other slots are unaffected.
        if (skydogeEnabled && pindex->nHeight >= nCTIPRulesHeight) {
            uint8_t nSidechainFail = 0;
            uint256 txidFail;
            if (!CheckDepositContinuity(vDeposit, scdbCache, nSidechainFail, txidFail)) {
                if (!fJustCheck)
                    AlertSCDBDivergence(block.GetHash(), "bad-deposit-continuity");
                return state.DoS(0,
                    error("%s: deposit does not chain from the treasury of sidechain %u: %s",
                          __func__, nSidechainFail, txidFail.ToString()),
                    REJECT_INVALID, "bad-deposit-continuity");
            }
        }

        // Mutates the copy only; committed below after all rejection points.
        // Kept log-and-continue (as before): a sort failure here must NOT reject
        // the block, or one crafted block could halt upgraded nodes while
        // un-upgraded nodes accept it.
        //
        // Still skipped under fJustCheck: the copy is discarded on that path, so
        // the sort would be paid for nothing, and skipping it keeps what the
        // withdrawal spend below sees exactly as it was before.
        if (!fJustCheck)
            scdbCache.AddDeposits(vDeposit);
    }

    if (skydogeEnabled && vWithdrawalToSpend.size()) {
        for (size_t i = 0; i < vWithdrawalToSpend.size(); i++) {
            uint8_t nSidechain = std::get<0>(vWithdrawalToSpend[i]);
            const CTransaction tx = std::get<1>(vWithdrawalToSpend[i]);
            int nTx = std::get<2>(vWithdrawalToSpend[i]);

            uint256 hashBlind;
            tx.GetBlindHash(hashBlind);
            if (!scdbCache.SpendWithdrawal(nSidechain, block.GetHash(), tx, nTx, pindex->nHeight, fJustCheck, true /* fDebug */)) {
                // DoS(0): an SCDB-state-dependent reject; see bad-withdrawal-spend above.
                if (!fJustCheck)
                    AlertSCDBDivergence(block.GetHash(), "bad-withdrawal-spend-final");
                return state.DoS(0,
                    error("ConnectBlock(): Final spend Withdrawal failed (blind Withdrawal hash : txid): %s : %s.\n nSidechain: %u\n",
                          hashBlind.ToString(), tx.GetHash().ToString(), nSidechain),
                    REJECT_INVALID, "bad-withdrawal-spend-final");
            }
        }
    }

    if (skydogeEnabled) {
        // Security fix (height-gated): reject a block whose coinbase
        // carries a malformed sidechain proposal commitment. The try/catch in
        // DeserializeFromProposalScript already stops such a block from
        // permanently halting THIS node (the proposal is skipped rather than
        // throwing up through ConnectBlock), but a skipped-and-accepted block
        // would still be relayed to un-upgraded peers, where it wedges them.
        // Marking it invalid here with real `state` stops propagation and keeps
        // it off the best chain. DeserializeFromProposalScript is a pure
        // function of the script bytes, so all nodes agree deterministically.
        // Height-gated at SmallBlockHeight (the coordinated flag day) so it
        // never retroactively invalidates a stored or historical block.
        if (pindex->nHeight >= chainparams.GetConsensus().SmallBlockHeight) {
            for (const CTxOut& out : block.vtx[0]->vout) {
                if (!out.scriptPubKey.IsSidechainProposalCommit())
                    continue;
                Sidechain proposalCheck;
                if (!proposalCheck.DeserializeFromProposalScript(out.scriptPubKey)) {
                    return state.DoS(100,
                        error("%s: malformed sidechain proposal commitment in block: %s",
                              __func__, block.GetHash().ToString()),
                        REJECT_INVALID, "bad-sidechain-proposal");
                }
                // Bounded size (see SIDECHAIN_PROPOSAL_MAX_TEXT_BYTES).
                // A pure function of the script bytes, like the check above.
                if (proposalCheck.title.size() + proposalCheck.description.size() > SIDECHAIN_PROPOSAL_MAX_TEXT_BYTES) {
                    return state.DoS(100,
                        error("%s: oversized sidechain proposal commitment (%u bytes of title and description, limit %u) in block: %s",
                              __func__, (unsigned)(proposalCheck.title.size() + proposalCheck.description.size()),
                              (unsigned)SIDECHAIN_PROPOSAL_MAX_TEXT_BYTES, block.GetHash().ToString()),
                        REJECT_INVALID, "bad-sidechain-proposal-size");
                }
            }
        }

        // Update / synchronize SCDB
        if (!scdbCache.Update(pindex->nHeight, block.GetHash(), block.GetPrevHash(), block.vtx[0]->vout, fJustCheck, true /* fDebug */)) {
            LogPrintf("%s: SCDB failed to update with block: %s\n", __func__, block.GetHash().ToString());
            // DoS(0): an SCDB-state-dependent reject; see bad-withdrawal-spend above.
            if (!fJustCheck)
                AlertSCDBDivergence(block.GetHash(), "bad-scdb-update");
            return state.DoS(0,
                error("%s: SCDB update failed for block: %s", __func__, block.GetHash().ToString()),
                REJECT_INVALID, "bad-scdb-update");
        }
        // (mempool CTIP is refreshed at the commit point below, after all
        // rejection/error points, so a later-rejected block never updates it.)

        // SCDB commitment soft fork, the value half: from SCDBCommitmentHeight
        // the committed hash must equal GetCommitmentHash() of the post-connect
        // state scdbCache now holds. Gated on !fJustCheck because deposit
        // application is deliberately skipped under fJustCheck (above), so
        // there the cache is not the post-connect state and an ungated check
        // would make TestBlockValidity reject the miner's own valid template.
        // Presence and shape were settled at DoS(100) in ContextualCheckBlock;
        // this is the SCDB-state-dependent half, so it stays DoS(0) like the
        // three rejects above: the reject already forks a diverged node off
        // the chain loudly, without punishing the peer that relayed the block.
        if (!fJustCheck &&
                pindex->nHeight >= chainparams.GetConsensus().SCDBCommitmentHeight) {
            uint256 hashCommitted;
            uint256 hashDummy;
            int nCommit = 0;
            for (const CTxOut& out : block.vtx[0]->vout) {
                if (out.scriptPubKey.IsSCDBHashCommit(hashDummy)) {
                    hashCommitted = hashDummy;
                    nCommit++;
                }
            }
            // Exactly one, the same count ContextualCheckBlock demands. This
            // loop used to take the LAST match and say nothing about how many
            // there were, so the two surfaces disagreed: a block carrying two
            // commitments is refused outright by contextual validation but,
            // reaching here without it - a block already on disk being
            // replayed by -reindex-chainstate, which never calls AcceptBlock -
            // was judged on whichever commitment happened to come last. A pure
            // function of the coinbase's bytes, which the merkle root commits
            // to, so every node answers identically and a relayed copy cannot
            // be doctored into failing it: DoS(100), not corruption-possible,
            // exactly as in ContextualCheckBlock. Same reason string too, so
            // the two surfaces are also indistinguishable in the logs.
            if (nCommit != 1) {
                LogPrintf("%s: expected exactly 1 SCDB hash commitment in block %s, found %d\n",
                          __func__, block.GetHash().ToString(), nCommit);
                return state.DoS(100,
                    error("%s: expected exactly 1 SCDB hash commitment, found %d", __func__, nCommit),
                    REJECT_INVALID, "bad-scdb-commitment-missing");
            }
            const uint256 hashComputed = scdbCache.GetCommitmentHash(pindex->nHeight);
            if (hashCommitted != hashComputed) {
                LogPrintf("%s: SCDB commitment mismatch in block %s: committed %s computed %s\n",
                          __func__, block.GetHash().ToString(),
                          hashCommitted.ToString(), hashComputed.ToString());
                AlertSCDBDivergence(block.GetHash(), "bad-scdb-commitment");
                return state.DoS(0,
                    error("%s: SCDB commitment mismatch for block: %s", __func__, block.GetHash().ToString()),
                    REJECT_INVALID, "bad-scdb-commitment");
            }
        }

        // Treasury anchor soft fork, the anchor itself: from CTIPAnchorHeight
        // every treasury pointer this node carries must name a coin that
        // actually exists in the unspent output set, with the treasury script
        // for its own slot and exactly the amount recorded against it.
        //
        // The pointer stays maintained state and its transition is untouched -
        // this anchors the answer to the one store every node shares, it never
        // derives the pointer from that store. Deriving it is the form that was
        // analysed and rejected: the treasury script is anyone-can-spend and
        // uniqueness is not enforced, so a slot can hold more than one
        // candidate, and mainnet already does.
        //
        // Gated on !fJustCheck for the same reason as the commitment check
        // above: deposits are not applied under fJustCheck, so there the state
        // is not the post-connect state and an ungated check would reject the
        // miner's own template. The block's own outputs are already in the
        // view by this point, so a pointer this block just moved anchors to
        // the coin this block just created.
        //
        // DoS(0), permanently. A failure says this node's pointer disagrees
        // with the chain's coins, which is real and worth stopping on, but the
        // pointer is record-derived and two honest nodes can hold different
        // ones in the forked states already on chain - so a ban would assert
        // something about the peer that this check cannot establish.
        //
        // Cost is one point lookup per slot holding a pointer, plus - only when
        // a pointer does not anchor - one input scan of the block.
        //
        // Refuse the block only when
        // the block itself is what broke the pointer. A pointer whose coin
        // THIS BLOCK spent and did not move is the event this anchor exists
        // to stop, and it still stops it (DoS(0), as before). A pointer that
        // was already unanchored before this block - its coin already spent,
        // or a coin of the wrong script or amount, neither of which any block
        // can cause - is state every node agrees on, and refusing every block
        // over it halts the whole upgraded set at once while no block can
        // repair it (continuity demands spending a coin that is gone). It is
        // reported (log line plus a throttled alert under its own key) and the
        // block is accepted; the slot stays frozen - no deposits, no
        // withdrawals - until the pointer is repaired by invalidating the
        // block that broke it, or by a release that moves the anchor. The
        // PRE-EXISTING break must be surfaced, which is why the alert keeps
        // its own key here rather than folding into the reject above.
        if (!fJustCheck &&
                pindex->nHeight >= chainparams.GetConsensus().CTIPAnchorHeight) {
            for (const std::pair<const uint8_t, SidechainCTIP>& p : scdbCache.GetCTIP()) {
                const Coin& coin = view.AccessCoin(p.second.out);
                uint8_t nSidechainCoin;
                if (!coin.IsSpent() &&
                        coin.out.scriptPubKey.IsDrivechain(nSidechainCoin) &&
                        nSidechainCoin == p.first &&
                        coin.out.nValue == p.second.amount)
                    continue;

                bool fSpentByThisBlock = false;
                if (coin.IsSpent()) {
                    for (const CTransactionRef& ptx : block.vtx) {
                        for (const CTxIn& in : ptx->vin) {
                            if (in.prevout == p.second.out) {
                                fSpentByThisBlock = true;
                                break;
                            }
                        }
                        if (fSpentByThisBlock)
                            break;
                    }
                }

                if (!fSpentByThisBlock) {
                    const std::string strMessage = strprintf(
                        "Warning: treasury pointer of sidechain %u is already unanchored going into block %s (%s names no matching unspent output) and was NOT refused: this block did not break it, and no block can repair it. The slot is frozen for deposits and withdrawals until the block that broke it is invalidated or a release moves the anchor.",
                        p.first, block.GetHash().ToString(), p.second.out.ToString());
                    AlertSCDBNotify("ctip-anchor-preexisting", strMessage);
                    continue;
                }

                LogPrintf("%s: treasury pointer of sidechain %u is not anchored in block %s: %s\n",
                          __func__, p.first, block.GetHash().ToString(),
                          p.second.out.ToString());
                AlertSCDBDivergence(block.GetHash(), "bad-ctip-anchor");
                return state.DoS(0,
                    error("%s: treasury pointer of sidechain %u names no matching unspent output",
                          __func__, p.first),
                    REJECT_INVALID, "bad-ctip-anchor");
            }
        }
    }

    if (fJustCheck)
        return true;

    if (!WriteUndoDataForBlock(blockundo, state, pindex, chainparams))
        return false;

    if (!pindex->IsValid(BLOCK_VALID_SCRIPTS)) {
        pindex->RaiseValidity(BLOCK_VALID_SCRIPTS);
        setDirtyBlockIndex.insert(pindex);
    }

    if (!WriteTxIndexDataForBlock(block, state, pindex))
        return false;

    // The record no longer carries the entire sidechain table: only the active
    // slots are stored (see below), and ApplyLDBData rebuilds the rest on read.
    // A possible later step: keeping a single copy of each
    // sidechain in the database and storing only its hash per block, so that an
    // old sidechain could be re-activated by looking it up by hash.
    SidechainBlockData data;
    data.vWithdrawalStatus = scdbCache.GetState();
    data.vActivationStatus = scdbCache.GetSidechainActivationStatus();
    data.vSidechain = scdbCache.GetSidechains();

    // DELTA or CUMULATIVE, decided by the anchor cadence. On a delta block
    // vFailed and vSpent carry only what THIS block failed and spent; on an
    // anchor they carry the whole set, which is what makes an anchor the
    // restore point a reconstruction walk stops at.
    bool fAnchorRecord =
            (pindex->nHeight % SCDB_RECORD_ANCHOR_INTERVAL) == 0;

    // AND ALWAYS AN ANCHOR WHEN THIS BLOCK DROPPED FAILURES.
    // A delta only ADDS to the failed set, so a delta chain that spanned a
    // drop would put the dropped failures back on every restore. Anchoring the
    // dropping block means no walk ever crosses one: every walk stops at or
    // after the most recent drop. At most one extra anchor per failure, and
    // the cap bounds failures to 32 per slot per 129,600 blocks on mainnet.
    // If Update did not run for this block the value is the previous block's,
    // which can only force an anchor that was not needed - the safe direction.
    if (scdbCache.GetFailedPrunedLastUpdate() > 0)
        fAnchorRecord = true;

    // AND ALWAYS AN ANCHOR WHEN THE PARENT CANNOT BE A BASE. A delta is only
    // meaningful if the record chain behind it terminates at one that states
    // both sets in full, and that is NOT guaranteed by the cadence alone: a node
    // upgraded IN PLACE from 0.44.0 ('S' records) or 0.44.05 ('V') has a history
    // of records that state neither set, so the very first delta it wrote would
    // sit on top of one. Forcing an anchor there makes every delta chain
    // terminate correctly BY CONSTRUCTION, which is what lets
    // RestoreFailedSpentFromRecords be a walk rather than a guess.
    //
    // A delta parent is fine - it recurses to its own base by induction. A
    // missing parent record (genesis, or a gap) is not, so it forces an anchor
    // too, which is the conservative direction.
    if (!fAnchorRecord) {
        SidechainBlockData parentRecord;
        const bool fParentUsable =
                pindex->pprev && psidechaintree &&
                psidechaintree->GetBlockData(pindex->pprev->GetBlockHash(), parentRecord) &&
                (parentRecord.IsFailedSpentAnchor() || parentRecord.HasFailedSpentDelta());
        if (!fParentUsable)
            fAnchorRecord = true;
    }

    // The treasury pointer of each sidechain as of this block, and the bundle
    // failures standing at it. Both used to survive only in files written at
    // shutdown, so an unclean stop left the treasury describing an older block
    // with nothing to notice it. Recorded against the block, they are restored
    // by ResyncSCDB like the lists above.
    //
    // Taken from scdbCache, not the global: this is the copy that has the
    // block's effects applied and that is about to be moved over the global at
    // the commit point, exactly as the three lists above are.
    m_scdb_finding.Reset();
    data.vTreasury = scdbCache.GetTreasuryLog(&m_scdb_finding.audit);
    data.vFailed = fAnchorRecord
            ? scdbCache.GetFailedWithdrawalCache()
            : scdbCache.GetBlockFailedWithdrawals(block.GetHash());

    // A record is read back as a statement about the treasury of every active
    // sidechain - ApplyLDBData clears mapCTIP and installs exactly what the
    // record lists - so writing one from caches this node already knows are
    // inconsistent publishes that inconsistency into its own future, and a
    // slot the record fails to mention loses its pointer on every later
    // replay. It is still written: refusing would break the chain of records,
    // and dropping the treasury key would drop the spent-bundle key and the
    // compact table with it. But it must not be written SILENTLY, because the
    // resulting divergence is otherwise indistinguishable from a healthy node.
    //
    // Scope: DepositCacheSupportsTreasury sees only the caches, not the
    // chain, so it catches the deposits-present / pointer-absent shape only.
    // That is why every node runs a full -reindex on this release before the
    // fork height (see the release notes).
    //
    // Only MEASURED here, where scdbCache is still the copy the record was built
    // from. The alert is raised after the commit point below, because until then
    // the block is not accepted: a failed disk write returns an error from here,
    // and an alert saying the block was accepted and the record written would be
    // false - and would burn the one-hour notification throttle that the real
    // alert needs when the block is retried successfully.
    m_scdb_finding.fCacheUnsound =
            !scdbCache.DepositCacheSupportsTreasury(m_scdb_finding.nSlotUnsupported);
    m_scdb_finding.nStated = data.vTreasury.size();

    // The spent bundles, for the same reason and from the same copy. This field
    // has been in the record's serialisation from the start and nothing ever
    // filled it; see DB_SIDECHAIN_BLOCK_OP_SPENT for why it matters and why the
    // key rather than the contents has to say so.
    //
    // The whole cache, not just this block's spends, matching vFailed above:
    // ApplyLDBData restores state as of the block, not a per-block delta, and
    // each entry carries the block it belongs to so the map rebuilds exactly.
    // Unbounded in principle, as vFailed already is, and bounded in practice by
    // how rarely a bundle is paid out.
    if (fAnchorRecord) {
        data.vSpent = scdbCache.GetSpentWithdrawalCache();
    } else {
        data.vSpent = scdbCache.GetBlockSpentWithdrawals(block.GetHash());
    }

    // The sidechain table is a fixed 256-slot list; almost every block has at
    // most one active slot (the rest are canonical blanks). Serializing all 256
    // entries into the blocks/sidechain index on every block is what bloats that
    // DB (~15 KB/block). Persist only the ACTIVE slots (each carries its own
    // nSidechain index); SidechainDB::ApplyLDBData rebuilds the canonical
    // 256-slot blank table and overlays these back on read, so the restored
    // in-memory SCDB is byte-identical. Local-index serialization only --
    // nothing here is hashed into a block.
    {
        std::vector<Sidechain> vActive;
        for (const Sidechain& s : data.vSidechain) {
            if (s.fActive)
                vActive.push_back(s);
        }
        // A full (256-entry) vector marks the legacy/complete format on read, so
        // only substitute the sparse form when it is strictly smaller.
        // ApplyLDBData decides whether to re-expand from the vector's length
        // rather than from the key, so the compact table and the treasury log
        // are independent choices and the record below carries both.
        if (vActive.size() < data.vSidechain.size())
            data.vSidechain = std::move(vActive);

        // Written under its own DB key (see DB_SIDECHAIN_BLOCK_OP_SPENT, and
        // DB_SIDECHAIN_BLOCK_OP_TREASURY below it) so that an older binary,
        // which can neither re-expand the compact table nor read the appended
        // treasury fields nor tell a populated vSpent from the empty one it
        // always wrote, gets a clean "no data" and reindexes instead of
        // silently mis-reading a record it only partly understands.
        // The wide key from SidechainParamsHeight, where the window values
        // stop fitting the legacy 37-byte withdrawal-state form. Below it the
        // record is written exactly as 0.44.08 wrote it, which is what keeps
        // every existing blocks/sidechain database readable.
        //
        // Four keys, two independent dimensions: withdrawal-state WIDTH (by
        // height, consensus) and whether vFailed/vSpent are a DELTA (by the
        // node-local anchor cadence). Both dimensions get a key so that setting
        // SidechainParamsHeight later cannot silently drop the delta form.
        const bool fWideRecord =
                pindex->nHeight >= chainparams.GetConsensus().SidechainParamsHeight;
        if (fAnchorRecord) {
            data.sidechainop = fWideRecord ? DB_SIDECHAIN_BLOCK_OP_WIDE
                                           : DB_SIDECHAIN_BLOCK_OP_SPENT;
        } else {
            data.sidechainop = fWideRecord ? DB_SIDECHAIN_BLOCK_OP_DELTA_WIDE
                                           : DB_SIDECHAIN_BLOCK_OP_DELTA;
        }
    }

    // Whether the record was NEWLY written matters to the alert: reconnecting a
    // block whose record is already on disk writes nothing, so saying "and wrote
    // its sidechain record" would be false there.
    m_scdb_finding.fRecordNewlyWritten = !psidechaintree->HaveBlockData(block.GetHash());
    if (m_scdb_finding.fRecordNewlyWritten &&
            !psidechaintree->WriteSidechainBlockData(
                std::make_pair(block.GetHash(), data)))
    {
        return state.Error("Failed to write sidechain block data!");
    }

    if (vOPReturnData.size() && !popreturndb->HaveBlockData(block.GetHash()) &&
            !popreturndb->WriteBlockData(
                std::make_pair(block.GetHash(), vOPReturnData)))
    {
        return state.Error("Failed to write block OP_RETURN data!");
    }

    // SCDB commit point: every rejection/error above has passed (withdrawal
    // spends, SCDB update, and both disk writes), so publish the SCDB mutations
    // globally now, atomically with block acceptance under cs_main. Until here
    // the global SCDB was untouched, so a reject or disk-write error left it
    // unpoisoned. fJustCheck returned earlier, so TestBlockValidity never
    // reaches this and can no longer mutate the global SCDB.
    // Checked before the commit below, not after. The sidechain state and the
    // coins view have to move to this block together; publishing one and then
    // stopping on a failed check would leave the two describing different
    // blocks, which is not something a restart can work out.
    assert(pindex->phashBlock);

    if (skydogeEnabled) {
        scdb = std::move(scdbCache);
        // A verification walk (level 4 reconnects) is unwound by the guard in
        // VerifyDB; re-anchoring the mempool on each intermediate block would
        // evict deposits that are valid at the real tip.
        if (!fSidechainVerifying)
            mempool.UpdateCTIPFromBlock(scdb.GetCTIP(), false);
    }

    // add this block to the view's block chain
    view.SetBestBlock(pindex->GetBlockHash());

    int64_t nTime5 = GetTimeMicros(); nTimeIndex += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "    - Index writing: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime5 - nTime4), nTimeIndex * MICRO, nTimeIndex * MILLI / nBlocksTotal);

    int64_t nTime6 = GetTimeMicros(); nTimeCallbacks += nTime6 - nTime5;
    LogPrint(BCLog::BENCH, "    - Callbacks: %.2fms [%.2fs (%.2fms/blk)]\n", MILLI * (nTime6 - nTime5), nTimeCallbacks * MICRO, nTimeCallbacks * MILLI / nBlocksTotal);

    return true;
}

/**
 * Update the on-disk chain state.
 * The caches and indexes are flushed depending on the mode we're called with
 * if they're too large, if it's been a while since the last write,
 * or always and in all cases if we're in prune mode and are deleting files.
 */
bool static FlushStateToDisk(const CChainParams& chainparams, CValidationState &state, FlushStateMode mode, int nManualPruneHeight) {
    int64_t nMempoolUsage = mempool.DynamicMemoryUsage();
    LOCK(cs_main);
    static int64_t nLastWrite = 0;
    static int64_t nLastFlush = 0;
    static int64_t nLastSetChain = 0;
    std::set<int> setFilesToPrune;
    bool fFlushForPrune = false;
    bool fDoFullFlush = false;
    int64_t nNow = 0;
    try {
    {
        LOCK(cs_LastBlockFile);
        if (fPruneMode && (fCheckForPruning || nManualPruneHeight > 0) && !fReindex) {
            if (nManualPruneHeight > 0) {
                FindFilesToPruneManual(setFilesToPrune, nManualPruneHeight);
            } else {
                FindFilesToPrune(setFilesToPrune, chainparams.PruneAfterHeight());
                fCheckForPruning = false;
            }
            if (!setFilesToPrune.empty()) {
                fFlushForPrune = true;
                if (!fHavePruned) {
                    pblocktree->WriteFlag("prunedblockfiles", true);
                    fHavePruned = true;
                }
            }
        }
        nNow = GetTimeMicros();
        // Avoid writing/flushing immediately after startup.
        if (nLastWrite == 0) {
            nLastWrite = nNow;
        }
        if (nLastFlush == 0) {
            nLastFlush = nNow;
        }
        if (nLastSetChain == 0) {
            nLastSetChain = nNow;
        }
        int64_t nMempoolSizeMax = gArgs.GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000;
        int64_t cacheSize = pcoinsTip->DynamicMemoryUsage();
        int64_t nTotalSpace = nCoinCacheUsage + std::max<int64_t>(nMempoolSizeMax - nMempoolUsage, 0);
        // The cache is large and we're within 10% and 10 MiB of the limit, but we have time now (not in the middle of a block processing).
        bool fCacheLarge = mode == FLUSH_STATE_PERIODIC && cacheSize > std::max((9 * nTotalSpace) / 10, nTotalSpace - MAX_BLOCK_COINSDB_USAGE * 1024 * 1024);
        // The cache is over the limit, we have to write now.
        bool fCacheCritical = mode == FLUSH_STATE_IF_NEEDED && cacheSize > nTotalSpace;
        // It's been a while since we wrote the block index to disk. Do this frequently, so we don't need to redownload after a crash.
        bool fPeriodicWrite = mode == FLUSH_STATE_PERIODIC && nNow > nLastWrite + (int64_t)DATABASE_WRITE_INTERVAL * 1000000;
        // It's been very long since we flushed the cache. Do this infrequently, to optimize cache usage.
        bool fPeriodicFlush = mode == FLUSH_STATE_PERIODIC && nNow > nLastFlush + (int64_t)DATABASE_FLUSH_INTERVAL * 1000000;
        // Combine all conditions that result in a full cache flush.
        fDoFullFlush = (mode == FLUSH_STATE_ALWAYS) || fCacheLarge || fCacheCritical || fPeriodicFlush || fFlushForPrune;
        // Durability point for the sidechain / OP_RETURN indexes. Their per-block
        // records are buffered in memory (txdb.cpp) rather than written as they
        // are produced, and are persisted here in a single synchronous batch
        // *before* the chainstate best-block pointer advances. That ordering
        // keeps the invariant index-durable >= chainstate-durable: after any
        // crash, every block the chainstate knows about already has its snapshot
        // on disk (ResyncSCDB looks it up by hash). Because nothing is written
        // between these points there is no partially-written state to strand, so
        // the guarantee does not depend on the database's internal log handling.
        // Done before the pruning/block-index section below so that a failure
        // here cannot leave pruned block files deleted with a stale coins tip.
        if (fDoFullFlush) {
            if (psidechaintree && !psidechaintree->FlushBuffer())
                return AbortNode(state, "Failed to flush sidechain database");
            if (popreturndb && !popreturndb->FlushBuffer())
                return AbortNode(state, "Failed to flush OP_RETURN database");
        }
        // Write blocks and block index to disk.
        if ((fDoFullFlush || fPeriodicWrite)) {
            // Depend on nMinDiskSpace to ensure we can write block index
            if (!CheckDiskSpace(0))
                return state.Error("out of disk space");
            // First make sure all block and undo data is flushed to disk.
            if (!FlushBlockFile())
                return AbortNode(state, "Failed to flush block data to disk");
            // Then update all block file information (which may refer to block and undo files).
            {
                std::vector<std::pair<int, const CBlockFileInfo*> > vFiles;
                vFiles.reserve(setDirtyFileInfo.size());
                for (std::set<int>::iterator it = setDirtyFileInfo.begin(); it != setDirtyFileInfo.end(); ) {
                    vFiles.push_back(std::make_pair(*it, &vinfoBlockFile[*it]));
                    setDirtyFileInfo.erase(it++);
                }
                std::vector<const CBlockIndex*> vBlocks;
                vBlocks.reserve(setDirtyBlockIndex.size());
                for (std::set<CBlockIndex*>::iterator it = setDirtyBlockIndex.begin(); it != setDirtyBlockIndex.end(); ) {
                    vBlocks.push_back(*it);
                    setDirtyBlockIndex.erase(it++);
                }
                if (!pblocktree->WriteBatchSync(vFiles, nLastBlockFile, vBlocks)) {
                    return AbortNode(state, "Failed to write to block index database");
                }
            }
            // Finally remove any pruned files
            if (fFlushForPrune)
                UnlinkPrunedFiles(setFilesToPrune);
            nLastWrite = nNow;
        }
        // Flush best chain related state. This can only be done if the blocks / block index write was also done.
        if (fDoFullFlush) {
            // Typical Coin structures on disk are around 48 bytes in size.
            // Pushing a new one to the database can cause it to be written
            // twice (once in the log, and once in the tables). This is already
            // an overestimation, as most will delete an existing entry or
            // overwrite one. Still, use a conservative safety factor of 2.
            if (!CheckDiskSpace(48 * 2 * 2 * pcoinsTip->GetCacheSize()))
                return state.Error("out of disk space");
            // Flush the chainstate (which may refer to block index entries).
            if (!pcoinsTip->Flush())
                return AbortNode(state, "Failed to write to coin database");
            nLastFlush = nNow;
        }
    }
    if (fDoFullFlush || ((mode == FLUSH_STATE_ALWAYS || mode == FLUSH_STATE_PERIODIC) && nNow > nLastSetChain + (int64_t)DATABASE_WRITE_INTERVAL * 1000000)) {
        // Update best block in wallet (so we can detect restored wallets).
        GetMainSignals().SetBestChain(chainActive.GetLocator());
        nLastSetChain = nNow;
    }
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error while flushing: ") + e.what());
    }
    return true;
}

void FlushStateToDisk() {
    CValidationState state;
    const CChainParams& chainparams = Params();
    FlushStateToDisk(chainparams, state, FLUSH_STATE_ALWAYS);
}

void PruneAndFlush() {
    CValidationState state;
    fCheckForPruning = true;
    const CChainParams& chainparams = Params();
    FlushStateToDisk(chainparams, state, FLUSH_STATE_NONE);
}

static void DoWarning(const std::string& strWarning)
{
    static bool fWarned = false;
    SetMiscWarning(strWarning);
    if (!fWarned) {
        AlertNotify(strWarning);
        fWarned = true;
    }
}

/** Check warning conditions and do some notifications on new chain tip set. */
void static UpdateTip(const CBlockIndex *pindexNew, const CChainParams& chainParams) {
    // New best block
    mempool.AddTransactionsUpdated(1);

    cvBlockChange.notify_all();

    std::vector<std::string> warningMessages;
    if (!IsInitialBlockDownload())
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexNew;
        for (int bit = 0; bit < VERSIONBITS_NUM_BITS; bit++) {
            WarningBitsConditionChecker checker(bit);
            ThresholdState state = checker.GetStateFor(pindex, chainParams.GetConsensus(), warningcache[bit]);
            if (state == THRESHOLD_ACTIVE || state == THRESHOLD_LOCKED_IN) {
                const std::string strWarning = strprintf(_("Warning: unknown new rules activated (versionbit %i)"), bit);
                if (state == THRESHOLD_ACTIVE) {
                    DoWarning(strWarning);
                } else {
                    warningMessages.push_back(strWarning);
                }
            }
        }
        // Check the version of the last 100 blocks to see if we need to upgrade:
        for (int i = 0; i < 100 && pindex != nullptr; i++)
        {
            int32_t nExpectedVersion = ComputeBlockVersion(pindex->pprev, chainParams.GetConsensus());
            if (pindex->nVersion > VERSIONBITS_LAST_OLD_BLOCK_VERSION && (pindex->nVersion & ~nExpectedVersion) != 0)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            warningMessages.push_back(strprintf(_("%d of last 100 blocks have unexpected version"), nUpgraded));
        if (nUpgraded > 100/2)
        {
            std::string strWarning = _("Warning: Unknown block versions being mined! It's possible unknown rules are in effect");
            // notify GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            DoWarning(strWarning);
        }
    }
    LogPrintf("%s: new best=%s height=%d version=0x%08x log2_work=%.8g tx=%lu date='%s' progress=%f cache=%.1fMiB(%utxo)", __func__,
      pindexNew->GetBlockHash().ToString(), pindexNew->nHeight, pindexNew->nVersion,
      log(pindexNew->nChainWork.getdouble())/log(2.0), (unsigned long)pindexNew->nChainTx,
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexNew->GetBlockTime()),
      GuessVerificationProgress(chainParams.TxData(), pindexNew), pcoinsTip->DynamicMemoryUsage() * (1.0 / (1<<20)), pcoinsTip->GetCacheSize());
    if (!warningMessages.empty())
        LogPrintf(" warning='%s'", boost::algorithm::join(warningMessages, ", "));
    LogPrintf("\n");

}

/** Disconnect chainActive's tip.
  * After calling, the mempool will be in an inconsistent state, with
  * transactions from disconnected blocks being added to disconnectpool.  You
  * should make the mempool consistent again by calling UpdateMempoolForReorg.
  * with cs_main held.
  *
  * If disconnectpool is nullptr, then no disconnected transactions are added to
  * disconnectpool (note that the caller is responsible for mempool consistency
  * in any case).
  */
bool CChainState::DisconnectTip(CValidationState& state, const CChainParams& chainparams, DisconnectedBlockTransactions *disconnectpool)
{
    CBlockIndex *pindexDelete = chainActive.Tip();
    assert(pindexDelete);
    // Read block from disk.
    std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
    CBlock& block = *pblock;
    if (!ReadBlockFromDisk(block, pindexDelete, chainparams.GetConsensus()))
        return AbortNode(state, "Failed to read block");
    // Apply the block atomically to the chain state.
    int64_t nStart = GetTimeMicros();
    {
        CCoinsViewCache view(pcoinsTip.get());
        assert(view.GetBestBlock() == pindexDelete->GetBlockHash());
        if (DisconnectBlock(block, pindexDelete, view) != DISCONNECT_OK)
            return error("DisconnectTip(): DisconnectBlock %s failed", pindexDelete->GetBlockHash().ToString());
        bool flushed = view.Flush();
        assert(flushed);
    }
    LogPrint(BCLog::BENCH, "- Disconnect block: %.2fms\n", (GetTimeMicros() - nStart) * MILLI);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(chainparams, state, FLUSH_STATE_IF_NEEDED))
        return false;

    if (disconnectpool) {
        // Save transactions to re-add to mempool at end of reorg
        for (auto it = block.vtx.rbegin(); it != block.vtx.rend(); ++it) {
            disconnectpool->addTransaction(*it);
        }
        while (disconnectpool->DynamicMemoryUsage() > MAX_DISCONNECTED_TX_POOL_SIZE * 1000) {
            // Drop the earliest entry, and remove its children from the mempool.
            auto it = disconnectpool->queuedTx.get<insertion_order>().begin();
            mempool.removeRecursive(**it, MemPoolRemovalReason::REORG);
            disconnectpool->removeEntry(it);
        }
    }

    chainActive.SetTip(pindexDelete->pprev);

    UpdateTip(pindexDelete->pprev, chainparams);
    // Let wallets know transactions went from 1-confirmed to
    // 0-confirmed or conflicted:
    GetMainSignals().BlockDisconnected(pblock);
    return true;
}

static int64_t nTimeReadFromDisk = 0;
static int64_t nTimeConnectTotal = 0;
static int64_t nTimeFlush = 0;
static int64_t nTimeChainState = 0;
static int64_t nTimePostConnect = 0;

struct PerBlockConnectTrace {
    CBlockIndex* pindex = nullptr;
    std::shared_ptr<const CBlock> pblock;
    std::shared_ptr<std::vector<CTransactionRef>> conflictedTxs;
    PerBlockConnectTrace() : conflictedTxs(std::make_shared<std::vector<CTransactionRef>>()) {}
};
/**
 * Used to track blocks whose transactions were applied to the UTXO state as a
 * part of a single ActivateBestChainStep call.
 *
 * This class also tracks transactions that are removed from the mempool as
 * conflicts (per block) and can be used to pass all those transactions
 * through SyncTransaction.
 *
 * This class assumes (and asserts) that the conflicted transactions for a given
 * block are added via mempool callbacks prior to the BlockConnected() associated
 * with those transactions. If any transactions are marked conflicted, it is
 * assumed that an associated block will always be added.
 *
 * This class is single-use, once you call GetBlocksConnected() you have to throw
 * it away and make a new one.
 */
class ConnectTrace {
private:
    std::vector<PerBlockConnectTrace> blocksConnected;
    CTxMemPool &pool;

public:
    explicit ConnectTrace(CTxMemPool &_pool) : blocksConnected(1), pool(_pool) {
        pool.NotifyEntryRemoved.connect(boost::bind(&ConnectTrace::NotifyEntryRemoved, this, _1, _2));
    }

    ~ConnectTrace() {
        pool.NotifyEntryRemoved.disconnect(boost::bind(&ConnectTrace::NotifyEntryRemoved, this, _1, _2));
    }

    void BlockConnected(CBlockIndex* pindex, std::shared_ptr<const CBlock> pblock) {
        assert(!blocksConnected.back().pindex);
        assert(pindex);
        assert(pblock);
        blocksConnected.back().pindex = pindex;
        blocksConnected.back().pblock = std::move(pblock);
        blocksConnected.emplace_back();
    }

    std::vector<PerBlockConnectTrace>& GetBlocksConnected() {
        // We always keep one extra block at the end of our list because
        // blocks are added after all the conflicted transactions have
        // been filled in. Thus, the last entry should always be an empty
        // one waiting for the transactions from the next block. We pop
        // the last entry here to make sure the list we return is sane.
        assert(!blocksConnected.back().pindex);
        assert(blocksConnected.back().conflictedTxs->empty());
        blocksConnected.pop_back();
        return blocksConnected;
    }

    void NotifyEntryRemoved(CTransactionRef txRemoved, MemPoolRemovalReason reason) {
        assert(!blocksConnected.back().pindex);
        if (reason == MemPoolRemovalReason::CONFLICT) {
            blocksConnected.back().conflictedTxs->emplace_back(std::move(txRemoved));
        }
    }
};

/**
 * Connect a new block to chainActive. pblock is either nullptr or a pointer to a CBlock
 * corresponding to pindexNew, to bypass loading it again from disk.
 *
 * The block is added to connectTrace if connection succeeds.
 */
bool CChainState::ConnectTip(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexNew, const std::shared_ptr<const CBlock>& pblock, ConnectTrace& connectTrace, DisconnectedBlockTransactions &disconnectpool)
{
    assert(pindexNew->pprev == chainActive.Tip());
    // Read block from disk.
    int64_t nTime1 = GetTimeMicros();
    std::shared_ptr<const CBlock> pthisBlock;
    if (!pblock) {
        std::shared_ptr<CBlock> pblockNew = std::make_shared<CBlock>();
        if (!ReadBlockFromDisk(*pblockNew, pindexNew, chainparams.GetConsensus()))
            return AbortNode(state, "Failed to read block");
        pthisBlock = pblockNew;
    } else {
        pthisBlock = pblock;
    }
    const CBlock& blockConnecting = *pthisBlock;
    // Apply the block atomically to the chain state.
    int64_t nTime2 = GetTimeMicros(); nTimeReadFromDisk += nTime2 - nTime1;
    int64_t nTime3;
    LogPrint(BCLog::BENCH, "  - Load block from disk: %.2fms [%.2fs]\n", (nTime2 - nTime1) * MILLI, nTimeReadFromDisk * MICRO);
    {
        CCoinsViewCache view(pcoinsTip.get());
        bool rv = ConnectBlock(blockConnecting, state, pindexNew, view, chainparams);
        GetMainSignals().BlockChecked(blockConnecting, state);
        if (!rv) {
            if (state.IsInvalid())
                InvalidBlockFound(pindexNew, state);
            return error("ConnectTip(): ConnectBlock %s failed", pindexNew->GetBlockHash().ToString());
        }
        nTime3 = GetTimeMicros(); nTimeConnectTotal += nTime3 - nTime2;
        LogPrint(BCLog::BENCH, "  - Connect total: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime3 - nTime2) * MILLI, nTimeConnectTotal * MICRO, nTimeConnectTotal * MILLI / nBlocksTotal);
        bool flushed = view.Flush();
        assert(flushed);
    }
    int64_t nTime4 = GetTimeMicros(); nTimeFlush += nTime4 - nTime3;
    LogPrint(BCLog::BENCH, "  - Flush: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime4 - nTime3) * MILLI, nTimeFlush * MICRO, nTimeFlush * MILLI / nBlocksTotal);
    // Write the chain state to disk, if necessary.
    if (!FlushStateToDisk(chainparams, state, FLUSH_STATE_IF_NEEDED))
        return false;
    int64_t nTime5 = GetTimeMicros(); nTimeChainState += nTime5 - nTime4;
    LogPrint(BCLog::BENCH, "  - Writing chainstate: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime5 - nTime4) * MILLI, nTimeChainState * MICRO, nTimeChainState * MILLI / nBlocksTotal);

    // Remove conflicting transactions from the mempool.;
    mempool.removeForBlock(blockConnecting.vtx, pindexNew->nHeight);
    disconnectpool.removeForBlock(blockConnecting.vtx);

    // Small-block soft fork: the block just connected may be the last one
    // before the rule binds. Transactions admitted under the old standardness
    // limit are not grandfathered - once the next block is bound by
    // MAX_SMALL_BLOCK_SERIALIZED_SIZE an oversized one can never be mined by
    // an assembler that holds back SMALL_BLOCK_COINBASE_RESERVE_BYTES, so
    // leaving it in place would pin it and its descendants in every mempool
    // until the 14-day expiry while it holds a fee that can never be
    // collected. Fires only on the crossing block: from there on
    // AcceptToMemoryPool refuses them at the door, so there is nothing to
    // sweep and no per-block cost.
    //
    // Applied on -acceptnonstdtxn nodes too, and that is deliberate. Such a
    // node took the relay cap off on purpose and a transaction between the
    // cap and the block limit could in principle be mined by some other
    // assembler, so this does drop something it chose to keep. From this
    // block on AcceptToMemoryPool refuses the same transaction on every node,
    // whatever fRequireStandard says, so the purge and the door agree: one
    // rule beats two.
    {
        const int nSmallBlockHeight = chainparams.GetConsensus().SmallBlockHeight;
        if (pindexNew->nHeight + 1 >= nSmallBlockHeight &&
                (!pindexNew->pprev || pindexNew->pprev->nHeight + 1 < nSmallBlockHeight)) {
            mempool.removeForSmallBlockActivation(MAX_STANDARD_TX_SMALL_BLOCK_SIZE);
        }
    }

    // Update mempool CTIP
    bool skydogeEnabled = IsSkydogeEnabled(chainActive.Tip(), Params().GetConsensus());
    if (skydogeEnabled)
        mempool.UpdateCTIPFromBlock(scdb.GetCTIP(), false /* fDisconnect */);

    // Update chainActive & related variables.
    chainActive.SetTip(pindexNew);
    UpdateTip(pindexNew, chainparams);

    // Diagnostic only. While a configured -acksidechainproposal
    // value names no pending proposal, say so every block (not during initial
    // sync, when the proposal it names may simply not have been reached yet).
    if (!IsInitialBlockDownload())
        LogConfiguredSidechainProposalAckStatus(false /* fStartup */);

    // Only now is the block really on this node's chain: the flush above
    // succeeded and chainActive has moved. Anything ConnectBlock noticed about
    // this node's own SCDB caches is reported here, where every claim the alert
    // makes is true. VerifyDB reaches ConnectBlock without coming through here
    // at all, which is the point - re-verifying history is not acceptance.
    if (!m_scdb_finding.IsClean()) {
        AlertSCDBUnsoundRecord(pindexNew->GetBlockHash(), m_scdb_finding.fCacheUnsound,
                               m_scdb_finding.nSlotUnsupported, m_scdb_finding.nStated,
                               m_scdb_finding.fRecordNewlyWritten, m_scdb_finding.audit);
    }
    m_scdb_finding.Reset();

    int64_t nTime6 = GetTimeMicros(); nTimePostConnect += nTime6 - nTime5; nTimeTotal += nTime6 - nTime1;
    LogPrint(BCLog::BENCH, "  - Connect postprocess: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime5) * MILLI, nTimePostConnect * MICRO, nTimePostConnect * MILLI / nBlocksTotal);
    LogPrint(BCLog::BENCH, "- Connect block: %.2fms [%.2fs (%.2fms/blk)]\n", (nTime6 - nTime1) * MILLI, nTimeTotal * MICRO, nTimeTotal * MILLI / nBlocksTotal);

    connectTrace.BlockConnected(pindexNew, std::move(pthisBlock));
    return true;
}

/**
 * Return the tip of the chain with the most work in it, that isn't
 * known to be invalid (it's however far from certain to be valid).
 */
CBlockIndex* CChainState::FindMostWorkChain() {
    do {
        CBlockIndex *pindexNew = nullptr;

        // Find the best candidate header.
        {
            std::set<CBlockIndex*, CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexCandidates.rbegin();
            if (it == setBlockIndexCandidates.rend())
                return nullptr;
            pindexNew = *it;
        }

        // Check whether all blocks on the path between the currently active chain and the candidate are valid.
        // Just going until the active chain is an optimization, as we know all blocks in it are valid already.
        CBlockIndex *pindexTest = pindexNew;
        bool fInvalidAncestor = false;
        while (pindexTest && !chainActive.Contains(pindexTest)) {
            assert(pindexTest->nChainTx || pindexTest->nHeight == 0);

            // Pruned nodes may have entries in setBlockIndexCandidates for
            // which block files have been deleted.  Remove those as candidates
            // for the most work chain if we come across them; we can't switch
            // to a chain unless we have all the non-active-chain parent blocks.
            bool fFailedChain = pindexTest->nStatus & BLOCK_FAILED_MASK;
            bool fMissingData = !(pindexTest->nStatus & BLOCK_HAVE_DATA);
            if (fFailedChain || fMissingData) {
                // Candidate chain is not usable (either invalid or missing data)
                if (fFailedChain && (pindexBestInvalid == nullptr || pindexNew->nChainWork > pindexBestInvalid->nChainWork))
                    pindexBestInvalid = pindexNew;
                CBlockIndex *pindexFailed = pindexNew;
                // Remove the entire chain from the set.
                while (pindexTest != pindexFailed) {
                    if (fFailedChain) {
                        pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    } else if (fMissingData) {
                        // If we're missing data, then add back to mapBlocksUnlinked,
                        // so that if the block arrives in the future we can try adding
                        // to setBlockIndexCandidates again.
                        mapBlocksUnlinked.insert(std::make_pair(pindexFailed->pprev, pindexFailed));
                    }
                    setBlockIndexCandidates.erase(pindexFailed);
                    pindexFailed = pindexFailed->pprev;
                }
                setBlockIndexCandidates.erase(pindexTest);
                fInvalidAncestor = true;
                break;
            }
            pindexTest = pindexTest->pprev;
        }
        if (!fInvalidAncestor)
            return pindexNew;
    } while(true);
}

/** Delete all entries in setBlockIndexCandidates that are worse than the current tip. */
void CChainState::PruneBlockIndexCandidates() {
    // Note that we can't delete the current block itself, as we may need to return to it later in case a
    // reorganization to a better block fails.
    std::set<CBlockIndex*, CBlockIndexWorkComparator>::iterator it = setBlockIndexCandidates.begin();
    while (it != setBlockIndexCandidates.end() && setBlockIndexCandidates.value_comp()(*it, chainActive.Tip())) {
        setBlockIndexCandidates.erase(it++);
    }
    // Either the current tip or a successor of it we're working towards is left in setBlockIndexCandidates.
    assert(!setBlockIndexCandidates.empty());
}

//! Put the deposit cache back when a disconnect has left it unable to account
//! for the treasury it is serving.
//!
//! A slot can change occupant: a proposal naming an already-active slot
//! activates, and the incoming sidechain starts clean, so activation clears
//! that slot's deposits. That is right going forwards. Going backwards it is
//! not. The per-block record restores the slot table and the treasury pointer,
//! but the deposits have no per-block representation to be restored from -
//! they carry whole transactions and are re-derivable, which is why they were
//! deliberately kept out of the record - and Undo only ever removes deposits,
//! never puts them back. The node therefore comes out of the reorg naming a
//! treasury output it holds no deposits behind. The output is still on chain
//! and still unspent; the node has simply lost track of where it is.
//!
//! The repair is the pass a stale cache already gets at startup, for the same
//! reason it is used there: rebuilding from blocks reuses the production
//! collection rather than adding a second implementation of connect-time
//! semantics, which is the one way a repair of this kind manufactures the
//! divergence it exists to remove.
//!
//! Only called where blocks were actually disconnected. Connecting a block
//! cannot produce this state, so a node moving forwards never pays for the
//! check.
static void RepairSidechainDepositsIfNeeded()
{
    AssertLockHeld(cs_main);

    // Set when a rebuild ran and did not settle it. A state this pass cannot
    // fix then costs one pass rather than one for every block that follows.
    // Cleared as soon as the cache is sound again, by whatever route.
    static bool fRepairDidNotTake = false;

    uint8_t nSlot = 0;
    if (scdb.DepositCacheSupportsTreasury(nSlot)) {
        fRepairDidNotTake = false;
        return;
    }

    if (fRepairDidNotTake)
        return;

    LogPrintf("%s: Deposit cache does not account for the treasury of sidechain %u "
              "after disconnecting blocks; rebuilding it from blocks.\n",
              __func__, nSlot);

    std::string strError;
    if (!RebuildSidechainDeposits(strError)) {
        fRepairDidNotTake = true;
        LogPrintf("%s: Sidechain rebuild failed: %s\n", __func__, strError);
        return;
    }

    if (!scdb.DepositCacheSupportsTreasury(nSlot)) {
        fRepairDidNotTake = true;
        LogPrintf("%s: Deposit cache still does not account for the treasury of "
                  "sidechain %u after rebuilding.\n", __func__, nSlot);
        return;
    }

    LogPrintf("%s: Deposit cache rebuilt.\n", __func__);
}

/**
 * Try to make some progress towards making pindexMostWork the active block.
 * pblock is either nullptr or a pointer to a CBlock corresponding to pindexMostWork.
 */
bool CChainState::ActivateBestChainStep(CValidationState& state, const CChainParams& chainparams, CBlockIndex* pindexMostWork, const std::shared_ptr<const CBlock>& pblock, bool& fInvalidFound, ConnectTrace& connectTrace)
{
    AssertLockHeld(cs_main);
    const CBlockIndex *pindexOldTip = chainActive.Tip();
    const CBlockIndex *pindexFork = chainActive.FindFork(pindexMostWork);

    // Disconnect active blocks which are no longer in the best chain.
    bool fBlocksDisconnected = false;
    DisconnectedBlockTransactions disconnectpool;
    while (chainActive.Tip() && chainActive.Tip() != pindexFork) {
        if (!DisconnectTip(state, chainparams, &disconnectpool)) {
            // This is likely a fatal error, but keep the mempool consistent,
            // just in case. Only remove from the mempool in this case.
            UpdateMempoolForReorg(disconnectpool, false);
            return false;
        }
        fBlocksDisconnected = true;
    }

    // Build list of new blocks to connect.
    std::vector<CBlockIndex*> vpindexToConnect;
    bool fContinue = true;
    int nHeight = pindexFork ? pindexFork->nHeight : -1;
    while (fContinue && nHeight != pindexMostWork->nHeight) {
        // Don't iterate the entire list of potential improvements toward the best tip, as we likely only need
        // a few blocks along the way.
        int nTargetHeight = std::min(nHeight + 32, pindexMostWork->nHeight);
        vpindexToConnect.clear();
        vpindexToConnect.reserve(nTargetHeight - nHeight);
        CBlockIndex *pindexIter = pindexMostWork->GetAncestor(nTargetHeight);
        while (pindexIter && pindexIter->nHeight != nHeight) {
            vpindexToConnect.push_back(pindexIter);
            pindexIter = pindexIter->pprev;
        }
        nHeight = nTargetHeight;

        // Connect new blocks.
        for (CBlockIndex *pindexConnect : reverse_iterate(vpindexToConnect)) {
            if (!ConnectTip(state, chainparams, pindexConnect, pindexConnect == pindexMostWork ? pblock : std::shared_ptr<const CBlock>(), connectTrace, disconnectpool)) {
                if (state.IsInvalid()) {
                    // The block violates a consensus rule.
                    if (!state.CorruptionPossible())
                        InvalidChainFound(vpindexToConnect.back());
                    state = CValidationState();
                    fInvalidFound = true;
                    fContinue = false;
                    break;
                } else {
                    // A system error occurred (disk space, database error, ...).
                    // Make the mempool consistent with the current tip, just in case
                    // any observers try to use it before shutdown.
                    UpdateMempoolForReorg(disconnectpool, false);
                    return false;
                }
            } else {
                PruneBlockIndexCandidates();
                if (!pindexOldTip || chainActive.Tip()->nChainWork > pindexOldTip->nChainWork) {
                    // We're in a better position than we were. Return temporarily to release the lock.
                    fContinue = false;
                    break;
                }
            }
        }
    }

    if (fBlocksDisconnected) {
        // If any blocks were disconnected, disconnectpool may be non empty.  Add
        // any disconnected transactions back to the mempool.
        UpdateMempoolForReorg(disconnectpool, true);

        // Done after the reconnects above rather than beside the disconnects,
        // so a reorg that removes a slot handover and then puts one back is
        // judged on where it ended up. The check is over the active sidechains
        // and costs nothing when the cache is sound.
        RepairSidechainDepositsIfNeeded();
    }
    mempool.check(pcoinsTip.get());

    // Callbacks/notifications for a new best chain.
    if (fInvalidFound)
        CheckForkWarningConditionsOnNewFork(vpindexToConnect.back());
    else
        CheckForkWarningConditions();

    return true;
}

static void NotifyHeaderTip() {
    bool fNotify = false;
    bool fInitialBlockDownload = false;
    static CBlockIndex* pindexHeaderOld = nullptr;
    CBlockIndex* pindexHeader = nullptr;
    {
        LOCK(cs_main);
        pindexHeader = pindexBestHeader;

        if (pindexHeader != pindexHeaderOld) {
            fNotify = true;
            fInitialBlockDownload = IsInitialBlockDownload();
            pindexHeaderOld = pindexHeader;
        }
    }
    // Send block tip changed notifications without cs_main
    if (fNotify) {
        uiInterface.NotifyHeaderTip(fInitialBlockDownload, pindexHeader);
    }
}

/**
 * Make the best chain active, in multiple steps. The result is either failure
 * or an activated best chain. pblock is either nullptr or a pointer to a block
 * that is already loaded (to avoid loading it again from disk).
 */
bool CChainState::ActivateBestChain(CValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock) {
    // Note that while we're often called here from ProcessNewBlock, this is
    // far from a guarantee. Things in the P2P/RPC will often end up calling
    // us in the middle of ProcessNewBlock - do not assume pblock is set
    // sanely for performance or correctness!
    AssertLockNotHeld(cs_main);

    CBlockIndex *pindexMostWork = nullptr;
    CBlockIndex *pindexNewTip = nullptr;
    int nStopAtHeight = gArgs.GetArg("-stopatheight", DEFAULT_STOPATHEIGHT);
    do {
        boost::this_thread::interruption_point();

        if (GetMainSignals().CallbacksPending() > 10) {
            // Block until the validation queue drains. This should largely
            // never happen in normal operation, however may happen during
            // reindex, causing memory blowup if we run too far ahead.
            SyncWithValidationInterfaceQueue();
        }

        const CBlockIndex *pindexFork;
        bool fInitialDownload;
        {
            LOCK(cs_main);
            ConnectTrace connectTrace(mempool); // Destructed before cs_main is unlocked

            CBlockIndex *pindexOldTip = chainActive.Tip();
            if (pindexMostWork == nullptr) {
                pindexMostWork = FindMostWorkChain();
            }

            // Whether we have anything to do at all.
            if (pindexMostWork == nullptr || pindexMostWork == chainActive.Tip())
                return true;

            bool fInvalidFound = false;
            std::shared_ptr<const CBlock> nullBlockPtr;
            if (!ActivateBestChainStep(state, chainparams, pindexMostWork, pblock && pblock->GetHash() == pindexMostWork->GetBlockHash() ? pblock : nullBlockPtr, fInvalidFound, connectTrace))
                return false;

            if (fInvalidFound) {
                // Wipe cache, we may need another branch now.
                pindexMostWork = nullptr;
            }
            pindexNewTip = chainActive.Tip();
            pindexFork = chainActive.FindFork(pindexOldTip);
            fInitialDownload = IsInitialBlockDownload();

            for (const PerBlockConnectTrace& trace : connectTrace.GetBlocksConnected()) {
                assert(trace.pblock && trace.pindex);
                GetMainSignals().BlockConnected(trace.pblock, trace.pindex, trace.conflictedTxs);
            }
        }
        // When we reach this point, we switched to a new tip (stored in pindexNewTip).

        // Notifications/callbacks that can run without cs_main

        // Notify external listeners about the new tip.
        GetMainSignals().UpdatedBlockTip(pindexNewTip, pindexFork, fInitialDownload);

        // Always notify the UI if a new block tip was connected
        if (pindexFork != pindexNewTip) {
            uiInterface.NotifyBlockTip(fInitialDownload, pindexNewTip);
        }

        if (nStopAtHeight && pindexNewTip && pindexNewTip->nHeight >= nStopAtHeight) StartShutdown();

        // We check shutdown only after giving ActivateBestChainStep a chance to run once so that we
        // never shutdown before connecting the genesis block during LoadChainTip(). Previously this
        // caused an assert() failure during shutdown in such cases as the UTXO DB flushing checks
        // that the best block hash is non-null.
        if (ShutdownRequested())
            break;
    } while (pindexNewTip != pindexMostWork);
    CheckBlockIndex(chainparams.GetConsensus());

    // Write changes periodically to disk, after relay.
    if (!FlushStateToDisk(chainparams, state, FLUSH_STATE_PERIODIC)) {
        return false;
    }

    return true;
}
bool ActivateBestChain(CValidationState &state, const CChainParams& chainparams, std::shared_ptr<const CBlock> pblock) {
    return g_chainstate.ActivateBestChain(state, chainparams, std::move(pblock));
}

bool CChainState::PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex *pindex)
{
    {
        LOCK(cs_main);
        if (pindex->nChainWork < chainActive.Tip()->nChainWork) {
            // Nothing to do, this block is not at the tip.
            return true;
        }
        if (chainActive.Tip()->nChainWork > nLastPreciousChainwork) {
            // The chain has been extended since the last call, reset the counter.
            nBlockReverseSequenceId = -1;
        }
        nLastPreciousChainwork = chainActive.Tip()->nChainWork;
        setBlockIndexCandidates.erase(pindex);
        pindex->nSequenceId = nBlockReverseSequenceId;
        if (nBlockReverseSequenceId > std::numeric_limits<int32_t>::min()) {
            // We can't keep reducing the counter if somebody really wants to
            // call preciousblock 2**31-1 times on the same set of tips...
            nBlockReverseSequenceId--;
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && pindex->nChainTx) {
            setBlockIndexCandidates.insert(pindex);
            PruneBlockIndexCandidates();
        }
    }

    return ActivateBestChain(state, params, std::shared_ptr<const CBlock>());
}
bool PreciousBlock(CValidationState& state, const CChainParams& params, CBlockIndex *pindex) {
    return g_chainstate.PreciousBlock(state, params, pindex);
}

bool CChainState::InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex)
{
    AssertLockHeld(cs_main);

    // We first disconnect backwards and then mark the blocks as invalid.
    // This prevents a case where pruned nodes may fail to invalidateblock
    // and be left unable to start as they have no tip candidates (as there
    // are no blocks that meet the "have data and are not invalid per
    // nStatus" criteria for inclusion in setBlockIndexCandidates).

    bool pindex_was_in_chain = false;
    CBlockIndex *invalid_walk_tip = chainActive.Tip();

    DisconnectedBlockTransactions disconnectpool;
    while (chainActive.Contains(pindex)) {
        pindex_was_in_chain = true;
        // ActivateBestChain considers blocks already in chainActive
        // unconditionally valid already, so force disconnect away from it.
        if (!DisconnectTip(state, chainparams, &disconnectpool)) {
            // It's probably hopeless to try to make the mempool consistent
            // here if DisconnectTip failed, but we can try.
            UpdateMempoolForReorg(disconnectpool, false);
            return false;
        }
    }

    // Now mark the blocks we just disconnected as descendants invalid
    // (note this may not be all descendants).
    while (pindex_was_in_chain && invalid_walk_tip != pindex) {
        invalid_walk_tip->nStatus |= BLOCK_FAILED_CHILD;
        setDirtyBlockIndex.insert(invalid_walk_tip);
        setBlockIndexCandidates.erase(invalid_walk_tip);
        invalid_walk_tip = invalid_walk_tip->pprev;
    }

    // Mark the block itself as invalid.
    pindex->nStatus |= BLOCK_FAILED_VALID;
    setDirtyBlockIndex.insert(pindex);
    setBlockIndexCandidates.erase(pindex);
    g_failed_blocks.insert(pindex);

    // DisconnectTip will add transactions to disconnectpool; try to add these
    // back to the mempool.
    UpdateMempoolForReorg(disconnectpool, true);

    // This route reaches its final tip here rather than in ActivateBestChain:
    // by the time the caller gets there the most-work chain is already the
    // active one, so it returns before doing any work. The repair has to be
    // made where the disconnecting happened.
    if (pindex_was_in_chain)
        RepairSidechainDepositsIfNeeded();

    // The resulting new best tip may not be in setBlockIndexCandidates anymore, so
    // add it again.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && !setBlockIndexCandidates.value_comp()(it->second, chainActive.Tip())) {
            setBlockIndexCandidates.insert(it->second);
        }
        it++;
    }

    InvalidChainFound(pindex);
    uiInterface.NotifyBlockTip(IsInitialBlockDownload(), pindex->pprev);
    return true;
}
bool InvalidateBlock(CValidationState& state, const CChainParams& chainparams, CBlockIndex *pindex) {
    return g_chainstate.InvalidateBlock(state, chainparams, pindex);
}

bool CChainState::ResetBlockFailureFlags(CBlockIndex *pindex) {
    AssertLockHeld(cs_main);

    int nHeight = pindex->nHeight;

    // Remove the invalidity flag from this block and all its descendants.
    BlockMap::iterator it = mapBlockIndex.begin();
    while (it != mapBlockIndex.end()) {
        if (!it->second->IsValid() && it->second->GetAncestor(nHeight) == pindex) {
            it->second->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(it->second);
            if (it->second->IsValid(BLOCK_VALID_TRANSACTIONS) && it->second->nChainTx && setBlockIndexCandidates.value_comp()(chainActive.Tip(), it->second)) {
                setBlockIndexCandidates.insert(it->second);
            }
            if (it->second == pindexBestInvalid) {
                // Reset invalid block marker if it was pointing to one of those.
                pindexBestInvalid = nullptr;
            }
            g_failed_blocks.erase(it->second);
        }
        it++;
    }

    // Remove the invalidity flag from all ancestors too.
    while (pindex != nullptr) {
        if (pindex->nStatus & BLOCK_FAILED_MASK) {
            pindex->nStatus &= ~BLOCK_FAILED_MASK;
            setDirtyBlockIndex.insert(pindex);
        }
        pindex = pindex->pprev;
    }
    return true;
}
bool ResetBlockFailureFlags(CBlockIndex *pindex) {
    return g_chainstate.ResetBlockFailureFlags(pindex);
}

CBlockIndex* CChainState::AddToBlockIndex(const CBlockHeader& block)
{
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end())
        return it->second;

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(block);
    // We assign the sequence id to blocks only when the full data is available,
    // to avoid miners withholding blocks but broadcasting headers, to get a
    // competitive advantage.
    pindexNew->nSequenceId = 0;
    BlockMap::iterator mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    BlockMap::iterator miPrev = mapBlockIndex.find(block.hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
        pindexNew->BuildSkip();
    }
    pindexNew->nTimeMax = (pindexNew->pprev ? std::max(pindexNew->pprev->nTimeMax, pindexNew->nTime) : pindexNew->nTime);
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + GetBlockProof(*pindexNew);
    pindexNew->RaiseValidity(BLOCK_VALID_TREE);
    if (pindexBestHeader == nullptr || pindexBestHeader->nChainWork < pindexNew->nChainWork)
        pindexBestHeader = pindexNew;

    setDirtyBlockIndex.insert(pindexNew);

    return pindexNew;
}

/** Mark a block as having its data received and checked (up to BLOCK_VALID_TRANSACTIONS). */
bool CChainState::ReceivedBlockTransactions(const CBlock &block, CValidationState& state, CBlockIndex *pindexNew, const CDiskBlockPos& pos, const Consensus::Params& consensusParams)
{
    pindexNew->nTx = block.vtx.size();
    pindexNew->nChainTx = 0;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus |= BLOCK_HAVE_DATA;
    if (IsWitnessEnabled(pindexNew->pprev, consensusParams)) {
        pindexNew->nStatus |= BLOCK_OPT_WITNESS;
    }

    pindexNew->RaiseValidity(BLOCK_VALID_TRANSACTIONS);
    setDirtyBlockIndex.insert(pindexNew);

    if (pindexNew->pprev == nullptr || pindexNew->pprev->nChainTx) {
        // If pindexNew is the genesis block or all parents are BLOCK_VALID_TRANSACTIONS.
        std::deque<CBlockIndex*> queue;
        queue.push_back(pindexNew);

        // Recursively process any descendant blocks that now may be eligible to be connected.
        while (!queue.empty()) {
            CBlockIndex *pindex = queue.front();
            queue.pop_front();
            pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
            {
                LOCK(cs_nBlockSequenceId);
                pindex->nSequenceId = nBlockSequenceId++;
            }
            if (chainActive.Tip() == nullptr || !setBlockIndexCandidates.value_comp()(pindex, chainActive.Tip())) {
                setBlockIndexCandidates.insert(pindex);
            }
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex);
            while (range.first != range.second) {
                std::multimap<CBlockIndex*, CBlockIndex*>::iterator it = range.first;
                queue.push_back(it->second);
                range.first++;
                mapBlocksUnlinked.erase(it);
            }
        }
    } else {
        if (pindexNew->pprev && pindexNew->pprev->IsValid(BLOCK_VALID_TREE)) {
            mapBlocksUnlinked.insert(std::make_pair(pindexNew->pprev, pindexNew));
        }
    }
    return true;
}

static bool FindBlockPos(CDiskBlockPos &pos, unsigned int nAddSize, unsigned int nHeight, uint64_t nTime, bool fKnown = false)
{
    LOCK(cs_LastBlockFile);

    unsigned int nFile = fKnown ? pos.nFile : nLastBlockFile;
    if (vinfoBlockFile.size() <= nFile) {
        vinfoBlockFile.resize(nFile + 1);
    }

    if (!fKnown) {
        while (vinfoBlockFile[nFile].nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            nFile++;
            if (vinfoBlockFile.size() <= nFile) {
                vinfoBlockFile.resize(nFile + 1);
            }
        }
        pos.nFile = nFile;
        pos.nPos = vinfoBlockFile[nFile].nSize;
    }

    if ((int)nFile != nLastBlockFile) {
        if (!fKnown) {
            LogPrintf("Leaving block file %i: %s\n", nLastBlockFile, vinfoBlockFile[nLastBlockFile].ToString());
        }
        // The file being left behind is finalized here and never written again,
        // so if it cannot be flushed do not move on to the next one - the block
        // about to be stored would be recorded against a file whose contents
        // are not known to be on disk.
        if (!FlushBlockFile(!fKnown))
            return error("%s: failed to flush block file %i", __func__, nLastBlockFile);
        nLastBlockFile = nFile;
    }

    vinfoBlockFile[nFile].AddBlock(nHeight, nTime);
    if (fKnown)
        vinfoBlockFile[nFile].nSize = std::max(pos.nPos + nAddSize, vinfoBlockFile[nFile].nSize);
    else
        vinfoBlockFile[nFile].nSize += nAddSize;

    if (!fKnown) {
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (vinfoBlockFile[nFile].nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks) {
            if (fPruneMode)
                fCheckForPruning = true;
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos)) {
                FILE *file = OpenBlockFile(pos);
                if (file) {
                    LogPrintf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            }
            else
                return error("out of disk space");
        }
    }

    setDirtyFileInfo.insert(nFile);
    return true;
}

static bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    pos.nPos = vinfoBlockFile[nFile].nUndoSize;
    nNewSize = vinfoBlockFile[nFile].nUndoSize += nAddSize;
    setDirtyFileInfo.insert(nFile);

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        if (fPruneMode)
            fCheckForPruning = true;
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos)) {
            FILE *file = OpenUndoFile(pos);
            if (file) {
                LogPrintf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        }
        else
            return state.Error("out of disk space");
    }

    return true;
}

static bool CheckBlockHeader(const CBlockHeader& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW = true)
{
    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(block.GetHash(), block.nBits, consensusParams))
        return state.DoS(50, false, REJECT_INVALID, "high-hash", false, "proof of work failed");

    return true;
}

bool CheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, bool fCheckPOW, bool fCheckMerkleRoot)
{
    // These are checks that are independent of context.

    if (block.fChecked)
        return true;

    // Check that the header is valid (particularly PoW).  This is mostly
    // redundant with the call in AcceptBlockHeader.
    if (!CheckBlockHeader(block, state, consensusParams, fCheckPOW))
        return false;

    // Check the merkle root.
    if (fCheckMerkleRoot) {
        bool mutated;
        uint256 hashMerkleRoot2 = BlockMerkleRoot(block, &mutated);
        if (block.hashMerkleRoot != hashMerkleRoot2)
            return state.DoS(100, false, REJECT_INVALID, "bad-txnmrklroot", true, "hashMerkleRoot mismatch");

        // Check for merkle tree malleability (CVE-2012-2459): repeating sequences
        // of transactions in a block without affecting the merkle root of a block,
        // while still invalidating it.
        if (mutated)
            return state.DoS(100, false, REJECT_INVALID, "bad-txns-duplicate", true, "duplicate transaction");
    }

    // All potential-corruption validation must be done before we do any
    // transaction validation, as otherwise we may mark the header as invalid
    // because we receive the wrong transactions for it.
    // Note that witness malleability is checked in ContextualCheckBlock, so no
    // checks that use witness data may be performed here.

    // Size limits
    if (block.vtx.empty() || block.vtx.size() * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT || ::GetSerializeSize(block, SER_NETWORK, PROTOCOL_VERSION | SERIALIZE_TRANSACTION_NO_WITNESS) * WITNESS_SCALE_FACTOR > MAX_BLOCK_WEIGHT)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-length", false, "size limits failed");

    // First transaction must be coinbase, the rest must not be
    if (block.vtx.empty() || !block.vtx[0]->IsCoinBase())
        return state.DoS(100, false, REJECT_INVALID, "bad-cb-missing", false, "first tx is not coinbase");
    for (unsigned int i = 1; i < block.vtx.size(); i++)
        if (block.vtx[i]->IsCoinBase())
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-multiple", false, "more than one coinbase");

    // Check transactions
    for (const auto& tx : block.vtx)
        if (!CheckTransaction(*tx, state))
            return state.Invalid(false, state.GetRejectCode(), state.GetRejectReason(),
                                 strprintf("Transaction check failed (tx hash %s) %s", tx->GetHash().ToString(), state.GetDebugMessage()));

    unsigned int nSigOps = 0;
    for (const auto& tx : block.vtx)
    {
        nSigOps += GetLegacySigOpCount(*tx);
    }
    if (nSigOps * WITNESS_SCALE_FACTOR > MAX_BLOCK_SIGOPS_COST)
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-sigops", false, "out-of-bounds SigOpCount");

    if (fCheckPOW && fCheckMerkleRoot)
        block.fChecked = true;

    return true;
}

bool IsWitnessEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    return (VersionBitsState(pindexPrev, params, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == THRESHOLD_ACTIVE);
}

bool IsSkydogeEnabled(const CBlockIndex* pindexPrev, const Consensus::Params& params)
{
    LOCK(cs_main);
    return (pindexPrev && pindexPrev->nHeight + 1 >= params.DrivechainHeight);
}

// Compute at which vout of the block's coinbase transaction the witness
// commitment occurs, or -1 if not found.
int GetWitnessCommitmentIndex(const CBlock& block)
{
    int commitpos = -1;
    if (!block.vtx.empty()) {
        for (size_t o = 0; o < block.vtx[0]->vout.size(); o++) {
            if (block.vtx[0]->vout[o].scriptPubKey.size() >= 38 && block.vtx[0]->vout[o].scriptPubKey[0] == OP_RETURN && block.vtx[0]->vout[o].scriptPubKey[1] == 0x24 && block.vtx[0]->vout[o].scriptPubKey[2] == 0xaa && block.vtx[0]->vout[o].scriptPubKey[3] == 0x21 && block.vtx[0]->vout[o].scriptPubKey[4] == 0xa9 && block.vtx[0]->vout[o].scriptPubKey[5] == 0xed) {
                commitpos = o;
            }
        }
    }
    return commitpos;
}

void UpdateUncommittedBlockStructures(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    int commitpos = GetWitnessCommitmentIndex(block);
    static const std::vector<unsigned char> nonce(32, 0x00);
    if (commitpos != -1 && IsWitnessEnabled(pindexPrev, consensusParams) && !block.vtx[0]->HasWitness()) {
        CMutableTransaction tx(*block.vtx[0]);
        tx.vin[0].scriptWitness.stack.resize(1);
        tx.vin[0].scriptWitness.stack[0] = nonce;
        block.vtx[0] = MakeTransactionRef(std::move(tx));
    }
}

std::vector<unsigned char> GenerateCoinbaseCommitment(CBlock& block, const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    std::vector<unsigned char> commitment;
    int commitpos = GetWitnessCommitmentIndex(block);
    std::vector<unsigned char> ret(32, 0x00);
    if (consensusParams.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout != 0) {
        if (commitpos == -1) {
            uint256 witnessroot = BlockWitnessMerkleRoot(block, nullptr);
            CHash256().Write(witnessroot.begin(), 32).Write(ret.data(), 32).Finalize(witnessroot.begin());
            CTxOut out;
            out.nValue = 0;
            out.scriptPubKey.resize(38);
            out.scriptPubKey[0] = OP_RETURN;
            out.scriptPubKey[1] = 0x24;
            out.scriptPubKey[2] = 0xaa;
            out.scriptPubKey[3] = 0x21;
            out.scriptPubKey[4] = 0xa9;
            out.scriptPubKey[5] = 0xed;
            memcpy(&out.scriptPubKey[6], witnessroot.begin(), 32);
            commitment = std::vector<unsigned char>(out.scriptPubKey.begin(), out.scriptPubKey.end());
            CMutableTransaction tx(*block.vtx[0]);
            tx.vout.push_back(out);
            block.vtx[0] = MakeTransactionRef(std::move(tx));
        }
    }
    UpdateUncommittedBlockStructures(block, pindexPrev, consensusParams);
    return commitment;
}

CTxOut GetCriticalHashCommitmentOut(const CCriticalData& data)
{
    CTxOut out;
    out.nValue = 0;
    out.scriptPubKey.resize(37);
    out.scriptPubKey[0] = OP_RETURN;
    out.scriptPubKey[1] = 0xD1;
    out.scriptPubKey[2] = 0x61;
    out.scriptPubKey[3] = 0x73;
    out.scriptPubKey[4] = 0x68;

    memcpy(&out.scriptPubKey[5], &data.hashCritical, 32);

    // Add bytes (optional)
    if (!data.vBytes.empty())
        out.scriptPubKey += CScript(data.vBytes.begin(), data.vBytes.end());

    return out;
}

void GenerateCriticalHashCommitments(CBlock& block)
{
    /*
     * M8 (v1)
     * Critical data / Skydoge BMM commitment request.
     * BIP: 300 & 301
     */
    if (block.vtx.size() < 2)
        return;


    std::vector<CCriticalData> vCriticalData = GetCriticalDataRequests(block);
    std::vector<CTxOut> vout;
    for (const CCriticalData& d : vCriticalData)
        vout.push_back(GetCriticalHashCommitmentOut(d));

    // Update coinbase in block
    if (!vout.empty()) {
        CMutableTransaction mtx(*block.vtx[0]);
        for (const CTxOut& o : vout)
            mtx.vout.push_back(o);
        block.vtx[0] = MakeTransactionRef(std::move(mtx));
    }
}

void GenerateLNCriticalHashCommitment(CBlock& block)
{
    /*
     * M8 (v2)
     * Example Lightning version of Skydoge BMM commitment request.
     * BIP: 300 & 301
     */

    // TODO
    std::vector<CCriticalData> vCriticalData; // = GetLNBMMRequests();
    std::vector<CTxOut> vout;
    for (const CCriticalData& d : vCriticalData) {
        CTxOut out;
        out.nValue = 0;
        out.scriptPubKey.resize(69);
        out.scriptPubKey[0] = OP_RETURN;
        out.scriptPubKey[1] = 0xD0;
        out.scriptPubKey[2] = 0x52;
        out.scriptPubKey[3] = 0x0C;
        out.scriptPubKey[4] = 0x6E;

        // Add side:block hash
        memcpy(&out.scriptPubKey[5], &d.hashCritical, 32);

        // Add previous side:block hash
        // TODO
        uint256 prevBlockHash = uint256(); // d.prevBlockHash
        memcpy(&out.scriptPubKey[38], &prevBlockHash, 32);

        // Add bytes (optional)
        if (!d.vBytes.empty())
            out.scriptPubKey += CScript(d.vBytes.begin(), d.vBytes.end());

        vout.push_back(out);
    }

    // Update coinbase in block
    if (!vout.empty()) {
        CMutableTransaction mtx(*block.vtx[0]);
        for (const CTxOut& o : vout)
            mtx.vout.push_back(o);
        block.vtx[0] = MakeTransactionRef(std::move(mtx));
    }
}



//void GenerateWithdrawalHashCommitment(CBlock& block, const uint256& hash, const uint8_t nSidechain, const Consensus::Params& consensusParams)
void GenerateWithdrawalHashCommitment(CBlock& block, const uint256& hash, const uint8_t nSidechain)
{
    /*
     * M3
     * Skydoge Withdrawal commit message "Propose Withdrawal".
     * BIP: 300 & 301
     */


    CTxOut out;
    out.nValue = 0;

    // Add script header
    out.scriptPubKey.resize(38);
    out.scriptPubKey[0] = OP_RETURN;
    out.scriptPubKey[1] = 0xD4;
    out.scriptPubKey[2] = 0x5A;
    out.scriptPubKey[3] = 0xA9;
    out.scriptPubKey[4] = 0x43;

    // Add Withdrawal hash
    memcpy(&out.scriptPubKey[5], &hash, 32);

    // Add nSidechain
    out.scriptPubKey[37] = nSidechain;

    // Update coinbase in block
    CMutableTransaction mtx(*block.vtx[0]);
    mtx.vout.push_back(out);
    block.vtx[0] = MakeTransactionRef(std::move(mtx));
}

void GenerateSidechainProposalCommitment(CBlock& block, const Sidechain& sidechain)
{
    CTxOut out;
    out.nValue = 0;

    // Add serialization of sidechain proposal & Header 0xD5E0C4AF
    out.scriptPubKey = sidechain.GetProposalScript();

    // Update coinbase in block
    CMutableTransaction mtx(*block.vtx[0]);
    mtx.vout.push_back(out);
    block.vtx[0] = MakeTransactionRef(std::move(mtx));
}

void GenerateSidechainActivationCommitment(CBlock& block, const uint256& hash)
{

    CTxOut out;
    out.nValue = 0;

    // Add script header
    out.scriptPubKey.resize(37);
    out.scriptPubKey[0] = OP_RETURN;
    out.scriptPubKey[1] = 0xD6;
    out.scriptPubKey[2] = 0xE1;
    out.scriptPubKey[3] = 0xC5;
    out.scriptPubKey[4] = 0xBF;

    memcpy(&out.scriptPubKey[5], &hash, 32);
    // Update coinbase in block
    CMutableTransaction mtx(*block.vtx[0]);
    mtx.vout.push_back(out);
    block.vtx[0] = MakeTransactionRef(std::move(mtx));
}

void GenerateSCDBHashCommitment(CBlock& block, const uint256& hashCommitment)
{
    CTxOut out;
    out.nValue = 0;

    // Add script header
    out.scriptPubKey.resize(37);
    out.scriptPubKey[0] = OP_RETURN;
    out.scriptPubKey[1] = 0xD8;
    out.scriptPubKey[2] = 0x5C;
    out.scriptPubKey[3] = 0xDB;
    out.scriptPubKey[4] = 0xC0;

    memcpy(&out.scriptPubKey[5], &hashCommitment, 32);
    // Update coinbase in block
    CMutableTransaction mtx(*block.vtx[0]);
    mtx.vout.push_back(out);
    block.vtx[0] = MakeTransactionRef(std::move(mtx));
}

//! Defined beside ResyncSCDBInto, which is its other caller; forward-declared
//! here because the consensus seed below is compiled ~3,500 lines earlier.
static bool RestoreFailedSpentFromRecords(SidechainDB& db, const CBlockIndex* pindex);

SidechainDB GetSCDBConsensusSeed(const CBlockIndex* pindexPrev, const Consensus::Params& consensusParams)
{
    AssertLockHeld(cs_main);

    SidechainDB scdbSeed = scdb;

    // Where the parent's record is complete, the consensus sections are taken
    // from that record rather than from whatever the global happened to hold,
    // so decisions made against this state are a function of (parent record,
    // block) and not of the order this node received blocks in - the same
    // discipline DisconnectBlock applies on the way out. The copy still
    // supplies the node-local halves the record deliberately omits: the
    // deposit history, whose newest entries the pointer moves are derived
    // from, and the caches no validity decision reads.
    //
    // Only a record carrying the spent-bundle key stands in for the parent -
    // that key implies the treasury key, so such a record states every
    // consensus section. An older record holds neither the treasury nor the
    // spent bundles, and a working state built from one would reject blocks
    // the network accepts. Missing or old, the copy of the global stands,
    // which is the pre-record behaviour exactly - strictly additive on old
    // history, order-independent on new.
    //
    // The gate is IsSkydogeEnabled on the parent, spelled out rather than
    // reduced to the null check it happens to equal while DrivechainHeight
    // is 1, so this helper reproduces ConnectBlock's gate literally on every
    // chain rather than a currently-equivalent restatement of it.
    if (IsSkydogeEnabled(pindexPrev, consensusParams) &&
            pindexPrev->GetBlockHash() != consensusParams.hashGenesisBlock) {
        SidechainBlockData parentData;
        if (psidechaintree &&
                psidechaintree->GetBlockData(pindexPrev->GetBlockHash(), parentData) &&
                parentData.HasSpent()) {
            scdbSeed.ApplyLDBData(pindexPrev->GetBlockHash(), parentData);

            // Same reason as ResyncSCDBInto. If the rebuild fails the record
            // chain is broken, and seeding from a half-restored set would be
            // worse than not seeding: leave the copy of the global standing,
            // which is exactly what happens for a record too old to seed from.
            if (parentData.HasFailedSpentDelta() &&
                    !RestoreFailedSpentFromRecords(scdbSeed, pindexPrev)) {
                return scdb;
            }
        }
    }

    return scdbSeed;
}

bool ComputeSCDBCommitment(const CBlock& block, const CBlockIndex* pindexPrev, uint256& hashCommitment)
{
    AssertLockHeld(cs_main);

    if (!pindexPrev || block.vtx.empty() || !block.vtx[0])
        return false;

    const int nHeight = pindexPrev->nHeight + 1;

    // The working state ConnectBlock will use for this block, from the shared
    // seed helper: the copy of the global with the tip's record overlaid
    // where the record is complete. On a healthy node the two are identical;
    // on a diverged one, only this choice makes the miner commit the value
    // its own ConnectBlock will check, so the disagreement surfaces as the
    // network rejecting the block rather than the node rejecting its own
    // template.
    SidechainDB scdbSim = GetSCDBConsensusSeed(pindexPrev, Params().GetConsensus());

    // The block hash cannot exist yet, so every step below receives a
    // placeholder. Legitimate only because every field the placeholder lands
    // in - hashBlockLastSeen, the spent entries' provenance, the deposit
    // cache - is excluded from the committed form; which fields those had to
    // be was decided by exactly this call site. ApplyUpdate refuses a null
    // block hash, so the placeholder is 1 rather than 0 - a value no real
    // block can take, since it would need to beat every proof-of-work target.
    const uint256 hashPlaceholder = uint256S("0x1");

    // The connect path's steps, in its order: discover this block's payouts,
    // collect and apply the block's deposits, spend the payouts, then scan the
    // finished coinbase. Kept as a sequence of the same public calls
    // ConnectBlock makes rather than a shared helper - extraction would
    // refactor interleaved per-transaction rejects that were just stabilised,
    // and drift between the two halves cannot survive a single test run,
    // because a drifted miner's own block fails its own ConnectBlock commitment
    // check at the next height.
    //
    // The payouts are discovered from the block and the coin view the same way
    // ConnectBlock discovers them - a transaction that spends a sidechain
    // treasury output (a CTIP) and takes more sidechain value out than it puts
    // back - rather than trusted from a list maintained beside the block. Such
    // a list cannot see a payout the block carries by another route: a
    // hand-placed one (-blockplacetx) changes SCDB during connection but would
    // be absent from the list, so the miner would commit a hash its own
    // ConnectBlock then rejects while older nodes accepted the block. The view
    // is walked forward as ConnectBlock walks it - each transaction's outputs
    // applied before the next is judged - so a payout that spends an output
    // created earlier in the same block is still seen.
    std::vector<std::pair<uint8_t, size_t>> vPayout;
    {
        CCoinsViewCache viewSim(pcoinsTip.get());
        for (size_t i = 0; i < block.vtx.size(); i++) {
            const CTransaction& tx = *(block.vtx[i]);
            if (!tx.IsCoinBase()) {
                // The template is not yet CheckBlock-clean the way a connected
                // block is, so validate before walking it: UpdateCoins below
                // asserts on a duplicate input, which CheckTransaction rejects
                // and HaveInputs does not. Without this a malformed placed
                // transaction would abort the miner here instead of failing.
                CValidationState txState;
                if (!CheckTransaction(tx, txState))
                    return false;
                if (!viewSim.HaveInputs(tx))
                    return false;
                uint8_t nSidechain = 0;
                bool fSidechainInputs = false;
                for (const CTxIn& in : tx.vin) {
                    if (viewSim.AccessCoin(in.prevout).out.scriptPubKey.IsDrivechain(nSidechain)) {
                        fSidechainInputs = true;
                        break;
                    }
                }
                if (fSidechainInputs) {
                    CAmount amountSidechainIn = 0, amountIn = 0;
                    CAmount amountSidechainOut = 0, amountWithdrawn = 0;
                    std::string strFail;
                    if (!GetDrivechainAmounts(viewSim, tx, amountSidechainIn,
                                amountIn, amountSidechainOut, amountWithdrawn, strFail))
                        return false;
                    if (amountSidechainIn > amountSidechainOut)
                        vPayout.push_back(std::make_pair(nSidechain, i));
                }
            }
            UpdateCoins(tx, viewSim, nHeight);
        }
    }

    std::vector<SidechainDeposit> vDeposit;
    if (!GetBlockDeposits(block, scdbSim, vDeposit))
        return false;
    scdbSim.AddDeposits(vDeposit);

    for (const std::pair<uint8_t, size_t>& payout : vPayout) {
        if (payout.second >= block.vtx.size() || !block.vtx[payout.second])
            return false;
        if (!scdbSim.SpendWithdrawal(payout.first, hashPlaceholder,
                    *block.vtx[payout.second], (int)payout.second, nHeight,
                    false /* fJustCheck */, true /* fDebug */))
            return false;
    }

    if (!scdbSim.Update(nHeight, hashPlaceholder, pindexPrev->GetBlockHash(),
                block.vtx[0]->vout, false /* fJustCheck */, true /* fDebug */))
        return false;

    hashCommitment = scdbSim.GetCommitmentHash(nHeight);
    return true;
}

//! True if a withdrawal-bundle index can be written as a two-byte upvote
//! without colliding with a sentinel BYTE PAIR that ParseSCDBBytes would read
//! back as abstain or downvote.
//!
//! The encoding is little-endian, so the colliding indices are NOT the two
//! largest. 0xFEFF (65279) encodes as (0xFF,0xFE), which the reader takes as a
//! DOWNVOTE - an upvote silently inverted into its opposite. The guard this
//! replaced tested `n > 65533`, which let 65279 through and needlessly rejected
//! 65534. Both halves were wrong, in opposite directions.
//!
//! Kept as a named function so the writer's rule can be tested against the
//! reader's decode directly, rather than by restating the constants in a test
//! and having both agree on the same mistake.
bool ScdbVoteIndexIsEncodable(size_t n)
{
    if (n > 0xFFFF)
        return false;
    const unsigned char lo = n & 0xFF;
    const unsigned char hi = (n >> 8) & 0xFF;
    // The two sentinel pairs, exactly as ParseSCDBBytes matches them.
    if (lo == 0xFF && (hi == 0xFF || hi == 0xFE))
        return false;
    return true;
}

bool GenerateSCDBByteCommitment(CBlock& block, CScript& scriptOut, const std::vector<std::vector<SidechainWithdrawalState>>& vScores, const std::vector<std::string>& vVote)
{
        // Check for activation of Skydoge
    if (vVote.size() != SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        return false;

    // Create output that bytes will be added to
    CTxOut out;
    out.nValue = 0;

    // Add script header
    out.scriptPubKey.resize(6);
    out.scriptPubKey[0] = OP_RETURN;
    out.scriptPubKey[1] = 0xD7;
    out.scriptPubKey[2] = 0x7D;
    out.scriptPubKey[3] = 0x17;
    out.scriptPubKey[4] = 0x76;

    // Add version number
    out.scriptPubKey[5] = SCDB_BYTES_VERSION;

    // Set bytes based on withdrawal vote settings
    for (const std::vector<SidechainWithdrawalState>& vWithdrawal : vScores) {
        if (vWithdrawal.empty())
            return false;

        uint8_t nSidechain = vWithdrawal.front().nSidechain;

        // Add bytes to script based on our vote settings.
        //
        // THE RESERVED INDICES ARE 65279 AND 65535, NOT 65534 AND 65535. The
        // sentinels are defined by their BYTE PAIRS - ParseSCDBBytes tests
        // bytes[i]/bytes[i+1] directly - while an index is written LITTLE-ENDIAN
        // (low byte first). So the pair that means downvote, (0xFF,0xFE), is the
        // little-endian encoding of 0xFEFF = 65279, and 65534 = 0xFFFE encodes as
        // (0xFE,0xFF), which collides with nothing.
        //
        //   0..65534 except 65279 = upvote that index
        //   65279  (0xFF,0xFE)    = RESERVED, collides with downvote
        //   65535  (0xFF,0xFF)    = RESERVED, collides with abstain
        if (vVote[nSidechain].size() == 64) {
            uint256 hash = uint256S(vVote[nSidechain]);

            if (hash.IsNull())
                return false;

            // Lookup index of withdrawal bundle in SCDB
            // size_t, not uint16_t: the counter wrapped at 65,535 before the
            // n < size() test could terminate, so a longer vector was an
            // INFINITE LOOP in the miner. The wire format is still two bytes,
            // so an index that cannot be named is treated as abstain rather
            // than emitted as a sentinel - see the reserved-index note above
            // for WHICH indices those actually are.
            size_t n = 0;
            for (; n < vWithdrawal.size(); n++)
                if (vWithdrawal[n].hash == hash)
                    break;

            // If bundle exists add index bytes. Otherwise add abstain bytes.
            if (n == vWithdrawal.size() || !ScdbVoteIndexIsEncodable(n)) {
                out.scriptPubKey.push_back(0xFF);
                out.scriptPubKey.push_back(0xFF);
            } else {
                out.scriptPubKey.push_back(n & 0xff);
                out.scriptPubKey.push_back(n >> 8);
            }
        }
        else
        if (!vVote[nSidechain].empty() && vVote[nSidechain].front() == SCDB_ABSTAIN) {
            out.scriptPubKey.push_back(0xFF);
            out.scriptPubKey.push_back(0xFF);
        }
        else
        if (!vVote[nSidechain].empty() && vVote[nSidechain].front() == SCDB_DOWNVOTE) {
            out.scriptPubKey.push_back(0xFF);
            out.scriptPubKey.push_back(0xFE);
        }
        else {
            // Terminal default: abstain. Every branch above must emit exactly
            // one byte PAIR, because ParseSCDBBytes walks this payload two
            // bytes at a time and reads each pair positionally. A vote string
            // outside the validated set used to fall through emitting NOTHING,
            // which did not just lose this sidechain's vote - it shifted every
            // following slot's pair by two, so the remaining sidechains were
            // read against the wrong votes.
            //
            // This is producer-side only. Validation re-derives the votes from
            // the raw coinbase bytes, so a misaligned commitment was never a
            // consensus split - it only yielded a block other nodes reject.
            // Abstain is the safe default: it is what an entry initialises to.
            out.scriptPubKey.push_back(0xFF);
            out.scriptPubKey.push_back(0xFF);
        }
    }

    scriptOut = out.scriptPubKey;

    // Update coinbase in block
    CMutableTransaction mtx(*block.vtx[0]);
    mtx.vout.push_back(out);
    block.vtx[0] = MakeTransactionRef(std::move(mtx));

    return true;
}

CScript GetNewsTokyoDailyHeader()
{
    CScript script;
    script.resize(5);
    script[0] = OP_RETURN;
    script[1] = 0xA1;
    script[2] = 0xB2;
    script[3] = 0xC3;
    script[4] = 0x01;
    return script;
}

CScript GetNewsUSDailyHeader()
{
    CScript script;
    script.resize(5);
    script[0] = OP_RETURN;
    script[1] = 0xA1;
    script[2] = 0xB2;
    script[3] = 0xC3;
    script[4] = 0x02;
    return script;
}

std::vector<CCriticalData> GetCriticalDataRequests(const CBlock& block)
{
    std::vector<CCriticalData> vCriticalData;

    if (block.vtx.size() < 2)
        return vCriticalData;

    for (const CTransactionRef& tx : block.vtx) {
        if (!tx->criticalData.IsNull()) {
            vCriticalData.push_back(tx->criticalData);
        }
    }
    return vCriticalData;
}

bool ContextualCheckBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& params, const CBlockIndex* pindexPrev, int64_t nAdjustedTime)
{
    assert(pindexPrev != nullptr);
    const int nHeight = pindexPrev->nHeight + 1;

    // Check proof of work
    const Consensus::Params& consensusParams = params.GetConsensus();
    if (block.nBits != GetNextWorkRequired(pindexPrev, &block, consensusParams))
        return state.DoS(100, false, REJECT_INVALID, "bad-diffbits", false, "incorrect proof of work");

    // Enforce Network Fork
    // Special nBits requirement at the specified blockheight.
    // Mainnet BTC nodes will reject this block and all future blocks.
    if (nHeight == consensusParams.DrivechainHeight) {
        const arith_uint256 bnPoWDA = UintToArith256(consensusParams.powLimit);
        if (block.nBits != bnPoWDA.GetCompact()) {
            LogPrintf("%s: Invalid diffbits for Drivechain DA at height: %u.\n", __func__, nHeight);
            return state.DoS(100, false, REJECT_INVALID, "bad-diffbits-drivechain-da", false, "Bits invalid for Drivechain DA height block!");
        }
        LogPrintf("%s: Drivechain fork birthday DA activated! Height: %u\n", __func__, nHeight);
    }

    // Check against checkpoints
    if (fCheckpointsEnabled) {
        // Don't accept any forks from the main chain prior to last checkpoint.
        // GetLastCheckpoint finds the last checkpoint in MapCheckpoints that's in our
        // MapBlockIndex.
        CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(params.Checkpoints());
        if (pcheckpoint && nHeight < pcheckpoint->nHeight)
            return state.DoS(100, error("%s: forked chain older than last checkpoint (height %d)", __func__, nHeight), REJECT_CHECKPOINT, "bad-fork-prior-to-checkpoint");
    }

    // Check timestamp against prev
    if (block.GetBlockTime() <= pindexPrev->GetMedianTimePast())
        return state.Invalid(false, REJECT_INVALID, "time-too-old", "block's timestamp is too early");

    // Check timestamp
    if (block.GetBlockTime() > nAdjustedTime + MAX_FUTURE_BLOCK_TIME)
        return state.Invalid(false, REJECT_INVALID, "time-too-new", "block timestamp too far in the future");

    // Security fix (timewarp, tightening soft fork, BIP94-style): from
    // TimewarpGuardHeight, the first block of each difficulty adjustment period
    // may not date backward more than MAX_TIMEWARP relative to its parent. This
    // bounds the fake time a miner can inject per retarget window, neutralizing
    // the timewarp attack against the historic off-by-one retarget window in
    // CalculateNextWorkRequired. Height-gated so no historical block is
    // retroactively invalidated.
    if (nHeight >= consensusParams.TimewarpGuardHeight &&
        nHeight % consensusParams.DifficultyAdjustmentInterval() == 0 &&
        block.GetBlockTime() < pindexPrev->GetBlockTime() - MAX_TIMEWARP) {
        return state.DoS(100, false, REJECT_INVALID, "time-timewarp-attack", false,
                         "first block of difficulty period dates backward beyond MAX_TIMEWARP");
    }

    // Reject outdated version blocks when 95% (75% on testnet) of the network has upgraded:
    // check for version 2, 3 and 4 upgrades
    if((block.nVersion < 2 && nHeight >= consensusParams.BIP34Height) ||
       (block.nVersion < 3 && nHeight >= consensusParams.BIP66Height) ||
       (block.nVersion < 4 && nHeight >= consensusParams.BIP65Height))
            return state.Invalid(false, REJECT_OBSOLETE, strprintf("bad-version(0x%08x)", block.nVersion),
                                 strprintf("rejected nVersion=0x%08x block", block.nVersion));

    return true;
}

//! Answer "was this sidechain slot active as of pindexPrev" from the parent's
//! per-block record, so the answer is a function of this block's own ancestry
//! rather than of the tip-tracking global. Returns false when no record can
//! answer - the caller falls back to the global, which is the pre-record
//! behaviour. Any record vintage will do: the sidechain table has been in the
//! record since the original key, unlike the treasury and spent sections.
static bool SidechainActiveAsOf(const CBlockIndex* pindexPrev, uint8_t nSidechain, bool& fActive)
{
    if (!psidechaintree || !pindexPrev)
        return false;

    // Nothing can be active as of the genesis block, which has no record.
    if (pindexPrev->GetBlockHash() == Params().GetConsensus().hashGenesisBlock) {
        fActive = false;
        return true;
    }

    SidechainBlockData data;
    if (!psidechaintree->GetBlockData(pindexPrev->GetBlockHash(), data))
        return false;

    // The table is stored either complete (256 entries) or sparse (the active
    // slots only, each carrying its own index) - the same rule ApplyLDBData
    // re-expands by.
    fActive = false;
    if (data.vSidechain.size() < (size_t)SIDECHAIN_ACTIVATION_MAX_ACTIVE) {
        for (const Sidechain& s : data.vSidechain) {
            if (s.nSidechain == nSidechain && s.fActive) {
                fActive = true;
                break;
            }
        }
    } else if (nSidechain < data.vSidechain.size()) {
        fActive = data.vSidechain[nSidechain].fActive;
    }

    return true;
}

/** NOTE: This function is not currently invoked by ConnectBlock(), so we
 *  should consider upgrade issues if we change which consensus rules are
 *  enforced in this function (eg by adding a new consensus rule). See comment
 *  in ConnectBlock().
 *  Note that -reindex-chainstate skips the validation that happens here!
 */
static bool ContextualCheckBlock(const CBlock& block, CValidationState& state, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev, bool fFromDisk = false)
{
    const int nHeight = pindexPrev == nullptr ? 0 : pindexPrev->nHeight + 1;

    // Start enforcing BIP113 (Median Time Past) using versionbits logic.
    int nLockTimeFlags = 0;
    if (VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_CSV, versionbitscache) == THRESHOLD_ACTIVE) {
        nLockTimeFlags |= LOCKTIME_MEDIAN_TIME_PAST;
    }

    int64_t nLockTimeCutoff = (nHeight && nLockTimeFlags & LOCKTIME_MEDIAN_TIME_PAST)
                              ? pindexPrev->GetMedianTimePast()
                              : block.GetBlockTime();

    // Check that all transactions are finalized
    for (const auto& tx : block.vtx) {
        if (!IsFinalTx(*tx, nHeight, nLockTimeCutoff)) {
            return state.DoS(10, false, REJECT_INVALID, "bad-txns-nonfinal", false, "non-final transaction");
        }
    }

    // Enforce rule that the coinbase starts with serialized block height
    if (nHeight >= consensusParams.BIP34Height)
    {
        CScript expect = CScript() << nHeight;
        if (block.vtx[0]->vin[0].scriptSig.size() < expect.size() ||
            !std::equal(expect.begin(), expect.end(), block.vtx[0]->vin[0].scriptSig.begin())) {
            return state.DoS(100, false, REJECT_INVALID, "bad-cb-height", false, "block height mismatch in coinbase");
        }
    }

    // Validation for witness commitments.
    // * We compute the witness hash (which is the hash including witnesses) of all the block's transactions, except the
    //   coinbase (where 0x0000....0000 is used instead).
    // * The coinbase scriptWitness is a stack of a single 32-byte vector, containing a witness nonce (unconstrained).
    // * We build a merkle tree with all those witness hashes as leaves (similar to the hashMerkleRoot in the block header).
    // * There must be at least one output whose scriptPubKey is a single 36-byte push, the first 4 bytes of which are
    //   {0xaa, 0x21, 0xa9, 0xed}, and the following 32 bytes are SHA256^2(witness root, witness nonce). In case there are
    //   multiple, the last one is used.
    bool fHaveWitness = false;
    if (VersionBitsState(pindexPrev, consensusParams, Consensus::DEPLOYMENT_SEGWIT, versionbitscache) == THRESHOLD_ACTIVE) {
        int commitpos = GetWitnessCommitmentIndex(block);
        if (commitpos != -1) {
            bool malleated = false;
            uint256 hashWitness = BlockWitnessMerkleRoot(block, &malleated);
            // The malleation check is ignored; as the transaction tree itself
            // already does not permit it, it is impossible to trigger in the
            // witness tree.
            if (block.vtx[0]->vin[0].scriptWitness.stack.size() != 1 || block.vtx[0]->vin[0].scriptWitness.stack[0].size() != 32) {
                return state.DoS(100, false, REJECT_INVALID, "bad-witness-nonce-size", true, strprintf("%s : invalid witness nonce size", __func__));
            }
            CHash256().Write(hashWitness.begin(), 32).Write(&block.vtx[0]->vin[0].scriptWitness.stack[0][0], 32).Finalize(hashWitness.begin());
            if (memcmp(hashWitness.begin(), &block.vtx[0]->vout[commitpos].scriptPubKey[6], 32)) {
                return state.DoS(100, false, REJECT_INVALID, "bad-witness-merkle-match", true, strprintf("%s : witness merkle commitment mismatch", __func__));
            }
            fHaveWitness = true;
        }
    }

    // No witness data is allowed in blocks that don't commit to witness data, as this would otherwise leave room for spam
    if (!fHaveWitness) {
      for (const auto& tx : block.vtx) {
            if (tx->HasWitness()) {
                return state.DoS(100, false, REJECT_INVALID, "unexpected-witness", true, strprintf("%s : unexpected witness data found", __func__));
            }
        }
    }

    // Security fix: a v3 transaction's criticalData is counted in the
    // serialized size/weight gates below but is NOT committed to the block hash
    // (it is stripped from both the txid and the witness merkle leaf). Those
    // gates reject with corruptionIn=false, so a peer could pad a copy of an
    // honest block past the cap without changing its hash and get that hash
    // marked permanently invalid. Enforce the per-tx bound here, before the
    // gates, with corruptionIn=true so a malleated copy never poisons the honest
    // block's hash. (Deserialization also bounds vBytes; this is defense in
    // depth for any in-memory block that bypasses that path.)
    for (const auto& tx : block.vtx) {
        if (!tx->criticalData.IsNull() &&
                tx->criticalData.vBytes.size() > (size_t)MAX_CRITICAL_DATA_BYTES) {
            return state.DoS(100, false, REJECT_INVALID, "bad-critical-data-bytes", true,
                             strprintf("%s : critical data bytes size > MAX_CRITICAL_DATA_BYTES", __func__));
        }
    }

    // After the coinbase witness nonce and commitment are verified,
    // we can check if the block weight passes (before we've checked the
    // coinbase witness, it would be possible for the weight to be too
    // large by filling up the coinbase witness, which doesn't change
    // the block hash, so we couldn't mark the block as permanently
    // failed).
    //
    // Reported as corruption-possible, unlike upstream. Upstream can treat an
    // over-weight block as permanently invalid because, once the witness
    // commitment above has been checked, nothing left in the weight is
    // malleable. That does not hold here: a v3 transaction's criticalData is
    // counted in the weight but is committed to by neither the txid nor the
    // witness merkle leaf, so a peer can still pad a copy of an honest block
    // (within the per-tx bound enforced above) without changing its hash. If
    // this rejected with corruptionIn=false, that padded copy would get the
    // honest block's hash marked permanently invalid. The block is rejected
    // either way -- only the caching of the failure changes.
    if (GetBlockWeight(block) > MAX_BLOCK_WEIGHT) {
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-weight", true, strprintf("%s : weight limit failed", __func__));
    }

    // Small-block soft fork: at and after SmallBlockHeight the block's
    // COMMITTED serialized size (GetCommittedSerializedSize: witness at par,
    // criticalData excluded, a fixed charge per nVersion-3 transaction) must
    // fit in MAX_SMALL_BLOCK_SERIALIZED_SIZE bytes. Witness bytes count at
    // par, so this also removes the witness discount for blocks bound by this
    // rule. Like the weight check above, this may only run after the witness
    // commitment has been validated: witness data does not affect the block
    // hash, so rejecting on witness bytes any earlier would let a peer
    // malleate an honest block into one we mark permanently invalid.
    //
    // NOT corruption-possible, deliberately, and this is a change: while the
    // rule counted criticalData - bytes nothing in the block commits to - a
    // rejection could not be pinned on the hash, because a padded relayed
    // copy of an honest block would have failed it. Every input to the
    // measure is now committed data, so an over-size verdict is a verdict on
    // the block itself and is marked as such. The alternative was measured on
    // a test network: with corruptionPossible set nothing marks the
    // block failed, it stays a candidate, and an honest un-upgraded peer that
    // keeps announcing it is asked for it again ~100 times a second.
    if (nHeight >= consensusParams.SmallBlockHeight &&
            GetCommittedSerializedSize(block) > MAX_SMALL_BLOCK_SERIALIZED_SIZE) {
        return state.DoS(100, false, REJECT_INVALID, "bad-blk-size", false, strprintf("%s : committed size limit failed", __func__));
    }

    // SCDB commitment soft fork: at and after SCDBCommitmentHeight the
    // coinbase must carry exactly one SCDB hash commitment output. Presence
    // and shape only - a pure function of the block bytes and the height, so
    // every node answers identically and DoS(100) is safe. Requiring presence
    // is what makes divergence unable to hide behind omission. NOT
    // corruption-possible: a coinbase output is committed by the merkle root,
    // so a relayed copy cannot be doctored into failing this check. Whether
    // the committed value is right is ConnectBlock's question, not this one's.
    if (nHeight >= consensusParams.SCDBCommitmentHeight) {
        int nCommit = 0;
        uint256 hashCommitment;
        for (const CTxOut& out : block.vtx[0]->vout) {
            if (out.scriptPubKey.IsSCDBHashCommit(hashCommitment))
                nCommit++;
        }
        if (nCommit != 1)
            return state.DoS(100, false, REJECT_INVALID, "bad-scdb-commitment-missing", false, strprintf("%s : expected exactly 1 SCDB hash commitment, found %d", __func__, nCommit));
    }

    // Consensus fix: key the drivechain rule gate to this block's own context
    // (pindexPrev), not the active tip, so validating this block does not
    // depend on the order in which blocks were received and connected.
    bool skydogeEnabled = IsSkydogeEnabled(pindexPrev, consensusParams);

    // From
    // SCDBCommitmentHeight every critical hash commitment in the coinbase must
    // be matched by a transaction in this block carrying exactly that
    // criticalData. criticalData is outside the txid and the merkle root, so a
    // relay could strip a BMM request out of an honest block without changing
    // its hash, and nodes given the stripped copy and nodes given the honest
    // one could judge the block differently (ConnectBlock's slot-active rule
    // reads the request). With this rule a stripped copy is refused here,
    // before it is stored - corruption-possible, so the honest copy is still
    // accepted when it arrives - and every node judges the same bytes. The
    // reverse direction (a request with no commitment) is
    // bad-critical-data-no-commit below. No honest block changes: the miner
    // writes commitments only for transactions already in the block
    // (GenerateCriticalHashCommitments) and only appends transactions after.
    if (skydogeEnabled && nHeight >= consensusParams.SCDBCommitmentHeight) {
        for (const CTxOut& out : block.vtx[0]->vout) {
            uint256 hashCommit;
            std::vector<unsigned char> vBytesCommit;
            if (!out.scriptPubKey.IsCriticalHashCommit(hashCommit, vBytesCommit))
                continue;
            bool fMatched = false;
            for (size_t i = 1; i < block.vtx.size() && !fMatched; i++) {
                const CCriticalData& data = block.vtx[i]->criticalData;
                fMatched = !data.IsNull() && data.hashCritical == hashCommit &&
                           data.vBytes == vBytesCommit;
            }
            if (!fMatched)
                return state.DoS(100, false, REJECT_INVALID, "bad-critical-commit-unmatched", true,
                                 strprintf("%s : coinbase critical hash commitment %s has no matching transaction in the block", __func__, hashCommit.ToString()));
        }
    }

    // Check critical data transactions (outputs, not spending)
    if (skydogeEnabled) {
        // Track existence of BMM h* commit requests per sidechain
        std::vector<bool> vSidechainBMM;
        vSidechainBMM.resize(SIDECHAIN_ACTIVATION_MAX_ACTIVE);
        for (const auto& tx: block.vtx) {
            // Look for transactions with non-null CCriticalData
            if (!tx->criticalData.IsNull()) {
                // Check block height
                if (nHeight != ((int64_t)tx->nLockTime + 1))
                    return state.DoS(100, false, REJECT_INVALID, "bad-critical-data-locktime", true, strprintf("%s : critical data transaction locktime does not match block height - 1", __func__));

                // TODO move?
                // Check size of critical data bytes
                if (tx->criticalData.vBytes.size() > MAX_CRITICAL_DATA_BYTES)
                    return state.DoS(100, false, REJECT_INVALID, "bad-critical-data-bytes", true, strprintf("%s : extra bytes size > MAX_CRITICAL_DATA_BYTES", __func__));

                // Check for hashCritical commitment in coinbase
                bool fFound = false;
                for (const CTxOut& out : block.vtx[0]->vout) {
                    const CScript &scriptPubKey = out.scriptPubKey;
                    uint256 hashCritical = uint256();
                    std::vector<unsigned char> vBytes;
                    if (scriptPubKey.IsCriticalHashCommit(hashCritical, vBytes)) {
                        if (tx->criticalData.hashCritical == hashCritical &&
                                tx->criticalData.vBytes == vBytes) {
                            fFound = true;
                            break;
                        }
                    }
                }
                // Did we find hashCritical?
                if (!fFound)
                    return state.DoS(100, false, REJECT_INVALID, "bad-critical-data-no-commit", true, strprintf("%s : no commit found for critical data", __func__));

                // Enforce 1 BMM h* per sidechain per block & validate BMM txns.
                //
                // Only the ACTIVE-SLOT test is skipped when loading from disk.
                // The three that follow it are pure functions of the block's
                // own bytes - a sidechain number's range, the previous block's
                // low bytes, and whether one slot was committed twice in this
                // block - and none of them reads SCDB, so a reindexing node
                // whose SCDB is not yet at the tip answers them exactly as a
                // synchronised one does.
                //
                // They used to sit under the same !fFromDisk gate as the
                // active-slot test, which meant -reindex and -loadblock
                // accepted blocks that normal network validation rejects: a
                // block imported from disk with two BMM commitments for one
                // slot, or with prev-block bytes naming some other parent,
                // became this node's active chain while every peer refused it.
                // ConnectBlock does not repeat contextual validation (see its
                // NOTE), so nothing downstream caught it. Running them on both
                // paths cannot reject a block the network accepts, because
                // AcceptBlock already applies them to every block that arrives
                // over the wire at every height - a block in the canonical
                // chain has passed them by construction, or no node could have
                // synced it.
                uint8_t nSidechain;
                std::string strPrevBlock = "";
                if (tx->criticalData.IsBMMRequest(nSidechain, strPrevBlock)) {
                    // Answered from the parent's record where one exists, so
                    // that which sidechains were active is a fact about this
                    // block's own ancestry rather than about the tip the global
                    // happens to track. The global remains the fallback for a
                    // parent that was never connected (this check runs from
                    // AcceptBlock, which does not require it to have been) -
                    // that is the pre-record behaviour exactly. Still skipped
                    // for fFromDisk, where reindexing may not have built the
                    // records yet: this is the one test here that reads state
                    // a reindex has not rebuilt.
                    bool fSidechainActive = false;
                    if (!fFromDisk) {
                        if (!SidechainActiveAsOf(pindexPrev, nSidechain, fSidechainActive)) {
                            // No record for the parent: this node never
                            // connected it (a side branch, or a block that
                            // arrived before its parent was connected).
                            // Below SCDBCommitmentHeight the tip state stands
                            // in, exactly as before, so an upgraded node and a
                            // 0.44.8 node still agree on every pre-fork block.
                            // From it the tip says
                            // nothing about this block's ancestry - a synced
                            // and a fresh node answered differently, a
                            // possible split - so this pre-connect check does
                            // not decide; ConnectBlock does, against the
                            // parent's own state, on every path including
                            // -reindex and -reindex-chainstate.
                            if (nHeight >= consensusParams.SCDBCommitmentHeight)
                                fSidechainActive = true;
                            else
                                fSidechainActive = scdb.IsSidechainActive(nSidechain);
                        }
                        if (!fSidechainActive) {
                            // DoS(0), not DoS(100). The parent's record
                            // makes this node's answer reproducible, but a ban
                            // asserts what every other node computed, and a node
                            // whose records predate the treasury/spent keys - or
                            // that diverged before them - can still disagree. Keep
                            // at DoS(0) to match the three equivalent rejects in
                            // ConnectBlock.
                            return state.DoS(0, false, REJECT_INVALID,
                                    "bad-critical-bmm-nsidechain-inactive", true,
                                    strprintf("%s : Invalid (inactive) sidechain number: %u in BMM commitment", __func__, nSidechain));
                        }
                    }

                    // Check sidechain number
                    if (nSidechain >= vSidechainBMM.size()) {
                        return state.DoS(100, false, REJECT_INVALID,
                                "bad-critical-bmm-nsidechain-invalid", true,
                                strprintf("%s : Invalid sidechain number: %u in BMM commitment", __func__, nSidechain));
                    }

                    // Check Prev block bytes
                    if (strPrevBlock != block.hashPrevBlock.ToString().substr(56, 63)) {
                        return state.DoS(100, false, REJECT_INVALID,
                                "bad-critical-bmm-prevblock-invalid", true,
                                strprintf("%s : Invalid prev block bytes: %s in BMM commitment", __func__, strPrevBlock));
                    }

                    // Max 1 BMM commit per sidechain per block
                    if (vSidechainBMM[nSidechain] == false)
                        vSidechainBMM[nSidechain] = true;
                    else
                        return state.DoS(100, false, REJECT_INVALID,
                                "bad-critical-bmm-nsidechain-multiple", true,
                                strprintf("%s : Multiple BMM h* requests for a single Sidechain", __func__));
                }
            }
        }
    }
    return true;
}

bool CChainState::AcceptBlockHeader(const CBlockHeader& block, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex)
{
    AssertLockHeld(cs_main);
    // Check for duplicate
    uint256 hash = block.GetHash();
    BlockMap::iterator miSelf = mapBlockIndex.find(hash);
    CBlockIndex *pindex = nullptr;
    if (hash != chainparams.GetConsensus().hashGenesisBlock) {

        if (miSelf != mapBlockIndex.end()) {
            // Block header is already known.
            pindex = miSelf->second;
            if (ppindex)
                *ppindex = pindex;
            if (pindex->nStatus & BLOCK_FAILED_MASK)
                return state.Invalid(error("%s: block %s is marked invalid", __func__, hash.ToString()), 0, "duplicate");
            return true;
        }

        if (!CheckBlockHeader(block, state, chainparams.GetConsensus()))
            return error("%s: Consensus::CheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

        // Get prev block index
        CBlockIndex* pindexPrev = nullptr;
        BlockMap::iterator mi = mapBlockIndex.find(block.hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return state.DoS(10, error("%s: prev block not found", __func__), 0, "prev-blk-not-found");
        pindexPrev = (*mi).second;
        if (pindexPrev->nStatus & BLOCK_FAILED_MASK)
            return state.DoS(100, error("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");
        if (!ContextualCheckBlockHeader(block, state, chainparams, pindexPrev, GetAdjustedTime()))
            return error("%s: Consensus::ContextualCheckBlockHeader: %s, %s", __func__, hash.ToString(), FormatStateMessage(state));

        if (!pindexPrev->IsValid(BLOCK_VALID_SCRIPTS)) {
            for (const CBlockIndex* failedit : g_failed_blocks) {
                if (pindexPrev->GetAncestor(failedit->nHeight) == failedit) {
                    assert(failedit->nStatus & BLOCK_FAILED_VALID);
                    CBlockIndex* invalid_walk = pindexPrev;
                    while (invalid_walk != failedit) {
                        invalid_walk->nStatus |= BLOCK_FAILED_CHILD;
                        setDirtyBlockIndex.insert(invalid_walk);
                        invalid_walk = invalid_walk->pprev;
                    }
                    return state.DoS(100, error("%s: prev block invalid", __func__), REJECT_INVALID, "bad-prevblk");
                }
            }
        }
    }
    if (pindex == nullptr)
        pindex = AddToBlockIndex(block);

    if (ppindex)
        *ppindex = pindex;

    CheckBlockIndex(chainparams.GetConsensus());

    return true;
}

// Exposed wrapper for AcceptBlockHeader
bool ProcessNewBlockHeaders(const std::vector<CBlockHeader>& headers, CValidationState& state, const CChainParams& chainparams, const CBlockIndex** ppindex, CBlockHeader *first_invalid)
{
    if (first_invalid != nullptr) first_invalid->SetNull();
    {
        LOCK(cs_main);
        for (const CBlockHeader& header : headers) {
            CBlockIndex *pindex = nullptr; // Use a temp pindex instead of ppindex to avoid a const_cast
            if (!g_chainstate.AcceptBlockHeader(header, state, chainparams, &pindex)) {
                if (first_invalid) *first_invalid = header;
                return false;
            }
            if (ppindex) {
                *ppindex = pindex;
            }
        }
    }
    NotifyHeaderTip();
    return true;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
static CDiskBlockPos SaveBlockToDisk(const CBlock& block, int nHeight, const CChainParams& chainparams, const CDiskBlockPos* dbp) {
    unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
    CDiskBlockPos blockPos;
    if (dbp != nullptr)
        blockPos = *dbp;
    if (!FindBlockPos(blockPos, nBlockSize+8, nHeight, block.GetBlockTime(), dbp != nullptr)) {
        error("%s: FindBlockPos failed", __func__);
        return CDiskBlockPos();
    }
    if (dbp == nullptr) {
        if (!WriteBlockToDisk(block, blockPos, chainparams.MessageStart())) {
            AbortNode("Failed to write block");
            return CDiskBlockPos();
        }
    }
    return blockPos;
}

/** Store block on disk. If dbp is non-nullptr, the file is known to already reside on disk */
bool CChainState::AcceptBlock(const std::shared_ptr<const CBlock>& pblock, CValidationState& state, const CChainParams& chainparams, CBlockIndex** ppindex, bool fRequested, const CDiskBlockPos* dbp, bool* fNewBlock, bool fFromDisk)
{
    const CBlock& block = *pblock;

    if (fNewBlock) *fNewBlock = false;
    AssertLockHeld(cs_main);

    CBlockIndex *pindexDummy = nullptr;
    CBlockIndex *&pindex = ppindex ? *ppindex : pindexDummy;

    if (!AcceptBlockHeader(block, state, chainparams, &pindex))
        return false;

    // Try to process all requested blocks that we don't have, but only
    // process an unrequested block if it's new and has enough work to
    // advance our tip, and isn't too many blocks ahead.
    bool fAlreadyHave = pindex->nStatus & BLOCK_HAVE_DATA;
    bool fHasMoreOrSameWork = (chainActive.Tip() ? pindex->nChainWork >= chainActive.Tip()->nChainWork : true);
    // Blocks that are too out-of-order needlessly limit the effectiveness of
    // pruning, because pruning will not delete block files that contain any
    // blocks which are too close in height to the tip.  Apply this test
    // regardless of whether pruning is enabled; it should generally be safe to
    // not process unrequested blocks.
    bool fTooFarAhead = (pindex->nHeight > int(chainActive.Height() + MIN_BLOCKS_TO_KEEP));

    // TODO: Decouple this function from the block download logic by removing fRequested
    // This requires some new chain data structure to efficiently look up if a
    // block is in a chain leading to a candidate for best tip, despite not
    // being such a candidate itself.

    // TODO: deal better with return value and error conditions for duplicate
    // and unrequested blocks.
    if (fAlreadyHave) return true;
    if (!fRequested) {  // If we didn't ask for it:
        if (pindex->nTx != 0) return true;    // This is a previously-processed block that was pruned
        if (!fHasMoreOrSameWork) return true; // Don't process less-work chains
        if (fTooFarAhead) return true;        // Block height is too high

        // Protect against DoS attacks from low-work chains.
        // If our tip is behind, a peer could try to send us
        // low-work blocks on a fake chain that we would never
        // request; don't process these.
        if (pindex->nChainWork < nMinimumChainWork) return true;
    }
    if (fNewBlock) *fNewBlock = true;

    if (!CheckBlock(block, state, chainparams.GetConsensus()) ||
        !ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindex->pprev, fFromDisk)) {
        if (state.IsInvalid() && !state.CorruptionPossible()) {
            pindex->nStatus |= BLOCK_FAILED_VALID;
            setDirtyBlockIndex.insert(pindex);
        }
        return error("%s: %s", __func__, FormatStateMessage(state));
    }

    // Header is valid/has work, merkle tree and segwit merkle tree are good...RELAY NOW
    // (but if it does not build on our best tip, let the SendMessages loop relay it)
    if (!IsInitialBlockDownload() && chainActive.Tip() == pindex->pprev)
        GetMainSignals().NewPoWValidBlock(pindex, pblock);

    // Write block to history file
    try {
        CDiskBlockPos blockPos = SaveBlockToDisk(block, pindex->nHeight, chainparams, dbp);
        if (blockPos.IsNull()) {
            state.Error(strprintf("%s: Failed to find position to write new block to disk", __func__));
            return false;
        }
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos, chainparams.GetConsensus()))
            return error("AcceptBlock(): ReceivedBlockTransactions failed");
    } catch (const std::runtime_error& e) {
        return AbortNode(state, std::string("System error: ") + e.what());
    }

    if (fCheckForPruning)
        FlushStateToDisk(chainparams, state, FLUSH_STATE_NONE); // we just allocated more disk space for block files

    CheckBlockIndex(chainparams.GetConsensus());

    return true;
}

bool ProcessNewBlock(const CChainParams& chainparams, const std::shared_ptr<const CBlock> pblock, bool fForceProcessing, bool *fNewBlock)
{
    AssertLockNotHeld(cs_main);

    {
        CBlockIndex *pindex = nullptr;
        if (fNewBlock) *fNewBlock = false;
        CValidationState state;
        // Ensure that CheckBlock() passes before calling AcceptBlock, as
        // belt-and-suspenders.
        bool ret = CheckBlock(*pblock, state, chainparams.GetConsensus());

        LOCK(cs_main);

        if (ret) {
            // Store to disk
            ret = g_chainstate.AcceptBlock(pblock, state, chainparams, &pindex, fForceProcessing, nullptr, fNewBlock);
        }
        if (!ret) {
            GetMainSignals().BlockChecked(*pblock, state);
            return error("%s: AcceptBlock FAILED (%s)", __func__, state.GetDebugMessage());
        }
    }

    NotifyHeaderTip();

    CValidationState state; // Only used to report errors, not invalidity - ignore it
    if (!g_chainstate.ActivateBestChain(state, chainparams, pblock))
        return error("%s: ActivateBestChain failed", __func__);

    return true;
}

bool TestBlockValidity(CValidationState& state, const CChainParams& chainparams, const CBlock& block, CBlockIndex* pindexPrev, bool fCheckPOW, bool fCheckMerkleRoot)
{
    AssertLockHeld(cs_main);
    assert(pindexPrev && pindexPrev == chainActive.Tip());
    CCoinsViewCache viewNew(pcoinsTip.get());
    CBlockIndex indexDummy(block);
    indexDummy.pprev = pindexPrev;
    indexDummy.nHeight = pindexPrev->nHeight + 1;

    // NOTE: CheckBlockHeader is called by CheckBlock
    if (!ContextualCheckBlockHeader(block, state, chainparams, pindexPrev, GetAdjustedTime()))
        return error("%s: Consensus::ContextualCheckBlockHeader: %s", __func__, FormatStateMessage(state));
    if (!CheckBlock(block, state, chainparams.GetConsensus(), fCheckPOW, fCheckMerkleRoot))
        return error("%s: Consensus::CheckBlock: %s", __func__, FormatStateMessage(state));
    if (!ContextualCheckBlock(block, state, chainparams.GetConsensus(), pindexPrev))
        return error("%s: Consensus::ContextualCheckBlock: %s", __func__, FormatStateMessage(state));
    if (!g_chainstate.ConnectBlock(block, state, &indexDummy, viewNew, chainparams, true))
        return false;
    assert(state.IsValid());

    return true;
}

/**
 * BLOCK PRUNING CODE
 */

/* Calculate the amount of disk space the block & undo files currently use */
uint64_t CalculateCurrentUsage()
{
    LOCK(cs_LastBlockFile);

    uint64_t retval = 0;
    for (const CBlockFileInfo &file : vinfoBlockFile) {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}

/* Prune a block file (modify associated database entries)*/
void PruneOneBlockFile(const int fileNumber)
{
    LOCK(cs_LastBlockFile);

    for (const auto& entry : mapBlockIndex) {
        CBlockIndex* pindex = entry.second;
        if (pindex->nFile == fileNumber) {
            pindex->nStatus &= ~BLOCK_HAVE_DATA;
            pindex->nStatus &= ~BLOCK_HAVE_UNDO;
            pindex->nFile = 0;
            pindex->nDataPos = 0;
            pindex->nUndoPos = 0;
            setDirtyBlockIndex.insert(pindex);

            // Prune from mapBlocksUnlinked -- any block we prune would have
            // to be downloaded again in order to consider its chain, at which
            // point it would be considered as a candidate for
            // mapBlocksUnlinked or setBlockIndexCandidates.
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> range = mapBlocksUnlinked.equal_range(pindex->pprev);
            while (range.first != range.second) {
                std::multimap<CBlockIndex *, CBlockIndex *>::iterator _it = range.first;
                range.first++;
                if (_it->second == pindex) {
                    mapBlocksUnlinked.erase(_it);
                }
            }
        }
    }

    vinfoBlockFile[fileNumber].SetNull();
    setDirtyFileInfo.insert(fileNumber);
}


void UnlinkPrunedFiles(const std::set<int>& setFilesToPrune)
{
    for (std::set<int>::iterator it = setFilesToPrune.begin(); it != setFilesToPrune.end(); ++it) {
        CDiskBlockPos pos(*it, 0);
        fs::remove(GetBlockPosFilename(pos, "blk"));
        fs::remove(GetBlockPosFilename(pos, "rev"));
        LogPrintf("Prune: %s deleted blk/rev (%05u)\n", __func__, *it);
    }
}

/* Calculate the block/rev files to delete based on height specified by user with RPC command pruneblockchain */
static void FindFilesToPruneManual(std::set<int>& setFilesToPrune, int nManualPruneHeight)
{
    assert(fPruneMode && nManualPruneHeight > 0);

    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == nullptr)
        return;

    // last block to prune is the lesser of (user-specified height, MIN_BLOCKS_TO_KEEP from the tip)
    unsigned int nLastBlockWeCanPrune = std::min((unsigned)nManualPruneHeight, chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP);
    int count=0;
    for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
        if (vinfoBlockFile[fileNumber].nSize == 0 || vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
            continue;
        PruneOneBlockFile(fileNumber);
        setFilesToPrune.insert(fileNumber);
        count++;
    }
    LogPrintf("Prune (Manual): prune_height=%d removed %d blk/rev pairs\n", nLastBlockWeCanPrune, count);
}

/* This function is called from the RPC code for pruneblockchain */
void PruneBlockFilesManual(int nManualPruneHeight)
{
    CValidationState state;
    const CChainParams& chainparams = Params();
    FlushStateToDisk(chainparams, state, FLUSH_STATE_NONE, nManualPruneHeight);
}

/**
 * Prune block and undo files (blk???.dat and undo???.dat) so that the disk space used is less than a user-defined target.
 * The user sets the target (in MB) on the command line or in config file.  This will be run on startup and whenever new
 * space is allocated in a block or undo file, staying below the target. Changing back to unpruned requires a reindex
 * (which in this case means the blockchain must be re-downloaded.)
 *
 * Pruning functions are called from FlushStateToDisk when the global fCheckForPruning flag has been set.
 * Block and undo files are deleted in lock-step (when blk00003.dat is deleted, so is rev00003.dat.)
 * Pruning cannot take place until the longest chain is at least a certain length (100000 on mainnet, 1000 on testnet, 1000 on regtest).
 * Pruning will never delete a block within a defined distance (currently 288) from the active chain's tip.
 * The block index is updated by unsetting HAVE_DATA and HAVE_UNDO for any blocks that were stored in the deleted files.
 * A db flag records the fact that at least some block files have been pruned.
 *
 * @param[out]   setFilesToPrune   The set of file indices that can be unlinked will be returned
 */
static void FindFilesToPrune(std::set<int>& setFilesToPrune, uint64_t nPruneAfterHeight)
{
    LOCK2(cs_main, cs_LastBlockFile);
    if (chainActive.Tip() == nullptr || nPruneTarget == 0) {
        return;
    }
    if ((uint64_t)chainActive.Tip()->nHeight <= nPruneAfterHeight) {
        return;
    }

    unsigned int nLastBlockWeCanPrune = chainActive.Tip()->nHeight - MIN_BLOCKS_TO_KEEP;
    uint64_t nCurrentUsage = CalculateCurrentUsage();
    // We don't check to prune until after we've allocated new space for files
    // So we should leave a buffer under our target to account for another allocation
    // before the next pruning.
    uint64_t nBuffer = BLOCKFILE_CHUNK_SIZE + UNDOFILE_CHUNK_SIZE;
    uint64_t nBytesToPrune;
    int count=0;

    if (nCurrentUsage + nBuffer >= nPruneTarget) {
        for (int fileNumber = 0; fileNumber < nLastBlockFile; fileNumber++) {
            nBytesToPrune = vinfoBlockFile[fileNumber].nSize + vinfoBlockFile[fileNumber].nUndoSize;

            if (vinfoBlockFile[fileNumber].nSize == 0)
                continue;

            if (nCurrentUsage + nBuffer < nPruneTarget)  // are we below our target?
                break;

            // don't prune files that could have a block within MIN_BLOCKS_TO_KEEP of the main chain's tip but keep scanning
            if (vinfoBlockFile[fileNumber].nHeightLast > nLastBlockWeCanPrune)
                continue;

            PruneOneBlockFile(fileNumber);
            // Queue up the files for removal
            setFilesToPrune.insert(fileNumber);
            nCurrentUsage -= nBytesToPrune;
            count++;
        }
    }

    LogPrint(BCLog::PRUNE, "Prune: target=%dMiB actual=%dMiB diff=%dMiB max_prune_height=%d removed %d blk/rev pairs\n",
           nPruneTarget/1024/1024, nCurrentUsage/1024/1024,
           ((int64_t)nPruneTarget - (int64_t)nCurrentUsage)/1024/1024,
           nLastBlockWeCanPrune, count);
}

bool CheckDiskSpace(uint64_t nAdditionalBytes)
{
    uint64_t nFreeBytesAvailable = fs::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode("Disk space is low!", _("Error: Disk space is low!"));

    return true;
}

static FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return nullptr;
    fs::path path = GetBlockPosFilename(pos, prefix);
    fs::create_directories(path.parent_path());
    FILE* file = fsbridge::fopen(path, fReadOnly ? "rb": "rb+");
    if (!file && !fReadOnly)
        file = fsbridge::fopen(path, "wb+");
    if (!file) {
        LogPrintf("Unable to open file %s\n", path.string());
        return nullptr;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            LogPrintf("Unable to seek to position %u of %s\n", pos.nPos, path.string());
            fclose(file);
            return nullptr;
        }
    }
    return file;
}

FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "blk", fReadOnly);
}

/** Open an undo file (rev?????.dat) */
static FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "rev", fReadOnly);
}

fs::path GetBlockPosFilename(const CDiskBlockPos &pos, const char *prefix)
{
    return GetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
}

CBlockIndex * CChainState::InsertBlockIndex(const uint256& hash)
{
    if (hash.IsNull())
        return nullptr;

    // Return existing
    BlockMap::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    mi = mapBlockIndex.insert(std::make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool CChainState::LoadBlockIndex(const Consensus::Params& consensus_params, CBlockTreeDB& blocktree)
{
    if (!blocktree.LoadBlockIndexGuts(consensus_params, [this](const uint256& hash){ return this->InsertBlockIndex(hash); }))
        return false;

    boost::this_thread::interruption_point();

    // Calculate nChainWork
    std::vector<std::pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    for (const std::pair<uint256, CBlockIndex*>& item : mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(std::make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    for (const std::pair<int, CBlockIndex*>& item : vSortedByHeight)
    {
        CBlockIndex* pindex = item.second;
        pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0) + GetBlockProof(*pindex);
        pindex->nTimeMax = (pindex->pprev ? std::max(pindex->pprev->nTimeMax, pindex->nTime) : pindex->nTime);
        // We can link the chain of blocks for which we've received transactions at some point.
        // Pruned nodes may have deleted the block.
        if (pindex->nTx > 0) {
            if (pindex->pprev) {
                if (pindex->pprev->nChainTx) {
                    pindex->nChainTx = pindex->pprev->nChainTx + pindex->nTx;
                } else {
                    pindex->nChainTx = 0;
                    mapBlocksUnlinked.insert(std::make_pair(pindex->pprev, pindex));
                }
            } else {
                pindex->nChainTx = pindex->nTx;
            }
        }
        if (!(pindex->nStatus & BLOCK_FAILED_MASK) && pindex->pprev && (pindex->pprev->nStatus & BLOCK_FAILED_MASK)) {
            pindex->nStatus |= BLOCK_FAILED_CHILD;
            setDirtyBlockIndex.insert(pindex);
        }
        if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS) && (pindex->nChainTx || pindex->pprev == nullptr))
            setBlockIndexCandidates.insert(pindex);
        if (pindex->nStatus & BLOCK_FAILED_MASK && (!pindexBestInvalid || pindex->nChainWork > pindexBestInvalid->nChainWork))
            pindexBestInvalid = pindex;
        if (pindex->pprev)
            pindex->BuildSkip();
        if (pindex->IsValid(BLOCK_VALID_TREE) && (pindexBestHeader == nullptr || CBlockIndexWorkComparator()(pindexBestHeader, pindex)))
            pindexBestHeader = pindex;
    }

    return true;
}

bool static LoadBlockIndexDB(const CChainParams& chainparams)
{
    if (!g_chainstate.LoadBlockIndex(chainparams.GetConsensus(), *pblocktree))
        return false;

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    vinfoBlockFile.resize(nLastBlockFile + 1);
    LogPrintf("%s: last block file = %i\n", __func__, nLastBlockFile);
    for (int nFile = 0; nFile <= nLastBlockFile; nFile++) {
        pblocktree->ReadBlockFileInfo(nFile, vinfoBlockFile[nFile]);
    }
    LogPrintf("%s: last block file info: %s\n", __func__, vinfoBlockFile[nLastBlockFile].ToString());
    for (int nFile = nLastBlockFile + 1; true; nFile++) {
        CBlockFileInfo info;
        if (pblocktree->ReadBlockFileInfo(nFile, info)) {
            vinfoBlockFile.push_back(info);
        } else {
            break;
        }
    }

    // Check presence of blk files
    LogPrintf("Checking all blk files are present...\n");
    std::set<int> setBlkDataFiles;
    for (const std::pair<uint256, CBlockIndex*>& item : mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        if (pindex->nStatus & BLOCK_HAVE_DATA) {
            setBlkDataFiles.insert(pindex->nFile);
        }
    }
    for (std::set<int>::iterator it = setBlkDataFiles.begin(); it != setBlkDataFiles.end(); it++)
    {
        CDiskBlockPos pos(*it, 0);
        if (CAutoFile(OpenBlockFile(pos, true), SER_DISK, CLIENT_VERSION).IsNull()) {
            return false;
        }
    }

    // Check whether we have ever pruned block & undo files
    pblocktree->ReadFlag("prunedblockfiles", fHavePruned);
    if (fHavePruned)
        LogPrintf("LoadBlockIndexDB(): Block files have previously been pruned\n");

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    if(fReindexing) fReindex = true;

    // Check whether we have a transaction index
    pblocktree->ReadFlag("txindex", fTxIndex);
    LogPrintf("%s: transaction index %s\n", __func__, fTxIndex ? "enabled" : "disabled");

    return true;
}

bool LoadChainTip(const CChainParams& chainparams)
{
    if (chainActive.Tip() && chainActive.Tip()->GetBlockHash() == pcoinsTip->GetBestBlock()) return true;

    if (pcoinsTip->GetBestBlock().IsNull() && mapBlockIndex.size() == 1) {
        // In case we just added the genesis block, connect it now, so
        // that we always have a chainActive.Tip() when we return.
        LogPrintf("%s: Connecting genesis block...\n", __func__);
        CValidationState state;
        if (!ActivateBestChain(state, chainparams)) {
            return false;
        }
    }

    // Load pointer to end of best chain
    BlockMap::iterator it = mapBlockIndex.find(pcoinsTip->GetBestBlock());
    if (it == mapBlockIndex.end())
        return false;
    chainActive.SetTip(it->second);

    g_chainstate.PruneBlockIndexCandidates();

    LogPrintf("Loaded best chain: hashBestChain=%s height=%d date=%s progress=%f\n",
        chainActive.Tip()->GetBlockHash().ToString(), chainActive.Height(),
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", chainActive.Tip()->GetBlockTime()),
        GuessVerificationProgress(chainparams.TxData(), chainActive.Tip()));
    return true;
}

CVerifyDB::CVerifyDB()
{
    uiInterface.ShowProgress(_("Verifying blocks..."), 0, false);
}

CVerifyDB::~CVerifyDB()
{
    uiInterface.ShowProgress("", 100, false);
}

namespace {
//! Holds the process-global sidechain database still across a verification
//! walk. Levels 3 and 4 disconnect, and level 4 reconnects, the last blocks
//! to check their undo data against a throwaway coins cache - but
//! DisconnectBlock and ConnectBlock publish the sidechain state they compute
//! to the global object, and level 3 never walks it back up. Left alone, a
//! level-3 check leaves this node's sidechain state several blocks behind
//! its own tip: it can no longer build a block (the template fails with
//! bad-scdb-update) until the next block from a peer or a restart repairs
//! it, and a level-4 check replays slot replacements against the live
//! operator caches on the way back up. The startup path resyncs afterwards
//! (init.cpp); the RPC had nothing.
//!
//! The walk itself is left exactly as it was, so what it checks does not
//! change; only its side effects are undone. Whatever exit the walk takes -
//! success, an error return, a shutdown request or a thread interruption -
//! the destructor puts the saved state back, and while the guard is alive
//! the mempool's sidechain bookkeeping is not touched (fSidechainVerifying),
//! since a transaction removed from it could not be restored.
//!
//! Needs cs_main for its whole lifetime, which VerifyDB holds: nothing can
//! connect a block in between, so the state put back is the current one.
class SidechainVerifyGuard
{
public:
    SidechainVerifyGuard() : saved(scdb) { fSidechainVerifying = true; }
    ~SidechainVerifyGuard() { scdb = saved; fSidechainVerifying = false; }
    SidechainVerifyGuard(const SidechainVerifyGuard&) = delete;
    SidechainVerifyGuard& operator=(const SidechainVerifyGuard&) = delete;
private:
    SidechainDB saved;
};
} // namespace

bool CVerifyDB::VerifyDB(const CChainParams& chainparams, CCoinsView *coinsview, int nCheckLevel, int nCheckDepth)
{
    LOCK(cs_main);
    if (chainActive.Tip() == nullptr || chainActive.Tip()->pprev == nullptr)
        return true;

    // Everything below may rewind the global sidechain database; see the guard.
    SidechainVerifyGuard scdbGuard;

    // Verify blocks in the best chain
    if (nCheckDepth <= 0 || nCheckDepth > chainActive.Height())
        nCheckDepth = chainActive.Height();
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    LogPrintf("%s: Verifying last %i blocks at level %i\n", __func__, nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(coinsview);
    CBlockIndex* pindexState = chainActive.Tip();
    CBlockIndex* pindexFailure = nullptr;
    int nGoodTransactions = 0;
    CValidationState state;
    int reportDone = 0;
    LogPrintf("[0%%]...");
    for (CBlockIndex* pindex = chainActive.Tip(); pindex && pindex->pprev; pindex = pindex->pprev)
    {
        boost::this_thread::interruption_point();
        int percentageDone = std::max(1, std::min(99, (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * (nCheckLevel >= 4 ? 50 : 100))));
        if (reportDone < percentageDone/10) {
            // report every 10% step
            LogPrintf("[%d%%]...", percentageDone);
            reportDone = percentageDone/10;
        }
        uiInterface.ShowProgress(_("Verifying blocks..."), percentageDone, false);
        if (pindex->nHeight < chainActive.Height()-nCheckDepth)
            break;
        if (fPruneMode && !(pindex->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, only go back as far as we have data.
            LogPrintf("%s: block verification stopping at height %d (pruning, no data)\n", __func__, pindex->nHeight);
            break;
        }
        CBlock block;
        // check level 0: read from disk
        if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
            return error("%s: *** ReadBlockFromDisk failed at %d, hash=%s", __func__, pindex->nHeight, pindex->GetBlockHash().ToString());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !CheckBlock(block, state, chainparams.GetConsensus()))
            return error("%s: *** found bad block at %d, hash=%s (%s)\n", __func__,
                         pindex->nHeight, pindex->GetBlockHash().ToString(), FormatStateMessage(state));
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            if (!pindex->GetUndoPos().IsNull()) {
                if (!UndoReadFromDisk(undo, pindex)) {
                    return error("%s: *** found bad undo data at %d, hash=%s\n", __func__, pindex->nHeight, pindex->GetBlockHash().ToString());
                }
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && pindex == pindexState && (coins.DynamicMemoryUsage() + pcoinsTip->DynamicMemoryUsage()) <= nCoinCacheUsage) {
            assert(coins.GetBestBlock() == pindex->GetBlockHash());
            DisconnectResult res = g_chainstate.DisconnectBlock(block, pindex, coins);
            if (res == DISCONNECT_FAILED) {
                return error("%s: *** irrecoverable inconsistency in block data at %d, hash=%s", __func__, pindex->nHeight, pindex->GetBlockHash().ToString());
            }
            pindexState = pindex->pprev;
            if (res == DISCONNECT_UNCLEAN) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
                LogPrintf("%s: *** unclean disconnect of block at %d, hash=%s\n", __func__, pindexFailure->nHeight, pindex->GetBlockHash().ToString());
            } else {
                nGoodTransactions += block.vtx.size();
            }
        }
        if (ShutdownRequested())
            return true;
    }
    if (pindexFailure)
        return error("%s: *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", __func__, chainActive.Height() - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        CBlockIndex *pindex = pindexState;
        while (pindex != chainActive.Tip()) {
            boost::this_thread::interruption_point();
            uiInterface.ShowProgress(_("Verifying blocks..."), std::max(1, std::min(99, 100 - (int)(((double)(chainActive.Height() - pindex->nHeight)) / (double)nCheckDepth * 50))), false);
            pindex = chainActive.Next(pindex);
            CBlock block;
            if (!ReadBlockFromDisk(block, pindex, chainparams.GetConsensus()))
                return error("%s: *** ReadBlockFromDisk failed at %d, hash=%s", __func__, pindex->nHeight, pindex->GetBlockHash().ToString());
            if (!g_chainstate.ConnectBlock(block, state, pindex, coins, chainparams))
                return error("%s: *** found unconnectable block at %d, hash=%s", __func__, pindex->nHeight, pindex->GetBlockHash().ToString());
        }
    }

    LogPrintf("[DONE].\n");
    LogPrintf("No coin database inconsistencies in last %i blocks (%i transactions)\n", chainActive.Height() - pindexState->nHeight, nGoodTransactions);

    return true;
}

/** Apply the effects of a block on the utxo cache, ignoring that it may already have been applied. */
bool CChainState::RollforwardBlock(const CBlockIndex* pindex, CCoinsViewCache& inputs, const CChainParams& params)
{
    // TODO: merge with ConnectBlock
    CBlock block;
    if (!ReadBlockFromDisk(block, pindex, params.GetConsensus())) {
        return error("ReplayBlock(): ReadBlockFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString());
    }

    for (const CTransactionRef& tx : block.vtx) {
        if (!tx->IsCoinBase()) {
            for (const CTxIn &txin : tx->vin) {
                inputs.SpendCoin(txin.prevout, false);
            }
        }
        // Pass check = true as every addition may be an overwrite.
        AddCoins(inputs, *tx, pindex->nHeight, true);
    }
    return true;
}

bool CChainState::ReplayBlocks(const CChainParams& params, CCoinsView* view)
{
    LOCK(cs_main);

    CCoinsViewCache cache(view);

    std::vector<uint256> hashHeads = view->GetHeadBlocks();
    if (hashHeads.empty()) return true; // We're already in a consistent state.
    if (hashHeads.size() != 2) return error("ReplayBlocks(): unknown inconsistent state");

    uiInterface.ShowProgress(_("Replaying blocks..."), 0, false);
    LogPrintf("Replaying blocks\n");

    const CBlockIndex* pindexOld = nullptr;  // Old tip during the interrupted flush.
    const CBlockIndex* pindexNew;            // New tip during the interrupted flush.
    const CBlockIndex* pindexFork = nullptr; // Latest block common to both the old and the new tip.

    if (mapBlockIndex.count(hashHeads[0]) == 0) {
        return error("ReplayBlocks(): reorganization to unknown block requested");
    }
    pindexNew = mapBlockIndex[hashHeads[0]];

    if (!hashHeads[1].IsNull()) { // The old tip is allowed to be 0, indicating it's the first flush.
        if (mapBlockIndex.count(hashHeads[1]) == 0) {
            return error("ReplayBlocks(): reorganization from unknown block requested");
        }
        pindexOld = mapBlockIndex[hashHeads[1]];
        pindexFork = LastCommonAncestor(pindexOld, pindexNew);
        assert(pindexFork != nullptr);
    }

    // Rollback along the old branch.
    while (pindexOld != pindexFork) {
        if (pindexOld->nHeight > 0) { // Never disconnect the genesis block.
            CBlock block;
            if (!ReadBlockFromDisk(block, pindexOld, params.GetConsensus())) {
                return error("RollbackBlock(): ReadBlockFromDisk() failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            LogPrintf("Rolling back %s (%i)\n", pindexOld->GetBlockHash().ToString(), pindexOld->nHeight);
            DisconnectResult res = DisconnectBlock(block, pindexOld, cache);
            if (res == DISCONNECT_FAILED) {
                return error("RollbackBlock(): DisconnectBlock failed at %d, hash=%s", pindexOld->nHeight, pindexOld->GetBlockHash().ToString());
            }
            // If DISCONNECT_UNCLEAN is returned, it means a non-existing UTXO was deleted, or an existing UTXO was
            // overwritten. It corresponds to cases where the block-to-be-disconnect never had all its operations
            // applied to the UTXO set. However, as both writing a UTXO and deleting a UTXO are idempotent operations,
            // the result is still a version of the UTXO set with the effects of that block undone.
        }
        pindexOld = pindexOld->pprev;
    }

    // Roll forward from the forking point to the new tip.
    int nForkHeight = pindexFork ? pindexFork->nHeight : 0;
    for (int nHeight = nForkHeight + 1; nHeight <= pindexNew->nHeight; ++nHeight) {
        const CBlockIndex* pindex = pindexNew->GetAncestor(nHeight);
        LogPrintf("Rolling forward %s (%i)\n", pindex->GetBlockHash().ToString(), nHeight);
        if (!RollforwardBlock(pindex, cache, params)) return false;
    }

    cache.SetBestBlock(pindexNew->GetBlockHash());
    cache.Flush();
    uiInterface.ShowProgress("", 100, false);
    return true;
}

bool ReplayBlocks(const CChainParams& params, CCoinsView* view) {
    return g_chainstate.ReplayBlocks(params, view);
}

bool CChainState::RewindBlockIndex(const CChainParams& params)
{
    LOCK(cs_main);

    // Note that during -reindex-chainstate we are called with an empty chainActive!

    int nHeight = 1;
    while (nHeight <= chainActive.Height()) {
        if (IsWitnessEnabled(chainActive[nHeight - 1], params.GetConsensus()) && !(chainActive[nHeight]->nStatus & BLOCK_OPT_WITNESS)) {
            break;
        }
        nHeight++;
    }

    // nHeight is now the height of the first insufficiently-validated block, or tipheight + 1
    CValidationState state;
    CBlockIndex* pindex = chainActive.Tip();
    while (chainActive.Height() >= nHeight) {
        if (fPruneMode && !(chainActive.Tip()->nStatus & BLOCK_HAVE_DATA)) {
            // If pruning, don't try rewinding past the HAVE_DATA point;
            // since older blocks can't be served anyway, there's
            // no need to walk further, and trying to DisconnectTip()
            // will fail (and require a needless reindex/redownload
            // of the blockchain).
            break;
        }
        if (!DisconnectTip(state, params, nullptr)) {
            return error("RewindBlockIndex: unable to disconnect block at height %i", pindex->nHeight);
        }
        // Occasionally flush state to disk.
        if (!FlushStateToDisk(params, state, FLUSH_STATE_PERIODIC))
            return false;
    }

    // Reduce validity flag and have-data flags.
    // We do this after actual disconnecting, otherwise we'll end up writing the lack of data
    // to disk before writing the chainstate, resulting in a failure to continue if interrupted.
    for (const auto& entry : mapBlockIndex) {
        CBlockIndex* pindexIter = entry.second;

        // Note: If we encounter an insufficiently validated block that
        // is on chainActive, it must be because we are a pruning node, and
        // this block or some successor doesn't HAVE_DATA, so we were unable to
        // rewind all the way.  Blocks remaining on chainActive at this point
        // must not have their validity reduced.
        if (IsWitnessEnabled(pindexIter->pprev, params.GetConsensus()) && !(pindexIter->nStatus & BLOCK_OPT_WITNESS) && !chainActive.Contains(pindexIter)) {
            // Reduce validity
            pindexIter->nStatus = std::min<unsigned int>(pindexIter->nStatus & BLOCK_VALID_MASK, BLOCK_VALID_TREE) | (pindexIter->nStatus & ~BLOCK_VALID_MASK);
            // Remove have-data flags.
            pindexIter->nStatus &= ~(BLOCK_HAVE_DATA | BLOCK_HAVE_UNDO);
            // Remove storage location.
            pindexIter->nFile = 0;
            pindexIter->nDataPos = 0;
            pindexIter->nUndoPos = 0;
            // Remove various other things
            pindexIter->nTx = 0;
            pindexIter->nChainTx = 0;
            pindexIter->nSequenceId = 0;
            // Make sure it gets written.
            setDirtyBlockIndex.insert(pindexIter);
            // Update indexes
            setBlockIndexCandidates.erase(pindexIter);
            std::pair<std::multimap<CBlockIndex*, CBlockIndex*>::iterator, std::multimap<CBlockIndex*, CBlockIndex*>::iterator> ret = mapBlocksUnlinked.equal_range(pindexIter->pprev);
            while (ret.first != ret.second) {
                if (ret.first->second == pindexIter) {
                    mapBlocksUnlinked.erase(ret.first++);
                } else {
                    ++ret.first;
                }
            }
        } else if (pindexIter->IsValid(BLOCK_VALID_TRANSACTIONS) && pindexIter->nChainTx) {
            setBlockIndexCandidates.insert(pindexIter);
        }
    }

    if (chainActive.Tip() != nullptr) {
        // We can't prune block index candidates based on our tip if we have
        // no tip due to chainActive being empty!
        PruneBlockIndexCandidates();

        CheckBlockIndex(params.GetConsensus());
    }

    return true;
}

bool RewindBlockIndex(const CChainParams& params) {
    if (!g_chainstate.RewindBlockIndex(params)) {
        return false;
    }

    if (chainActive.Tip() != nullptr) {
        // FlushStateToDisk can possibly read chainActive. Be conservative
        // and skip it here, we're about to -reindex-chainstate anyway, so
        // it'll get called a bunch real soon.
        CValidationState state;
        if (!FlushStateToDisk(params, state, FLUSH_STATE_ALWAYS)) {
            return false;
        }
    }

    return true;
}

void CChainState::UnloadBlockIndex() {
    nBlockSequenceId = 1;
    g_failed_blocks.clear();
    setBlockIndexCandidates.clear();
}

void CChainState::UnloadWBlockIndex() {
    nBlockSequenceId = 1;
    g_failed_blocks.clear();
    StartShutdown();
    setBlockIndexCandidates.clear();
}

// May NOT be used after any connections are up as much
// of the peer-processing logic assumes a consistent
// block index state
void UnloadBlockIndex()
{
    LOCK(cs_main);
    chainActive.SetTip(nullptr);
    pindexBestInvalid = nullptr;
    pindexBestHeader = nullptr;
    mempool.clear();
    mapBlocksUnlinked.clear();
    vinfoBlockFile.clear();
    nLastBlockFile = 0;
    setDirtyBlockIndex.clear();
    setDirtyFileInfo.clear();
    versionbitscache.Clear();
    for (int b = 0; b < VERSIONBITS_NUM_BITS; b++) {
        warningcache[b].clear();
    }

    for (BlockMap::value_type& entry : mapBlockIndex) {
        delete entry.second;
    }
    mapBlockIndex.clear();
    fHavePruned = false;

    g_chainstate.UnloadBlockIndex();
}

bool LoadBlockIndex(const CChainParams& chainparams)
{
    // Load block index from databases
    bool needs_init = fReindex;
    if (!fReindex) {
        bool ret = LoadBlockIndexDB(chainparams);
        if (!ret) return false;
        needs_init = mapBlockIndex.empty();
    }

    if (needs_init) {
        // Everything here is for *new* reindex/DBs. Thus, though
        // LoadBlockIndexDB may have set fReindex if we shut down
        // mid-reindex previously, we don't check fReindex and
        // instead only check it prior to LoadBlockIndexDB to set
        // needs_init.

        LogPrintf("Initializing databases...\n");
        // Use the provided setting for -txindex in the new database
        fTxIndex = gArgs.GetBoolArg("-txindex", DEFAULT_TXINDEX);
        pblocktree->WriteFlag("txindex", fTxIndex);
    }
    return true;
}

bool CChainState::LoadGenesisBlock(const CChainParams& chainparams)
{
    LOCK(cs_main);

    // Check whether we're already initialized by checking for genesis in
    // mapBlockIndex. Note that we can't use chainActive here, since it is
    // set based on the coins db, not the block index db, which is the only
    // thing loaded at this point.
    if (mapBlockIndex.count(chainparams.GenesisBlock().GetHash()))
        return true;

    try {
        CBlock &block = const_cast<CBlock&>(chainparams.GenesisBlock());
        CDiskBlockPos blockPos = SaveBlockToDisk(block, 0, chainparams, nullptr);
        if (blockPos.IsNull())
            return error("%s: writing genesis block to disk failed", __func__);
        CBlockIndex *pindex = AddToBlockIndex(block);
        CValidationState state;
        if (!ReceivedBlockTransactions(block, state, pindex, blockPos, chainparams.GetConsensus()))
            return error("%s: genesis block not accepted", __func__);
    } catch (const std::runtime_error& e) {
        return error("%s: failed to write genesis block: %s", __func__, e.what());
    }

    return true;
}

bool LoadGenesisBlock(const CChainParams& chainparams)
{
    return g_chainstate.LoadGenesisBlock(chainparams);
}

bool LoadExternalBlockFile(const CChainParams& chainparams, FILE* fileIn, CDiskBlockPos *dbp)
{
    // Map of disk positions for blocks with unknown parent (only used for reindex)
    static std::multimap<uint256, CDiskBlockPos> mapBlocksUnknownParent;
    int64_t nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        // This takes over fileIn and calls fclose() on it in the CBufferedFile destructor
        CBufferedFile blkdat(fileIn, 2*MAX_BLOCK_SERIALIZED_SIZE, MAX_BLOCK_SERIALIZED_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64_t nRewind = blkdat.GetPos();
        while (!blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[CMessageHeader::MESSAGE_START_SIZE];
                blkdat.FindByte(chainparams.MessageStart()[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, chainparams.MessageStart(), CMessageHeader::MESSAGE_START_SIZE))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SERIALIZED_SIZE)
                    continue;
            } catch (const std::exception&) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64_t nBlockPos = blkdat.GetPos();
                if (dbp)
                    dbp->nPos = nBlockPos;
                blkdat.SetLimit(nBlockPos + nSize);
                blkdat.SetPos(nBlockPos);
                std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
                CBlock& block = *pblock;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                // detect out of order blocks, and store them for later
                uint256 hash = block.GetHash();
                if (hash != chainparams.GetConsensus().hashGenesisBlock && mapBlockIndex.find(block.hashPrevBlock) == mapBlockIndex.end()) {
                    LogPrint(BCLog::REINDEX, "%s: Out of order block %s, parent %s not known\n", __func__, hash.ToString(),
                            block.hashPrevBlock.ToString());
                    if (dbp)
                        mapBlocksUnknownParent.insert(std::make_pair(block.hashPrevBlock, *dbp));
                    continue;
                }

                // process in case the block isn't known yet
                if (mapBlockIndex.count(hash) == 0 || (mapBlockIndex[hash]->nStatus & BLOCK_HAVE_DATA) == 0) {
                    LOCK(cs_main);
                    CValidationState state;
                    if (g_chainstate.AcceptBlock(pblock, state, chainparams, nullptr, true, dbp, nullptr, true /* fFromDisk */))
                        nLoaded++;
                    if (state.IsError())
                        break;
                } else if (hash != chainparams.GetConsensus().hashGenesisBlock && mapBlockIndex[hash]->nHeight % 1000 == 0) {
                    LogPrint(BCLog::REINDEX, "Block Import: already had block %s at height %d\n", hash.ToString(), mapBlockIndex[hash]->nHeight);
                }

                // Activate the genesis block so normal node progress can continue
                if (hash == chainparams.GetConsensus().hashGenesisBlock) {
                    CValidationState state;
                    if (!ActivateBestChain(state, chainparams)) {
                        break;
                    }
                }

                NotifyHeaderTip();

                // Recursively process earlier encountered successors of this block
                std::deque<uint256> queue;
                queue.push_back(hash);
                while (!queue.empty()) {
                    uint256 head = queue.front();
                    queue.pop_front();
                    std::pair<std::multimap<uint256, CDiskBlockPos>::iterator, std::multimap<uint256, CDiskBlockPos>::iterator> range = mapBlocksUnknownParent.equal_range(head);
                    while (range.first != range.second) {
                        std::multimap<uint256, CDiskBlockPos>::iterator it = range.first;
                        std::shared_ptr<CBlock> pblockrecursive = std::make_shared<CBlock>();
                        if (ReadBlockFromDisk(*pblockrecursive, it->second, chainparams.GetConsensus()))
                        {
                            LogPrint(BCLog::REINDEX, "%s: Processing out of order child %s of %s\n", __func__, pblockrecursive->GetHash().ToString(),
                                    head.ToString());
                            LOCK(cs_main);
                            CValidationState dummy;
                            if (g_chainstate.AcceptBlock(pblockrecursive, dummy, chainparams, nullptr, true, &it->second, nullptr, true /* fFromDisk */))
                            {
                                nLoaded++;
                                queue.push_back(pblockrecursive->GetHash());
                            }
                        }
                        range.first++;
                        mapBlocksUnknownParent.erase(it);
                        NotifyHeaderTip();
                    }
                }
            } catch (const std::exception& e) {
                LogPrintf("%s: Deserialize or I/O error - %s\n", __func__, e.what());
            }
        }
    } catch (const std::runtime_error& e) {
        AbortNode(std::string("System error: ") + e.what());
    }
    if (nLoaded > 0)
        LogPrintf("Loaded %i blocks from external file in %dms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}

void CChainState::CheckBlockIndex(const Consensus::Params& consensusParams)
{
    if (!fCheckBlockIndex) {
        return;
    }

    LOCK(cs_main);

    // During a reindex, we read the genesis block and call CheckBlockIndex before ActivateBestChain,
    // so we have the genesis block in mapBlockIndex but no active chain.  (A few of the tests when
    // iterating the block tree require that chainActive has been initialized.)
    if (chainActive.Height() < 0) {
        assert(mapBlockIndex.size() <= 1);
        return;
    }

    // Build forward-pointing map of the entire block tree.
    std::multimap<CBlockIndex*,CBlockIndex*> forward;
    for (auto& entry : mapBlockIndex) {
        forward.insert(std::make_pair(entry.second->pprev, entry.second));
    }

    assert(forward.size() == mapBlockIndex.size());

    std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeGenesis = forward.equal_range(nullptr);
    CBlockIndex *pindex = rangeGenesis.first->second;
    rangeGenesis.first++;
    assert(rangeGenesis.first == rangeGenesis.second); // There is only one index entry with parent nullptr.

    // Iterate over the entire block tree, using depth-first search.
    // Along the way, remember whether there are blocks on the path from genesis
    // block being explored which are the first to have certain properties.
    size_t nNodes = 0;
    int nHeight = 0;
    CBlockIndex* pindexFirstInvalid = nullptr; // Oldest ancestor of pindex which is invalid.
    CBlockIndex* pindexFirstMissing = nullptr; // Oldest ancestor of pindex which does not have BLOCK_HAVE_DATA.
    CBlockIndex* pindexFirstNeverProcessed = nullptr; // Oldest ancestor of pindex for which nTx == 0.
    CBlockIndex* pindexFirstNotTreeValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TREE (regardless of being valid or not).
    CBlockIndex* pindexFirstNotTransactionsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_TRANSACTIONS (regardless of being valid or not).
    CBlockIndex* pindexFirstNotChainValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_CHAIN (regardless of being valid or not).
    CBlockIndex* pindexFirstNotScriptsValid = nullptr; // Oldest ancestor of pindex which does not have BLOCK_VALID_SCRIPTS (regardless of being valid or not).
    while (pindex != nullptr) {
        nNodes++;
        if (pindexFirstInvalid == nullptr && pindex->nStatus & BLOCK_FAILED_VALID) pindexFirstInvalid = pindex;
        if (pindexFirstMissing == nullptr && !(pindex->nStatus & BLOCK_HAVE_DATA)) pindexFirstMissing = pindex;
        if (pindexFirstNeverProcessed == nullptr && pindex->nTx == 0) pindexFirstNeverProcessed = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTreeValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TREE) pindexFirstNotTreeValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotTransactionsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_TRANSACTIONS) pindexFirstNotTransactionsValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotChainValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_CHAIN) pindexFirstNotChainValid = pindex;
        if (pindex->pprev != nullptr && pindexFirstNotScriptsValid == nullptr && (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS) pindexFirstNotScriptsValid = pindex;

        // Begin: actual consistency checks.
        if (pindex->pprev == nullptr) {
            // Genesis block checks.
            assert(pindex->GetBlockHash() == consensusParams.hashGenesisBlock); // Genesis block's hash must match.
            assert(pindex == chainActive.Genesis()); // The current active chain's genesis block must be this block.
        }
        if (pindex->nChainTx == 0) assert(pindex->nSequenceId <= 0);  // nSequenceId can't be set positive for blocks that aren't linked (negative is used for preciousblock)
        // VALID_TRANSACTIONS is equivalent to nTx > 0 for all nodes (whether or not pruning has occurred).
        // HAVE_DATA is only equivalent to nTx > 0 (or VALID_TRANSACTIONS) if no pruning has occurred.
        if (!fHavePruned) {
            // If we've never pruned, then HAVE_DATA should be equivalent to nTx > 0
            assert(!(pindex->nStatus & BLOCK_HAVE_DATA) == (pindex->nTx == 0));
            assert(pindexFirstMissing == pindexFirstNeverProcessed);
        } else {
            // If we have pruned, then we can only say that HAVE_DATA implies nTx > 0
            if (pindex->nStatus & BLOCK_HAVE_DATA) assert(pindex->nTx > 0);
        }
        if (pindex->nStatus & BLOCK_HAVE_UNDO) assert(pindex->nStatus & BLOCK_HAVE_DATA);
        assert(((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS) == (pindex->nTx > 0)); // This is pruning-independent.
        // All parents having had data (at some point) is equivalent to all parents being VALID_TRANSACTIONS, which is equivalent to nChainTx being set.
        assert((pindexFirstNeverProcessed != nullptr) == (pindex->nChainTx == 0)); // nChainTx != 0 is used to signal that all parent blocks have been processed (but may have been pruned).
        assert((pindexFirstNotTransactionsValid != nullptr) == (pindex->nChainTx == 0));
        assert(pindex->nHeight == nHeight); // nHeight must be consistent.
        assert(pindex->pprev == nullptr || pindex->nChainWork >= pindex->pprev->nChainWork); // For every block except the genesis block, the chainwork must be larger than the parent's.
        assert(nHeight < 2 || (pindex->pskip && (pindex->pskip->nHeight < nHeight))); // The pskip pointer must point back for all but the first 2 blocks.
        assert(pindexFirstNotTreeValid == nullptr); // All mapBlockIndex entries must at least be TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TREE) assert(pindexFirstNotTreeValid == nullptr); // TREE valid implies all parents are TREE valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_CHAIN) assert(pindexFirstNotChainValid == nullptr); // CHAIN valid implies all parents are CHAIN valid
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_SCRIPTS) assert(pindexFirstNotScriptsValid == nullptr); // SCRIPTS valid implies all parents are SCRIPTS valid
        if (pindexFirstInvalid == nullptr) {
            // Checks for not-invalid blocks.
            assert((pindex->nStatus & BLOCK_FAILED_MASK) == 0); // The failed mask cannot be set for blocks without invalid parents.
        }
        if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && pindexFirstNeverProcessed == nullptr) {
            if (pindexFirstInvalid == nullptr) {
                // If this block sorts at least as good as the current tip and
                // is valid and we have all data for its parents, it must be in
                // setBlockIndexCandidates.  chainActive.Tip() must also be there
                // even if some data has been pruned.
                if (pindexFirstMissing == nullptr || pindex == chainActive.Tip()) {
                    assert(setBlockIndexCandidates.count(pindex));
                }
                // If some parent is missing, then it could be that this block was in
                // setBlockIndexCandidates but had to be removed because of the missing data.
                // In this case it must be in mapBlocksUnlinked -- see test below.
            }
        } else { // If this block sorts worse than the current tip or some ancestor's block has never been seen, it cannot be in setBlockIndexCandidates.
            assert(setBlockIndexCandidates.count(pindex) == 0);
        }
        // Check whether this block is in mapBlocksUnlinked.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangeUnlinked = mapBlocksUnlinked.equal_range(pindex->pprev);
        bool foundInUnlinked = false;
        while (rangeUnlinked.first != rangeUnlinked.second) {
            assert(rangeUnlinked.first->first == pindex->pprev);
            if (rangeUnlinked.first->second == pindex) {
                foundInUnlinked = true;
                break;
            }
            rangeUnlinked.first++;
        }
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed != nullptr && pindexFirstInvalid == nullptr) {
            // If this block has block data available, some parent was never received, and has no invalid parents, it must be in mapBlocksUnlinked.
            assert(foundInUnlinked);
        }
        if (!(pindex->nStatus & BLOCK_HAVE_DATA)) assert(!foundInUnlinked); // Can't be in mapBlocksUnlinked if we don't HAVE_DATA
        if (pindexFirstMissing == nullptr) assert(!foundInUnlinked); // We aren't missing data for any parent -- cannot be in mapBlocksUnlinked.
        if (pindex->pprev && (pindex->nStatus & BLOCK_HAVE_DATA) && pindexFirstNeverProcessed == nullptr && pindexFirstMissing != nullptr) {
            // We HAVE_DATA for this block, have received data for all parents at some point, but we're currently missing data for some parent.
            assert(fHavePruned); // We must have pruned.
            // This block may have entered mapBlocksUnlinked if:
            //  - it has a descendant that at some point had more work than the
            //    tip, and
            //  - we tried switching to that descendant but were missing
            //    data for some intermediate block between chainActive and the
            //    tip.
            // So if this block is itself better than chainActive.Tip() and it wasn't in
            // setBlockIndexCandidates, then it must be in mapBlocksUnlinked.
            if (!CBlockIndexWorkComparator()(pindex, chainActive.Tip()) && setBlockIndexCandidates.count(pindex) == 0) {
                if (pindexFirstInvalid == nullptr) {
                    assert(foundInUnlinked);
                }
            }
        }
        // assert(pindex->GetBlockHash() == pindex->GetBlockHeader().GetHash()); // Perhaps too slow
        // End: actual consistency checks.

        // Try descending into the first subnode.
        std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> range = forward.equal_range(pindex);
        if (range.first != range.second) {
            // A subnode was found.
            pindex = range.first->second;
            nHeight++;
            continue;
        }
        // This is a leaf node.
        // Move upwards until we reach a node of which we have not yet visited the last child.
        while (pindex) {
            // We are going to either move to a parent or a sibling of pindex.
            // If pindex was the first with a certain property, unset the corresponding variable.
            if (pindex == pindexFirstInvalid) pindexFirstInvalid = nullptr;
            if (pindex == pindexFirstMissing) pindexFirstMissing = nullptr;
            if (pindex == pindexFirstNeverProcessed) pindexFirstNeverProcessed = nullptr;
            if (pindex == pindexFirstNotTreeValid) pindexFirstNotTreeValid = nullptr;
            if (pindex == pindexFirstNotTransactionsValid) pindexFirstNotTransactionsValid = nullptr;
            if (pindex == pindexFirstNotChainValid) pindexFirstNotChainValid = nullptr;
            if (pindex == pindexFirstNotScriptsValid) pindexFirstNotScriptsValid = nullptr;
            // Find our parent.
            CBlockIndex* pindexPar = pindex->pprev;
            // Find which child we just visited.
            std::pair<std::multimap<CBlockIndex*,CBlockIndex*>::iterator,std::multimap<CBlockIndex*,CBlockIndex*>::iterator> rangePar = forward.equal_range(pindexPar);
            while (rangePar.first->second != pindex) {
                assert(rangePar.first != rangePar.second); // Our parent must have at least the node we're coming from as child.
                rangePar.first++;
            }
            // Proceed to the next one.
            rangePar.first++;
            if (rangePar.first != rangePar.second) {
                // Move to the sibling.
                pindex = rangePar.first->second;
                break;
            } else {
                // Move up further.
                pindex = pindexPar;
                nHeight--;
                continue;
            }
        }
    }

    // Check that we actually traversed the entire map.
    assert(nNodes == forward.size());
}

std::string CBlockFileInfo::ToString() const
{
    return strprintf("CBlockFileInfo(blocks=%u, size=%u, heights=%u...%u, time=%s...%s)", nBlocks, nSize, nHeightFirst, nHeightLast, DateTimeStrFormat("%Y-%m-%d", nTimeFirst), DateTimeStrFormat("%Y-%m-%d", nTimeLast));
}

CBlockFileInfo* GetBlockFileInfo(size_t n)
{
    LOCK(cs_LastBlockFile);

    return &vinfoBlockFile.at(n);
}

ThresholdState VersionBitsTipState(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsState(chainActive.Tip(), params, pos, versionbitscache);
}

BIP9Stats VersionBitsTipStatistics(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStatistics(chainActive.Tip(), params, pos);
}

int VersionBitsTipStateSinceHeight(const Consensus::Params& params, Consensus::DeploymentPos pos)
{
    LOCK(cs_main);
    return VersionBitsStateSinceHeight(chainActive.Tip(), params, pos, versionbitscache);
}

static const uint64_t MEMPOOL_DUMP_VERSION = 1;

bool LoadMempool(void)
{
    const CChainParams& chainparams = Params();
    int64_t nExpiryTimeout = gArgs.GetArg("-mempoolexpiry", DEFAULT_MEMPOOL_EXPIRY) * 60 * 60;
    FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat", "rb");
    CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);
    if (file.IsNull()) {
        LogPrintf("Failed to open mempool file from disk. Continuing anyway.\n");
        return false;
    }

    int64_t count = 0;
    int64_t expired = 0;
    int64_t failed = 0;
    int64_t already_there = 0;
    int64_t nNow = GetTime();

    try {
        uint64_t version;
        file >> version;
        if (version != MEMPOOL_DUMP_VERSION) {
            return false;
        }
        uint64_t num;
        file >> num;
        while (num--) {
            CTransactionRef tx;
            int64_t nTime;
            int64_t nFeeDelta;
            file >> tx;
            file >> nTime;
            file >> nFeeDelta;

            CAmount amountdelta = nFeeDelta;
            if (amountdelta) {
                mempool.PrioritiseTransaction(tx->GetHash(), amountdelta);
            }
            CValidationState state;
            if (nTime + nExpiryTimeout > nNow) {
                LOCK(cs_main);
                AcceptToMemoryPoolWithTime(chainparams, mempool, state, tx, nullptr /* pfMissingInputs */, nTime,
                                           nullptr /* plTxnReplaced */, false /* bypass_limits */, 0 /* nAbsurdFee */);
                if (state.IsValid()) {
                    ++count;
                } else {
                    // mempool may contain the transaction already, e.g. from
                    // wallet(s) having loaded it while we were processing
                    // mempool transactions; consider these as valid, instead of
                    // failed, but mark them as 'already there'
                    if (mempool.exists(tx->GetHash())) {
                        ++already_there;
                    } else {
                        ++failed;
                    }
                }
            } else {
                ++expired;
            }
            if (ShutdownRequested())
                return false;
        }
        std::map<uint256, CAmount> mapDeltas;
        file >> mapDeltas;

        for (const auto& i : mapDeltas) {
            mempool.PrioritiseTransaction(i.first, i.second);
        }
    } catch (const std::exception& e) {
        LogPrintf("Failed to deserialize mempool data on disk: %s. Continuing anyway.\n", e.what());
        return false;
    }

    LogPrintf("Imported mempool transactions from disk: %i succeeded, %i failed, %i expired, %i already there\n", count, failed, expired, already_there);
    return true;
}

bool DumpMempool(void)
{
    int64_t start = GetTimeMicros();

    std::map<uint256, CAmount> mapDeltas;
    std::vector<TxMempoolInfo> vinfo;

    {
        LOCK(mempool.cs);
        for (const auto &i : mempool.mapDeltas) {
            mapDeltas[i.first] = i.second;
        }
        vinfo = mempool.infoAll();
    }

    int64_t mid = GetTimeMicros();

    try {
        FILE* filestr = fsbridge::fopen(GetDataDir() / "mempool.dat.new", "wb");
        if (!filestr) {
            return false;
        }

        CAutoFile file(filestr, SER_DISK, CLIENT_VERSION);

        uint64_t version = MEMPOOL_DUMP_VERSION;
        file << version;

        file << (uint64_t)vinfo.size();
        for (const auto& i : vinfo) {
            file << *(i.tx);
            file << (int64_t)i.nTime;
            file << (int64_t)i.nFeeDelta;
            mapDeltas.erase(i.tx->GetHash());
        }

        file << mapDeltas;
        // Keep the previous dump rather than replacing it with one that never
        // reached the disk.
        if (!FileCommit(file.Get())) {
            LogPrintf("Failed to dump mempool: could not flush the file. Continuing anyway.\n");
            return false;
        }
        file.fclose();
        if (!RenameOver(GetDataDir() / "mempool.dat.new", GetDataDir() / "mempool.dat")) {
            LogPrintf("Failed to dump mempool: could not replace the previous file. Continuing anyway.\n");
            return false;
        }
        int64_t last = GetTimeMicros();
        LogPrintf("Dumped mempool: %gs to copy, %gs to dump\n", (mid-start)*MICRO, (last-mid)*MICRO);
    } catch (const std::exception& e) {
        LogPrintf("Failed to dump mempool: %s. Continuing anyway.\n", e.what());
        return false;
    }
    return true;
}

static const uint64_t SCDB_DUMP_VERSION = 1;

//! Version for deposit.dat alone, which carries a field the other dump files do
//! not. It is separate from SCDB_DUMP_VERSION so that adding it does not
//! invalidate withdrawal.dat and the rest, which would force a reindex on every
//! upgrade for no reason.
//!
//! Version 1 is the historical layout: a count and the deposits. Version 2
//! prefixes the block the cache corresponds to, which is what makes a stale
//! cache detectable at all - see LoadDepositCache.
static const uint64_t SCDB_DEPOSIT_DUMP_VERSION_LEGACY = 1;
static const uint64_t SCDB_DEPOSIT_DUMP_VERSION = 2;

//! Read a cache file, tolerating one that an older Windows build wrote in text
//! mode.
//!
//! Those builds opened these files with "w", so the C runtime turned every 0x0A
//! into 0x0D 0x0A on the way out. Reading such a file back in binary gives
//! misaligned data, and for the fixed-width ones it does not even throw - it
//! returns success with garbage, which the next clean shutdown then writes back
//! over the real thing.
//!
//! Both candidate readings are produced here and handed to the caller in order:
//! the bytes as they sit on disk, then the same bytes with the expansion undone.
//! The caller parses the first that works. Undoing the expansion in memory
//! rather than reopening in text mode keeps the behaviour identical on every
//! platform, which means it can be tested somewhere other than Windows.
CacheRead ReadCacheFileCandidates(const fs::path& path, std::vector<CDataStream>& vCandidate)
{
    vCandidate.clear();

    if (!fs::exists(path))
        return CacheRead::MISSING;

    FILE* file = fsbridge::fopen(path, "rb");
    if (!file)
        return CacheRead::UNOPENABLE;

    std::string strRaw;
    {
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), file)) > 0)
            strRaw.append(buf, n);
        const bool fReadError = ferror(file) != 0;
        fclose(file);
        if (fReadError)
            return CacheRead::UNOPENABLE;
    }

    vCandidate.emplace_back(strRaw.data(), strRaw.data() + strRaw.size(), SER_DISK, CLIENT_VERSION);

    std::string strUndone;
    strUndone.reserve(strRaw.size());
    for (size_t i = 0; i < strRaw.size(); i++) {
        if (strRaw[i] == '\r' && i + 1 < strRaw.size() && strRaw[i + 1] == '\n')
            continue;
        strUndone.push_back(strRaw[i]);
    }
    if (strUndone.size() != strRaw.size())
        vCandidate.emplace_back(strUndone.data(), strUndone.data() + strUndone.size(), SER_DISK, CLIENT_VERSION);

    return CacheRead::OK;
}

namespace {
/** 0.45.2: the custom withdrawal votes (one string per slot: the abstain or
 *  downvote character, or the hash of the bundle this node upvotes) read
 *  from customvotes.dat while blocks are still to be connected, held back
 *  until they have been - every sidechain activation a replay connects
 *  resets that slot's vote to abstain. Empty when nothing is held. */
CCriticalSection cs_vote_replay;
std::vector<std::string> g_vVoteAfterReplay GUARDED_BY(cs_vote_replay);
//! slot -> occupant (Sidechain::GetSerHash) when the file was written; a slot
//! missing here means the file does not say (written before 0.45.2).
std::map<uint8_t, uint256> g_mapVoteOccupant GUARDED_BY(cs_vote_replay);

bool IsAbstainVote(const std::string& strVote)
{
    return strVote.size() == 1 && strVote.front() == SCDB_ABSTAIN;
}
} // namespace

bool LoadCustomVoteCache(bool fHold)
{
    fs::path path = GetDataDir() / "skydoge" / "customvotes.dat";
    CAutoFile filein(fsbridge::fopen(path, "rb"), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        // A file that is there but will not open is not the same as no file
        // at all. Reporting "nothing to load" would let startup finish with an
        // empty cache and shutdown write that emptiness over data nothing can
        // rebuild, so say the load failed and leave the file alone.
        if (fs::exists(path))
            return error("%s: %s exists but could not be opened", __func__, path.string());
        return true;
    }

    std::vector<std::string> vVote;
    try {
        int64_t nVersion;
        filein >> nVersion;
        if (nVersion != SCDB_DUMP_VERSION) {
            return false;
        }

        int count = 0;
        filein >> count;

        if (count != SIDECHAIN_ACTIVATION_MAX_ACTIVE)
            return false;

        for (int i = 0; i < count; i++) {
            std::string strVote;
            filein >> strVote;
            vVote.push_back(strVote);
        }
    }
    catch (const std::exception& e) {
        LogPrintf("%s: Exception: %s\n", __func__, e.what());
        return false;
    }

    // 0.45.2: the occupant section after the votes (earlier releases stop
    // reading before it). Absent or short: no slot states its occupant.
    std::map<uint8_t, uint256> mapOccupant;
    try {
        int nOccupant = 0;
        filein >> nOccupant;
        for (int i = 0; i < nOccupant; i++) {
            uint8_t nSidechain = 0;
            uint256 hashOccupant;
            filein >> nSidechain;
            filein >> hashOccupant;
            mapOccupant[nSidechain] = hashOccupant;
        }
    }
    catch (const std::exception&) {
        mapOccupant.clear();
    }

    if (fHold && !vVote.empty()) {
        // 0.45.2: blocks are still to be connected and each sidechain
        // activation among them resets that slot's vote, so the votes are
        // installed afterwards (InstallReplayedCustomVotes).
        LOCK(cs_vote_replay);
        g_vVoteAfterReplay = vVote;
        g_mapVoteOccupant = mapOccupant;
        LogPrintf("%s: Holding the custom withdrawal votes until the blocks still to connect are connected.\n", __func__);
        return true;
    }

    // Add to SCDB
    if (!vVote.empty()) {
        scdb.CacheCustomVotes(vVote);
    }

    return true;
}

void InstallReplayedCustomVotes()
{
    LOCK2(cs_main, cs_vote_replay);
    if (g_vVoteAfterReplay.empty())
        return;

    // Slot by slot, the held vote replaces the live one only where the live
    // one is still abstain (a vote set while the blocks were being connected
    // is newer) and:
    //  - the slot is active;
    //  - where the file names the slot's occupant, it is still the same
    //    sidechain (the previous-occupant guard's rule, applied once, to the
    //    occupant at the end);
    //  - where it does not (a file written before 0.45.2): an upvote names a
    //    bundle the chain tracks or this node has cached for that slot; a
    //    downvote is kept.
    std::vector<std::string> vVote = scdb.GetVotes();
    // What stays held: the votes of slots this chain does not show active
    // (see InstallReplayedWithdrawalCache) - written back as read.
    std::vector<std::string> vStillHeld(g_vVoteAfterReplay.size(), std::string(1, SCDB_ABSTAIN));
    bool fStillHeld = false;
    unsigned int nKept = 0, nHeld = 0;
    for (size_t i = 0; i < g_vVoteAfterReplay.size() && i < vVote.size(); i++) {
        const std::string& strHeld = g_vVoteAfterReplay[i];
        if (IsAbstainVote(strHeld))
            continue;
        nHeld++;
        const uint8_t nSidechain = (uint8_t)i;
        std::string strDrop;
        Sidechain sidechain;
        if (!IsAbstainVote(vVote[i])) {
            strDrop = "a newer vote was set while the blocks were being connected";
        } else if (!scdb.GetSidechain(nSidechain, sidechain)) {
            vStillHeld[i] = strHeld;
            fStillHeld = true;
            continue;
        } else {
            const auto it = g_mapVoteOccupant.find(nSidechain);
            if (it != g_mapVoteOccupant.end() && !it->second.IsNull()) {
                if (sidechain.GetSerHash() != it->second)
                    strDrop = "the slot holds a different sidechain now";
            } else if (strHeld.size() == 64) {
                const uint256 hash = uint256S(strHeld);
                if (!scdb.HaveWorkScore(hash, nSidechain) && !scdb.HaveWithdrawalTxCachedForSlot(nSidechain, hash))
                    strDrop = "the file names no occupant and the upvoted bundle is neither tracked nor cached";
            }
        }
        if (!strDrop.empty()) {
            LogPrintf("%s: Not restoring the custom withdrawal vote %s for slot %u: %s.\n",
                      __func__, strHeld, (unsigned)nSidechain, strDrop);
            continue;
        }
        vVote[i] = strHeld;
        nKept++;
    }
    if (nKept && !scdb.CacheCustomVotes(vVote))
        LogPrintf("%s: The restored custom withdrawal votes were refused.\n", __func__);
    LogPrintf("%s: Blocks connected: restored %u of %u custom withdrawal vote(s)%s.\n", __func__, nKept, nHeld,
              fStillHeld ? "; votes for slots not active here stay held" : "");
    if (fStillHeld) {
        g_vVoteAfterReplay.swap(vStillHeld);
    } else {
        g_vVoteAfterReplay.clear();
        g_mapVoteOccupant.clear();
    }
}

void DumpCustomVoteCache()
{
    std::vector<std::string> vVote = scdb.GetVotes();

    // 0.45.2: votes still held back (the node stopped before the blocks
    // were connected) are written as they were read, where the live vote is
    // abstain, with the occupant they were read with. Every other non-abstain
    // vote is written with its slot's current occupant.
    std::vector<std::pair<uint8_t, uint256>> vOccupant;
    {
        LOCK(cs_vote_replay);
        for (size_t i = 0; i < vVote.size(); i++) {
            const uint8_t nSidechain = (uint8_t)i;
            if (i < g_vVoteAfterReplay.size() && IsAbstainVote(vVote[i]) && !IsAbstainVote(g_vVoteAfterReplay[i])) {
                vVote[i] = g_vVoteAfterReplay[i];
                const auto it = g_mapVoteOccupant.find(nSidechain);
                if (it != g_mapVoteOccupant.end())
                    vOccupant.push_back(std::make_pair(nSidechain, it->second));
                continue;
            }
            if (IsAbstainVote(vVote[i]))
                continue;
            Sidechain sidechain;
            if (scdb.GetSidechain(nSidechain, sidechain))
                vOccupant.push_back(std::make_pair(nSidechain, sidechain.GetSerHash()));
        }
    }

    int count = vVote.size();

    // Write the votes
    fs::path path = GetDataDir() / "skydoge" / "customvotes.dat.new";
    CAutoFile fileout(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return;
    }

    try {
        fileout << SCDB_DUMP_VERSION; // version required to read
        fileout << count; // Number of deposits in file

        for (const std::string& vote : vVote) {
            fileout << vote;
        }

        // 0.45.2: (slot, occupant) for the slots with a vote, after
        // everything earlier releases read.
        fileout << (int)vOccupant.size();
        for (const std::pair<uint8_t, uint256>& o : vOccupant) {
            fileout << o.first;
            fileout << o.second;
        }
    }
    catch (const std::exception& e) {
        LogPrintf("%s: Exception: %s\n", __func__, e.what());
        return;
    }

    if (!FileCommit(fileout.Get())) {
        // The replacement never reached the disk. Renaming it over the previous
        // file would trade a good copy for a truncated one, so keep what is
        // there; the .new file is overwritten on the next attempt.
        LogPrintf("%s: Failed to write the cache file; keeping the previous copy.\n", __func__);
        return;
    }
    fileout.fclose();
    if (!RenameOver(GetDataDir() / "skydoge" / "customvotes.dat.new",
                    GetDataDir() /  "skydoge" / "customvotes.dat")) {
        LogPrintf("%s: Failed to replace the previous file; the cache was not saved.\n", __func__);
        return;
    }

    LogPrintf("%s: Wrote %u\n", __func__, count);
}

//! Whether startup completed far enough for the in-memory caches read from disk
//! to be authoritative. Shutdown runs on the failure paths too, so every writer
//! of a file that only startup can populate has to consult this first or it will
//! put default-constructed state over the user's copy. Covers the sidechain
//! caches and the address book, which are read just before this is set; see
//! SetSCDBStateLoaded(), DumpSCDBCache() and DumpAddressBook().
static bool fSCDBStateLoaded = false;

void SetSCDBStateLoaded()
{
    fSCDBStateLoaded = true;
}

bool LoadDepositCache()
{
    fs::path path = GetDataDir() / "skydoge" / "deposit.dat";
    CAutoFile filein(fsbridge::fopen(path, "rb"), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        // No file at all is the normal state for a new data directory, and an
        // empty cache is the right answer there.
        //
        // A file that exists but will not open is a different matter, and must
        // not be treated as success where this file is the only copy of the
        // treasury. Carrying on would leave the node validating withdrawals
        // against an empty CTIP map, rejecting blocks the rest of the network
        // accepts, and would then let shutdown write that empty cache back over
        // the file. Fail instead, so the caller can offer the reindex that
        // rebuilds the cache from blocks.
        //
        // Where the block record carried a treasury log, ResyncSCDB has already
        // installed the pointer and an unreadable file costs only the deposit
        // history, so refusing to start would be a worse answer than starting
        // without it. Say so and carry on.
        if (fs::exists(path) && scdb.HasTreasuryFromRecord()) {
            LogPrintf("%s: %s exists but could not be opened. The treasury was restored from the "
                      "block record, so the node starts without its cached deposit history.\n",
                    __func__, path.string());
            return true;
        }

        if (fs::exists(path)) {
            LogPrintf("%s: %s exists but could not be opened; refusing to start with an empty deposit cache.\n",
                    __func__, path.string());
            return false;
        }
        return true;
    }

    std::vector<SidechainDeposit> vDeposit;
    uint256 hashCacheBlock;
    bool fHaveCacheBlock = false;
    try {
        uint64_t nVersion;
        filein >> nVersion;
        if (nVersion != SCDB_DEPOSIT_DUMP_VERSION &&
                nVersion != SCDB_DEPOSIT_DUMP_VERSION_LEGACY) {
            return false;
        }

        if (nVersion == SCDB_DEPOSIT_DUMP_VERSION) {
            filein >> hashCacheBlock;
            fHaveCacheBlock = true;
        }

        int count = 0;
        filein >> count;
        for (int i = 0; i < count; i++) {
            SidechainDeposit deposit;
            filein >> deposit;
            vDeposit.push_back(deposit);
        }
    }
    catch (const std::exception& e) {
        LogPrintf("%s: Exception: %s\n", __func__, e.what());
        return false;
    }

    // Refuse a cache that does not describe the chain we are about to run on.
    //
    // This file is written once, during shutdown, and is the only record of the
    // deposits and of the CTIPs derived from them - the sidechain index restores
    // the withdrawal, activation and sidechain lists but not these. So a node
    // that stopped uncleanly comes back with the treasury as of its last clean
    // shutdown while the chain has moved on, and nothing about that is visible:
    // it starts normally and serves a treasury the chain does not support. The
    // damage surfaces later, when a withdrawal is paid out and SpendWithdrawal
    // compares the payout's input against the CTIP this node believes in; the
    // mismatch rejects a block the rest of the network accepted, at DoS(0), so
    // the node quietly stops following the chain.
    //
    // Comparing the live hashBlockLastSeen would not catch this. ResyncSCDB runs
    // before this function and sets it to the tip, so by now it always agrees.
    // The stamp recorded in the file at dump time is the only thing that can be
    // checked against the chain.
    //
    // A null stamp is a special case that must not be refused. The sidechain
    // database only records a block once it has connected one past genesis, so
    // a cache written while the tip was still genesis is stamped null - and it
    // is necessarily empty, because a deposit cannot be cached without the block
    // that carried it. An empty cache installs nothing and cannot be stale, so a
    // node shut down cleanly at the genesis tip must be allowed to start. Only a
    // non-null stamp that names a different block is the dangerous case.
    //
    // All of that describes a node whose treasury can only come from this file.
    // Where the block record carried a treasury log, ResyncSCDB has already
    // installed the pointer from the block it belongs to, and a stale file is
    // no longer dangerous - only useless for the part it used to be trusted
    // for. It is still worth reading for its deposits, which are this node's
    // own history and are shown by the GUI and the RPCs, so the file is loaded
    // and told not to move the pointer.
    const bool fTreasuryFromRecord = scdb.HasTreasuryFromRecord();

    if (fHaveCacheBlock && !hashCacheBlock.IsNull()) {
        const uint256 hashTip = chainActive.Tip() ? chainActive.Tip()->GetBlockHash() : uint256();
        if (hashCacheBlock != hashTip) {
            if (!fTreasuryFromRecord) {
                LogPrintf("%s: Deposit cache describes block %s but the chain is at %s. "
                          "Refusing to load a stale deposit cache; the caller rebuilds it "
                          "from blocks, and offers a reindex only if that cannot run.\n",
                        __func__, hashCacheBlock.ToString(), hashTip.ToString());
                return false;
            }

            LogPrintf("%s: Deposit cache describes block %s but the chain is at %s. "
                      "The treasury was restored from the block record, so the cache is loaded "
                      "for its deposit history only and does not set the treasury.\n",
                    __func__, hashCacheBlock.ToString(), hashTip.ToString());
        }
    } else if (!fHaveCacheBlock) {
        // Written by a build that did not record the block. Nothing can be
        // verified, so say so rather than implying it was checked. The next
        // clean shutdown writes a stamped file and this stops appearing.
        LogPrintf("%s: Deposit cache predates block stamping and cannot be checked against "
                  "the chain. It will be verifiable after the next clean shutdown.\n", __func__);
    }

    // Add to SCDB
    if (!vDeposit.empty()) {
        // Tolerant, matching the ConnectBlock consensus path: AddDeposits logs and
        // continues on an unsortable (e.g. forked) deposit chain. Do NOT fail the
        // load / force a reindex on it — the condition is on-chain data a reindex
        // cannot fix, and the legacy build started fine in exactly this state.
        //
        // The pointer is left alone when it was restored from the block record:
        // that value belongs to the tip, and this file may not.
        scdb.AddDeposits(vDeposit, !fTreasuryFromRecord /* fUpdateCTIP */);

        // Publish the treasury the node is actually going to use, whichever of
        // the two set it.
        mempool.UpdateCTIPFromBlock(scdb.GetCTIP(), false /* fDisconnect */);
    }

    return true;
}

//! Rebuild the sidechain deposit cache by re-scanning local block files.
//!
//! The repair half of the sidechain database. Every durability measure in this
//! tree faithfully preserves whatever the node currently believes; this is the
//! only path that makes a node's sidechain state agree with its own chain
//! again, and it replaces the full reindex that a stale or missing deposit
//! cache used to force. Without it a node could have to re-verify the
//! whole chain.
//!
//! It is cheap because a deposit is a function of a block's own outputs: no
//! re-download, no script verification, no coins view, no undo data. The work
//! is one pass of ReadBlockFromDisk over the blocks that could carry a deposit.
//!
//! Two things make this a replay rather than a re-derivation, and both matter:
//!
//! - The per-block records drive it. AddDeposits drops deposits for a slot that
//!   is not active, so which sidechains were active AT EACH BLOCK changes the
//!   answer. Seeding that from the tip would accept deposits sitting in blocks
//!   from before their sidechain existed, which ConnectBlock skipped - a
//!   divergence invented by the repair itself. Applying each block's record as
//!   we reach it advances the activation state exactly as it stood.
//!
//! - The deposits come from GetBlockDeposits and the withdrawal change returns
//!   from GetWithdrawalChangeDeposit, which are the same functions the connect
//!   path uses. A second implementation of connect-time semantics is the one
//!   way this pass could manufacture the divergence it exists to repair.
//!
//! Cross-check every carried treasury pointer against the unspent output set.
//!
//! The pointer is maintained state; the coins view is the one store every node
//! shares. A pointer naming a coin that is not there, or that carries a
//! different amount or another slot's script, is this node disagreeing with
//! the chain about where a sidechain's money is - the condition that surfaces
//! years later as a refused withdrawal payout, and the one CTIPAnchorHeight
//! makes a block-level rule once it is set.
//!
//! Reports and never repairs, deliberately. A rebuild fixes a deposit cache
//! that has fallen behind its own chain; it cannot fix a pointer the chain
//! genuinely does not support, and running one here would hide the finding
//! behind a repair that did not repair it. It also runs before any height is
//! set, so it must not be able to change what the node validates.
//!
//! Returns the number of pointers that failed.
int AuditTreasuryAnchors()
{
    AssertLockHeld(cs_main);

    if (!pcoinsTip)
        return 0;

    const std::map<uint8_t, SidechainCTIP> mapCTIP = scdb.GetCTIP();
    std::vector<std::string> vFail;

    for (const std::pair<const uint8_t, SidechainCTIP>& p : mapCTIP) {
        const Coin& coin = pcoinsTip->AccessCoin(p.second.out);
        uint8_t nSidechainCoin;
        if (coin.IsSpent()) {
            vFail.push_back(strprintf("sidechain %u: %s is not unspent",
                                      p.first, p.second.out.ToString()));
        } else if (!coin.out.scriptPubKey.IsDrivechain(nSidechainCoin) ||
                   nSidechainCoin != p.first) {
            vFail.push_back(strprintf("sidechain %u: %s is not a treasury output of that slot",
                                      p.first, p.second.out.ToString()));
        } else if (coin.out.nValue != p.second.amount) {
            vFail.push_back(strprintf("sidechain %u: %s holds %d, recorded as %d",
                                      p.first, p.second.out.ToString(),
                                      coin.out.nValue, p.second.amount));
        }
    }

    // "Anchored" here means only that the pointer names an unspent output with
    // the right script and amount. It is necessary, not sufficient: a stale
    // pointer that happens to name a still-live output of the right shape
    // passes too, so "all anchored" is not "state is correct". The lineage
    // half - that the pointer is the one this chain implies - is
    // CheckDepositContinuity's, and only a reindex settles it end to end.
    // Said in the log so nobody reads a clean count as a clean bill of health.
    LogPrintf("%s: %u treasury pointer(s), %u anchored, %u not anchored. "
              "(Anchored = unspent with matching script and amount; it does not "
              "confirm the pointer is the one the chain implies - only a reindex "
              "does.)\n",
              __func__, (unsigned)mapCTIP.size(),
              (unsigned)(mapCTIP.size() - vFail.size()), (unsigned)vFail.size());

    if (vFail.empty())
        return 0;

    std::string strMessage =
        "Warning: SCDB DIVERGENCE POSSIBLE: this node carries sidechain treasury "
        "pointers that the unspent output set does not support. The money a "
        "sidechain can withdraw is not where this node believes it is, and a "
        "withdrawal payout the rest of the network accepts will be rejected here. "
        "Nothing has been changed automatically. Details:";
    for (const std::string& str : vFail) {
        strMessage += "\n  " + str;
        LogPrintf("%s: NOT ANCHORED - %s\n", __func__, str);
    }

    LogPrintf("%s\n", strMessage);
    AlertNotify(strMessage);

    return (int)vFail.size();
}

//! Builds into a local database and installs it only on success, so a failure
//! part-way leaves the node exactly as it was.
//!
//! Only the state the chain describes is rebuilt. The state that is this
//! node's own - how its operator votes, what it is proposing, which bundles it
//! is carrying - is carried across unchanged in the block just before the
//! install; see the comment there for why reloading it from the cache files
//! would not do.
bool RebuildSidechainDeposits(std::string& strError)
{
    AssertLockHeld(cs_main);

    const CBlockIndex* pindexTip = chainActive.Tip();
    if (!pindexTip) {
        strError = "no active chain to rebuild from";
        return false;
    }

    if (!psidechaintree) {
        strError = "sidechain index is not open";
        return false;
    }

    const int64_t nTimeStart = GetTimeMillis();
    const Consensus::Params& consensus = Params().GetConsensus();

    SidechainDB dbRebuild;

    int nBlocksRead = 0;
    int nDepositsFound = 0;
    int nChangeReturns = 0;

    uiInterface.InitMessage(_("Rebuilding sidechain database from blocks..."));

    for (int nHeight = 1; nHeight <= pindexTip->nHeight; nHeight++) {
        const CBlockIndex* pindex = chainActive[nHeight];
        if (!pindex) {
            strError = strprintf("chain is missing height %d", nHeight);
            return false;
        }

        // The record first. It carries the sidechain table, the activation
        // state and - where the block is new enough - the treasury and the
        // spent bundles, all as of this block.
        SidechainBlockData data;
        if (!psidechaintree->GetBlockData(pindex->GetBlockHash(), data)) {
            strError = strprintf("no sidechain record for block %s at height %d; "
                                 "a reindex is the only recovery from missing records",
                                 pindex->GetBlockHash().ToString(), nHeight);
            return false;
        }

        // A slot changing occupant drops the previous sidechain's deposits on
        // the connect path (UpdateActivationStatus). Applying records skips
        // that code, so the handover has to be spotted here instead: it shows
        // up as the slot holding a different sidechain than it did one block
        // ago. Captured before the record overwrites the table.
        //
        // Compared on the serialised form rather than with Sidechain::operator==,
        // which does not look at fActive and would miss a slot activating with
        // the same parameters it was proposed under.
        //
        // A limit the records cannot remove: a proposal identical in
        // every field to the sidechain already occupying the slot, activating
        // into it, changes nothing observable here while the connect path still
        // resets the slot. This pass would then keep deposits that node had
        // dropped - a longer history, not a wrong one, and the treasury pointer
        // still comes from the record either way. Distinguishing it needs the
        // block's activation commitments, which is the re-derivation this pass
        // is built to avoid. From the fork height such a proposal is not
        // tracked at all.
        const std::vector<Sidechain> vBefore = dbRebuild.GetSidechains();

        dbRebuild.ApplyLDBData(pindex->GetBlockHash(), data);

        const std::vector<Sidechain> vAfter = dbRebuild.GetSidechains();
        for (size_t n = 0; n < vAfter.size() && n < vBefore.size(); n++) {
            if (vAfter[n].fActive && vAfter[n].GetSerHash() != vBefore[n].GetSerHash())
                dbRebuild.ResetSlotDeposits((uint8_t)n);
        }

        // Nothing can be cached for a block with no active sidechain, so the
        // block itself does not need reading. This is what keeps the pass off
        // the long pre-activation span of a mature chain.
        if (dbRebuild.GetActiveSidechains().empty())
            continue;

        CBlock block;
        if (!ReadBlockFromDisk(block, pindex, consensus)) {
            strError = strprintf("could not read block %s at height %d from disk",
                                 pindex->GetBlockHash().ToString(), nHeight);
            return false;
        }
        nBlocksRead++;

        std::vector<SidechainDeposit> vDeposit;
        if (!GetBlockDeposits(block, dbRebuild, vDeposit)) {
            strError = strprintf("block %s at height %d carries a malformed deposit",
                                 pindex->GetBlockHash().ToString(), nHeight);
            return false;
        }

        // The change a paid-out bundle returns to the sidechain is cached as a
        // deposit too, so a pass that collected only deposit transactions would
        // rebuild a cache the connect path never held. The record names which
        // bundles this block spent; the transactions themselves are in the
        // block just read.
        //
        // Records written before the spent key carry nothing here, so on that
        // span this finds nothing and the rebuilt cache is short by exactly the
        // change returns of those blocks. Reported by the caller rather than
        // hidden, because it is the one way this pass knowingly falls short of
        // a reindex.
        for (const SidechainSpentWithdrawal& spent : data.vSpent) {
            if (spent.hashBlock != pindex->GetBlockHash())
                continue;

            for (size_t i = 0; i < block.vtx.size(); i++) {
                const CTransaction& tx = *(block.vtx[i]);

                uint256 hashBlind;
                if (!tx.GetBlindHash(hashBlind) || hashBlind != spent.hash)
                    continue;

                SidechainDeposit depositChange;
                if (!GetWithdrawalChangeDeposit(tx, (int)i, pindex->GetBlockHash(),
                                                spent.nSidechain, depositChange)) {
                    strError = strprintf("block %s at height %d spent bundle %s but its change "
                                         "return could not be rebuilt",
                                         pindex->GetBlockHash().ToString(), nHeight,
                                         spent.hash.ToString());
                    return false;
                }

                vDeposit.push_back(depositChange);
                nChangeReturns++;
                break;
            }
        }

        if (vDeposit.empty())
            continue;

        // The pointer is left to the record wherever the record carries one,
        // exactly as LoadDepositCache leaves it. Only on the older span, where
        // no record holds a treasury, is it derived from the cache being built.
        dbRebuild.AddDeposits(vDeposit, !dbRebuild.HasTreasuryFromRecord() /* fUpdateCTIP */);
        nDepositsFound += vDeposit.size();

        if (nHeight % 50000 == 0) {
            LogPrintf("%s: rebuilt to height %d, %d deposits so far.\n",
                    __func__, nHeight, nDepositsFound);
            uiInterface.InitMessage(strprintf(_("Rebuilding sidechain database... block %d of %d"),
                    nHeight, pindexTip->nHeight));
        }
    }

    // Everything above was rebuilt from the records and the blocks, which is
    // everything the chain describes. What the chain does not describe is the
    // state that belongs to this node alone: how its operator has told it to
    // vote, which proposals and activation acks it is carrying, the raw bundle
    // transactions it has been handed, the BMM requests its miner pulled from
    // the mempool. A fresh SidechainDB is constructed with none of that, so the
    // move below would silently delete every bit of it.
    //
    // That is not a cosmetic loss. The vote cache is what the miner writes into
    // the coinbase of every block it builds, and a fresh one reads abstain on
    // every slot: an upvote stops being cast the moment this function returns,
    // and a downvote - which is an instruction to kill a bundle, not silence
    // about it - becomes silence, with whatever default the node was
    // configured with governing from there. A bundle whose only copy of the
    // payout transaction is the withdrawal cache can no longer be paid out at
    // all. And none of this needs an operator to trigger it:
    // RepairSidechainDepositsIfNeeded calls this function from the disconnect
    // path, so an ordinary reorg deep enough to orphan a change return can
    // destroy the state mid-vote with no RPC involved.
    //
    // So the node-local members are carried into dbRebuild here, before the
    // move. Doing it on this side of the move is what keeps the "installs only
    // on success" invariant intact: every line below writes dbRebuild, and a
    // failure anywhere above has already returned without touching scdb.
    //
    // Re-running the startup loaders after the move - the obvious alternative -
    // would NOT do. The cache files are written at shutdown and at no other
    // time, so anything the operator has done since this process started
    // (setwithdrawalvote, receivewithdrawalbundle, createsidechainproposal)
    // exists only in memory, and reloading from disk would lose precisely the
    // changes that were worth keeping. One of these members is not persisted
    // anywhere at all.
    //
    // None of what is carried here is hashed by GetConsensusSections, so this
    // cannot change which blocks the node accepts. What it does change is what
    // the node PROPOSES, and that is the repair: the instruction it was acting
    // on one block ago is still the operator's instruction, and a rebuild of
    // the deposit cache was never asked to revoke it.
    const std::vector<std::string> vVote = scdb.GetVotes();
    const std::vector<Sidechain> vProposal = scdb.GetSidechainProposals();
    const std::vector<uint256> vHashAck = scdb.GetSidechainsToActivate();
    const std::vector<std::pair<uint8_t, CMutableTransaction>> vWithdrawalTx = scdb.GetWithdrawalTxCache();
    const std::vector<std::pair<uint256, SidechainFailedWithdrawal>> vFailedBlock = scdb.GetFailedWithdrawalBlocks();
    const std::set<uint256> setRemovedBMM = scdb.GetRemovedBMM();
    const std::vector<uint256> vRemovedDeposit = scdb.GetRemovedDeposits();

    // Reset() fills the vote cache with one abstain per slot, so the empty
    // vector CacheCustomVotes rejects is not a state this can be in; the guard
    // matches LoadCustomVoteCache's, which is the other caller. A rejection is
    // logged rather than failed, because a rebuild that has already succeeded
    // is worth keeping even at the price of an abstaining miner - and the
    // operator needs to be told, since nothing else would say so.
    if (!vVote.empty() && !dbRebuild.CacheCustomVotes(vVote)) {
        LogPrintf("%s: WARNING: could not carry this node's custom withdrawal votes "
                  "across the rebuild; they have reverted to the default vote.\n",
                __func__);
    }

    dbRebuild.CacheSidechainProposals(vProposal);

    for (const uint256& u : vHashAck)
        dbRebuild.CacheSidechainHashToAck(u);

    int nWithdrawalTxCarried = 0;
    for (const std::pair<uint8_t, CMutableTransaction>& p : vWithdrawalTx) {
        if (dbRebuild.CacheWithdrawalTx(CTransaction(p.second), p.first))
            nWithdrawalTxCarried++;
    }

    // The failure-to-block index, filtered exactly the way LoadWithdrawalCache
    // filters it and for exactly its reason: this index must never INTRODUCE a
    // failure. What has failed was re-established from the records above and
    // that is the authority; an entry here naming a failure those records did
    // not restore describes a state this chain no longer holds, and replaying
    // it would bar a bundle the network still allows. Matched on the slot as
    // well as the hash, because HaveFailedWithdrawal matches on both and the
    // same hash failing on two slots would otherwise attach the wrong one.
    int nFailedBlockCarried = 0;
    for (const std::pair<uint256, SidechainFailedWithdrawal>& p : vFailedBlock) {
        if (!dbRebuild.HaveFailedWithdrawal(p.second.hash, p.second.nSidechain))
            continue;

        dbRebuild.AddFailedWithdrawalBlocks(p.first, std::vector<SidechainFailedWithdrawal>{ p.second });
        nFailedBlockCarried++;
    }

    for (const uint256& txid : setRemovedBMM)
        dbRebuild.AddRemovedBMM(txid);

    for (const uint256& txid : vRemovedDeposit)
        dbRebuild.AddRemovedDeposit(txid);

    // Verify the rebuilt cache BEFORE it becomes the live database, not after.
    // The move below is irreversible in the ways that matter: it overwrites the
    // process-global scdb, and a clean shutdown then persists whatever scdb
    // holds via DumpSCDBCache (init.cpp) - so installing a rebuild that does
    // not support its own treasury and only noticing afterwards leaves the node
    // running the broken state AND writes it to disk on the next normal stop,
    // clobbering what a -reindex would otherwise rebuild from. Checking
    // dbRebuild here means a rebuild that cannot support the treasury is never
    // installed: scdb is untouched, "installed only on success" stays true, and
    // both callers (the rebuildscdb RPC and RepairSidechainDepositsIfNeeded)
    // see a plain false return and keep the state they had.
    //
    // This only refuses a genuinely unsupported pointer. A cache that is merely
    // short of some change returns but whose pointer still matches its newest
    // deposit passes DepositCacheSupportsTreasury, so the pre-spent-key record
    // span that rebuilds a correct-but-short cache still installs.
    uint8_t nSlotUnsupported = 0;
    if (!dbRebuild.DepositCacheSupportsTreasury(nSlotUnsupported)) {
        strError = strprintf(
            "rebuild completed but the treasury of sidechain %u is not supported "
            "by the rebuilt cache - its pointer may name a spent output. The node "
            "has NOT been changed. Recover with -reindex, which rebuilds every "
            "pointer from blocks, and verify getscdbhash against a known-good node.",
            nSlotUnsupported);
        LogPrintf("%s: %s\n", __func__, strError);
        return false;
    }

    // Only now, with every block behind us and the rebuild verified, does the
    // global database move.
    scdb = std::move(dbRebuild);
    mempool.UpdateCTIPFromBlock(scdb.GetCTIP(), false /* fDisconnect */);

    LogPrintf("%s: rebuilt the sidechain deposit cache to block %s (height %d) in %.2fs: "
              "%d blocks read, %d deposits, %d withdrawal change returns.\n",
            __func__, pindexTip->GetBlockHash().ToString(), pindexTip->nHeight,
            (GetTimeMillis() - nTimeStart) * 0.001,
            nBlocksRead, nDepositsFound, nChangeReturns);

    // Reported separately, and always, because it is the half of this function
    // that a reader of the log has no other way to check: the counts above come
    // from the chain and can be re-derived from it, these came from memory and
    // cannot. A line of zeroes on a node that was mid-vote is the symptom to
    // look for.
    //
    // The votes are counted rather than listed, and only the ones that say
    // something: the cache always holds one entry per slot, so its size would
    // report the same number on a node that has never voted in its life.
    int nVoteCarried = 0;
    for (const std::string& strVote : vVote) {
        if (strVote.size() != 1 || strVote.front() != SCDB_ABSTAIN)
            nVoteCarried++;
    }

    LogPrintf("%s: carried this node's own state across the rebuild: %d non-abstain vote(s), "
              "%d proposal(s), %d activation ack(s), %d cached withdrawal transaction(s), "
              "%d failure-to-block entries, %d removed BMM request(s), %d removed deposit(s).\n",
            __func__, nVoteCarried, (int)vProposal.size(), (int)vHashAck.size(),
            nWithdrawalTxCarried, nFailedBlockCarried, (int)setRemovedBMM.size(),
            (int)vRemovedDeposit.size());

    return true;
}

void DumpDepositCache()
{
    std::vector<SidechainDeposit> vDeposit;
    std::vector<Sidechain> vSidechain = scdb.GetActiveSidechains();
    for (const Sidechain& s : vSidechain) {
        std::vector<SidechainDeposit> vSidechainDeposit = scdb.GetDeposits(s.nSidechain);
        vDeposit.insert(std::end(vDeposit), std::begin(vSidechainDeposit), std::end(vSidechainDeposit));
    }

    // Only persist the cache once startup has established that the in-memory
    // sidechain state is authoritative. Startup can abort before the deposit
    // cache is loaded -- a failed SCDB resync calls scdb.Reset() and breaks out
    // before LoadDepositCache() -- and writing the still-empty cache on the way
    // out would destroy a good deposit.dat, turning a recoverable restart into a
    // mandatory reindex. Gating on load completion rather than on emptiness is
    // what lets a cache that has legitimately become empty (a sidechain slot
    // being replaced, or a deep reorg) still be written out correctly.
    if (!fSCDBStateLoaded) {
        LogPrintf("%s: Sidechain state was not fully loaded; not overwriting deposit.dat.\n", __func__);
        return;
    }


    // Write the deposits
    fs::path path = GetDataDir() / "skydoge" / "deposit.dat.new";
    CAutoFile fileout(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return;
    }

    int count = vDeposit.size();
    try {
        fileout << SCDB_DEPOSIT_DUMP_VERSION; // version required to read

        // Stamp the block this cache corresponds to, so the next startup can
        // tell whether it still describes the chain. The sidechain database's
        // own last-seen block is the right stamp rather than the chain tip:
        // the deposits are added by ConnectBlock, which advances both together,
        // so it is the height these deposits actually reflect.
        fileout << scdb.GetHashBlockLastSeen();

        fileout << count; // Number of deposits in file

        for (const SidechainDeposit& d : vDeposit) {
            fileout << d;
        }
    }
    catch (const std::exception& e) {
        LogPrintf("%s: Exception: %s\n", __func__, e.what());
        return;
    }

    if (!FileCommit(fileout.Get())) {
        // The replacement never reached the disk. Renaming it over the previous
        // file would trade a good copy for a truncated one, so keep what is
        // there; the .new file is overwritten on the next attempt.
        LogPrintf("%s: Failed to write the cache file; keeping the previous copy.\n", __func__);
        return;
    }
    fileout.fclose();
    if (!RenameOver(GetDataDir() / "skydoge" / "deposit.dat.new",
                    GetDataDir() /  "skydoge" / "deposit.dat")) {
        LogPrintf("%s: Failed to replace the previous file; the cache was not saved.\n", __func__);
        return;
    }

    LogPrintf("%s: Wrote %u\n", __func__, count);
}

namespace {
/** 0.45.2: a raw withdrawal bundle read from withdrawal.dat ahead of a chain
 *  replay, held back until the replay has finished. */
struct ReplayedWithdrawalBundle {
    uint8_t nSidechain;
    CTransactionRef tx;
    //! The slot's occupant (Sidechain::GetSerHash) when the file was written;
    //! null when the file does not say (written before 0.45.2).
    uint256 hashOccupant;
};
CCriticalSection cs_withdrawal_replay;
std::vector<ReplayedWithdrawalBundle> g_vWithdrawalAfterReplay GUARDED_BY(cs_withdrawal_replay);
} // namespace

bool LoadWithdrawalCache(bool fReindex, bool fHoldBundles)
{
    fs::path path = GetDataDir() / "skydoge" / "withdrawal.dat";
    CAutoFile filein(fsbridge::fopen(path, "rb"), SER_DISK, CLIENT_VERSION);
    if (filein.IsNull()) {
        // A file that is there but will not open is not the same as no file
        // at all. Reporting "nothing to load" would let startup finish with an
        // empty cache and shutdown write that emptiness over data nothing can
        // rebuild, so say the load failed and leave the file alone.
        if (fs::exists(path))
            return error("%s: %s exists but could not be opened", __func__, path.string());
        return true;
    }

    std::vector<std::pair<uint8_t, CTransactionRef>> vWithdrawal;
    std::vector<SidechainSpentWithdrawal> vSpent;
    std::vector<SidechainFailedWithdrawal> vFailed;
    std::vector<std::pair<uint256, SidechainFailedWithdrawal>> vFailedBlock;
    // (slot, bundle hash) -> the slot's occupant when the file was written.
    std::map<std::pair<uint8_t, uint256>, uint256> mapOccupant;
    try {
        uint64_t nVersion;
        filein >> nVersion;
        if (nVersion != SCDB_DUMP_VERSION) {
            return false;
        }

        int nWT = 0;
        filein >> nWT;
        for (int i = 0; i < nWT; i++) {
            uint8_t nSidechain = 0;
            filein >> nSidechain;
            CTransactionRef tx;
            filein >> tx;
            vWithdrawal.push_back(std::make_pair(nSidechain, tx));
        }

        if (!fReindex) {
            int nSpent = 0;
            filein >> nSpent;
            for (int i = 0; i < nSpent; i++) {
                SidechainSpentWithdrawal spent;
                filein >> spent;
                vSpent.push_back(spent);
            }

            int nFailed = 0;
            filein >> nFailed;
            for (int i = 0; i < nFailed; i++) {
                SidechainFailedWithdrawal failed;
                filein >> failed;
                vFailed.push_back(failed);
            }

            // Which block recorded each failure. This section was added after
            // the format was first written and the version is shared with every
            // other cache file, so a file that ends here is not an error - it
            // was written by an older build. Read it separately and treat a
            // short file as "no block is known for these failures", which is
            // what the node assumed before the section existed.
            bool fFailedBlockRead = false;
            try {
                int nFailedBlock = 0;
                filein >> nFailedBlock;
                for (int i = 0; i < nFailedBlock; i++) {
                    uint256 hashBlock;
                    SidechainFailedWithdrawal failed;
                    filein >> hashBlock;
                    filein >> failed;
                    vFailedBlock.push_back(std::make_pair(hashBlock, failed));
                }
                fFailedBlockRead = true;
            }
            catch (const std::exception&) {
                vFailedBlock.clear();
                LogPrintf("%s: No failure-to-block index in the file; a reorg "
                          "across a failure recorded before this start cannot "
                          "be undone.\n", __func__);
            }
            // 0.45.2: the bundle-occupant section, read only when the bundles
            // are held back (blocks still to connect, see init.cpp).
            if (fHoldBundles && fFailedBlockRead) {
                try {
                    int nOccupant = 0;
                    filein >> nOccupant;
                    for (int i = 0; i < nOccupant; i++) {
                        uint8_t nSidechain = 0;
                        uint256 hashBundle, hashOccupant;
                        filein >> nSidechain;
                        filein >> hashBundle;
                        filein >> hashOccupant;
                        mapOccupant[std::make_pair(nSidechain, hashBundle)] = hashOccupant;
                    }
                }
                catch (const std::exception&) {
                    mapOccupant.clear();
                }
            }
        } else {
            // 0.45.2: ahead of a replay only the bundles and, at the end of
            // the file, the occupant each slot had when it was written are
            // used. The sections in between are read past, not installed (see
            // the comment on the install below). A file that ends early was
            // written before 0.45.2 and states no occupant; nothing else
            // depends on these reads, so a short or odd tail only means that.
            try {
                int nSpent = 0;
                filein >> nSpent;
                for (int i = 0; i < nSpent; i++) {
                    SidechainSpentWithdrawal spent;
                    filein >> spent;
                }
                int nFailed = 0;
                filein >> nFailed;
                for (int i = 0; i < nFailed; i++) {
                    SidechainFailedWithdrawal failed;
                    filein >> failed;
                }
                int nFailedBlock = 0;
                filein >> nFailedBlock;
                for (int i = 0; i < nFailedBlock; i++) {
                    uint256 hashBlock;
                    SidechainFailedWithdrawal failed;
                    filein >> hashBlock;
                    filein >> failed;
                }
                int nOccupant = 0;
                filein >> nOccupant;
                for (int i = 0; i < nOccupant; i++) {
                    uint8_t nSidechain = 0;
                    uint256 hashBundle, hashOccupant;
                    filein >> nSidechain;
                    filein >> hashBundle;
                    filein >> hashOccupant;
                    mapOccupant[std::make_pair(nSidechain, hashBundle)] = hashOccupant;
                }
            }
            catch (const std::exception&) {
                mapOccupant.clear();
                LogPrintf("%s: The file states no sidechain occupant for its bundles "
                          "(written before 0.45.2).\n", __func__);
            }
        }
    }
    catch (const std::exception& e) {
        LogPrintf("%s: Exception: %s\n", __func__, e.what());
        return false;
    }

    // Add to SCDB

    if (fHoldBundles) {
        // Blocks are about to be
        // connected (a replay from genesis, or the rest of one that was
        // interrupted), and every sidechain activation the replay
        // connects drops the cached bundles of that slot - the previous-
        // occupant guard in UpdateActivationStatus, which is right for a live
        // activation and wrong here, where the slot is being handed back to
        // the very sidechain the bundles were cached for. Installed now, a
        // full -reindex lost every cached bundle (measured in testing).
        // So they are held back and installed once the
        // replay has finished (InstallReplayedWithdrawalCache), against the
        // replayed chain's own state. The guard itself is unchanged.
        LOCK(cs_withdrawal_replay);
        for (const std::pair<uint8_t, CTransactionRef>& pair : vWithdrawal) {
            const uint256 hash = pair.second->GetHash();
            bool fHeld = false;
            for (const ReplayedWithdrawalBundle& b : g_vWithdrawalAfterReplay) {
                if (b.nSidechain == pair.first && b.tx->GetHash() == hash) {
                    fHeld = true;
                    break;
                }
            }
            if (fHeld)
                continue;
            ReplayedWithdrawalBundle b;
            b.nSidechain = pair.first;
            b.tx = pair.second;
            const auto it = mapOccupant.find(std::make_pair(pair.first, hash));
            if (it != mapOccupant.end())
                b.hashOccupant = it->second;
            g_vWithdrawalAfterReplay.push_back(b);
        }
        if (!vWithdrawal.empty()) {
            LogPrintf("%s: Holding %u cached withdrawal bundle(s) until the chain replay has finished.\n",
                      __func__, (unsigned)vWithdrawal.size());
        }
        return true;
    }

    for (const std::pair<uint8_t, CTransactionRef>& pair : vWithdrawal) {
        if (!scdb.CacheWithdrawalTx(*pair.second.get(), pair.first))
            return false;
    }

    if (!fReindex) {
        // The spent and failed sets are installed only where this file is still
        // the node's best copy of them.
        //
        // ApplyLDBData does not merge those two maps, it clears them and
        // reinstalls them from the per-block record, and the record states the
        // whole set as of its own block rather than that block's additions -
        // ConnectBlock writes vSpent and vFailed from the entire cache. So once
        // ResyncSCDB has brought the database to the tip, the record is the
        // complete and authoritative answer, and this file - written once at
        // shutdown, with no block stamp and no staleness check of its own - can
        // only disagree with it, never improve on it.
        //
        // Disagreement is not hypothetical. A node that recorded a spend or a
        // failure on a branch it has since abandoned still holds that entry in
        // the file, while the surviving tip's record correctly does not state
        // it. The de-dup inside AddSpentWithdrawals makes an entry held by both
        // a no-op, but an entry held only by the file is precisely what it
        // cannot see, and re-adding one is not untidy: GetConsensusSections
        // hashes both maps, so the node reports a state no correctly-built node
        // can report, and HaveSpentWithdrawal / HaveFailedWithdrawal gate
        // AddWithdrawal, so a re-injected failure bars a bundle from ever being
        // proposed again on the chain the node is actually on. Nothing corrects
        // it later either: the file is re-read at every startup, and the maps
        // are hashed, not derived, so no amount of further syncing removes what
        // was put in.
        //
        // This is the reasoning that gave LoadDepositCache its fUpdateCTIP=false
        // path, applied to the other half of the same shutdown snapshot.
        //
        // The two keys are asked separately because they promise different
        // things. A record written under the treasury key reinstalls the failed
        // map, and serialises vSpent as the empty vector that nothing ever
        // filled; only the spent key says that field was written. A node whose
        // tip record predates either key still gets that map from this file, as
        // it always did - which is what stops an upgrade from an older build
        // coming back able to re-admit a bundle it has already paid out.
        //
        // Both counts are logged where the file is skipped, because a node that
        // has drifted is otherwise invisible: nothing about a stale file is
        // reported today, and the two numbers disagreeing is the cheapest
        // evidence an operator can be given that this node was carrying entries
        // its own chain does not state. Comparing the sets entry by entry would
        // be a better signal, but it is quadratic in containers that nothing
        // bounds from above, and this runs at startup.
        if (!scdb.HasSpentFromRecord()) {
            scdb.AddSpentWithdrawals(vSpent);
        } else if (!vSpent.empty()) {
            LogPrintf("%s: The block record states %u spent withdrawal(s); the %u in the file "
                      "were not installed.\n", __func__,
                    (unsigned)scdb.GetSpentWithdrawalCache().size(), (unsigned)vSpent.size());
        }

        if (!scdb.HasTreasuryFromRecord()) {
            scdb.AddFailedWithdrawals(vFailed);
        } else if (!vFailed.empty()) {
            LogPrintf("%s: The block record states %u failed withdrawal(s); the %u in the file "
                      "were not installed.\n", __func__,
                    (unsigned)scdb.GetFailedWithdrawalCache().size(), (unsigned)vFailed.size());
        }

        // Re-attach each failure to the block that recorded it. Failures with
        // no block in the index stay as plain records: they cannot be undone by
        // a disconnect, which is how every build before this one behaved.
        //
        // Reading this file must never introduce a failure, nor move one to a
        // different sidechain. The failed map holds one record per hash; this
        // section is written from an index that holds every failure per block,
        // and it arrives sorted by block hash, which is not chain order.
        // Replaying it into mapFailedWithdrawal could therefore install a slot
        // that was not the one in force, and since HaveFailedWithdrawal matches
        // on the slot, that would make this node reject a block the network
        // accepts. So the block is attached only to a failure the map already
        // holds, and only for the same slot. That guard is also what keeps this
        // section honest now that the section above may have installed nothing:
        // where the record supplied the failures, only the record's failures can
        // be given a block, and a file entry the record does not state is
        // skipped here as well.
        for (const std::pair<uint256, SidechainFailedWithdrawal>& p : vFailedBlock) {
            if (!scdb.HaveFailedWithdrawal(p.second.hash, p.second.nSidechain))
                continue;
            scdb.AddFailedWithdrawalBlocks(p.first, std::vector<SidechainFailedWithdrawal>{ p.second });
        }
    }

    return true;
}

void InstallReplayedWithdrawalCache()
{
    LOCK2(cs_main, cs_withdrawal_replay);
    if (g_vWithdrawalAfterReplay.empty())
        return;

    // Which held-back bundles the connected chain can still use:
    //  - one whose slot is not active is kept HELD, not installed and not
    //    dropped: the chain this start reached does not show that slot (a
    //    node restarted after a reindex was killed can come back at a low
    //    height), so nothing here can judge it; it is written back to
    //    withdrawal.dat as it was read and judged on a later start;
    //  - a bundle paid out or failed on this chain is dropped (the live paths
    //    drop a bundle's raw bytes at both);
    //  - where the file names the slot's occupant, it must still be the same
    //    sidechain - the previous-occupant guard's rule, applied to the
    //    occupant at the end instead of to every activation on the way;
    //  - where it does not (a file written before 0.45.2), only a bundle the
    //    chain still tracks for that slot is kept. A bundle it does not track
    //    cannot be paid out without being proposed again.
    std::vector<ReplayedWithdrawalBundle> vStillHeld;
    unsigned int nKept = 0, nDropped = 0;
    for (const ReplayedWithdrawalBundle& b : g_vWithdrawalAfterReplay) {
        const uint256 hash = b.tx->GetHash();
        Sidechain sidechain;
        std::string strDrop;
        if (!scdb.GetSidechain(b.nSidechain, sidechain)) {
            vStillHeld.push_back(b);
            continue;
        } else if (scdb.HaveSpentWithdrawal(hash, b.nSidechain) || scdb.HaveFailedWithdrawal(hash, b.nSidechain)) {
            strDrop = "it was paid out or failed on this chain";
        } else if (!b.hashOccupant.IsNull()) {
            if (sidechain.GetSerHash() != b.hashOccupant)
                strDrop = "the slot holds a different sidechain now";
        } else if (!scdb.HaveWorkScore(hash, b.nSidechain)) {
            strDrop = "the file names no occupant and the chain does not track the bundle";
        }
        if (!strDrop.empty()) {
            LogPrintf("%s: Dropping cached withdrawal bundle %s (slot %u): %s.\n",
                      __func__, hash.ToString(), (unsigned)b.nSidechain, strDrop);
            nDropped++;
            continue;
        }
        if (!scdb.HaveWithdrawalTxCachedForSlot(b.nSidechain, hash))
            scdb.CacheWithdrawalTx(*b.tx, b.nSidechain);
        nKept++;
    }
    LogPrintf("%s: Chain replay finished: kept %u, dropped %u, still held for an inactive slot %u of %u cached withdrawal bundle(s).\n",
              __func__, nKept, nDropped, (unsigned)vStillHeld.size(), (unsigned)g_vWithdrawalAfterReplay.size());
    g_vWithdrawalAfterReplay.swap(vStillHeld);
}

void DumpWithdrawalCache()
{
    std::vector<std::pair<uint8_t, CMutableTransaction>> vWithdrawal = scdb.GetWithdrawalTxCache();
    std::vector<SidechainSpentWithdrawal> vSpent = scdb.GetSpentWithdrawalCache();
    std::vector<SidechainFailedWithdrawal> vFailed = scdb.GetFailedWithdrawalCache();
    std::vector<std::pair<uint256, SidechainFailedWithdrawal>> vFailedBlock = scdb.GetFailedWithdrawalBlocks();

    // 0.45.2: the occupant of each bundle's slot (Sidechain::GetSerHash),
    // read back only ahead of a chain replay (LoadWithdrawalCache). A bundle
    // still held back from an unfinished replay is written as it was read, so
    // stopping the node mid-replay loses nothing.
    std::vector<std::pair<std::pair<uint8_t, uint256>, uint256>> vOccupant;
    for (const std::pair<uint8_t, CMutableTransaction>& pair : vWithdrawal) {
        Sidechain sidechain;
        uint256 hashOccupant;
        if (scdb.GetSidechain(pair.first, sidechain))
            hashOccupant = sidechain.GetSerHash();
        vOccupant.push_back(std::make_pair(std::make_pair(pair.first, pair.second.GetHash()), hashOccupant));
    }
    {
        LOCK(cs_withdrawal_replay);
        for (const ReplayedWithdrawalBundle& b : g_vWithdrawalAfterReplay) {
            const std::pair<uint8_t, uint256> key = std::make_pair(b.nSidechain, b.tx->GetHash());
            bool fListed = false;
            for (const auto& o : vOccupant) {
                if (o.first == key) {
                    fListed = true;
                    break;
                }
            }
            if (fListed)
                continue;
            vWithdrawal.push_back(std::make_pair(b.nSidechain, CMutableTransaction(*b.tx)));
            vOccupant.push_back(std::make_pair(key, b.hashOccupant));
        }
    }

    int nWithdrawal = vWithdrawal.size();
    int nSpent = vSpent.size();
    int nFailed = vFailed.size();

    // Write the Withdrawal raw tx cache & spent Withdrawal cache
    fs::path path = GetDataDir() / "skydoge" / "withdrawal.dat.new";
    CAutoFile fileout(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return;
    }

    try {
        fileout << SCDB_DUMP_VERSION; // version required to read

        fileout << nWithdrawal; // Number of Withdrawal(s) in file
        for (const std::pair<uint8_t, CMutableTransaction>& pair : vWithdrawal) {
            fileout << pair.first;
            fileout << MakeTransactionRef(pair.second);
        }

        fileout << nSpent; // Number of spent Withdrawal(s) in file
        for (const SidechainSpentWithdrawal& s : vSpent) {
            fileout << s;
        }

        fileout << nFailed; // Number of failed Withdrawal(s) in file
        for (const SidechainFailedWithdrawal& f : vFailed) {
            fileout << f;
        }

        // Which block recorded each failure, so that a reorg after a restart
        // can still take the failure back out. Appended after everything the
        // previous format wrote, and read back inside its own try block, so
        // that SCDB_DUMP_VERSION does not have to change: that constant is
        // shared by every cache file, and bumping it would make this release
        // reject the operator's proposals, votes and acknowledgements on first
        // start. An older build simply stops reading before this point.
        fileout << (int)vFailedBlock.size();
        for (const std::pair<uint256, SidechainFailedWithdrawal>& p : vFailedBlock) {
            fileout << p.first;
            fileout << p.second;
        }

        // 0.45.2: (slot, bundle hash, slot occupant) per cached bundle,
        // appended after everything earlier builds write, for the same reason
        // as the section above; an earlier build stops reading before it.
        fileout << (int)vOccupant.size();
        for (const auto& o : vOccupant) {
            fileout << o.first.first;
            fileout << o.first.second;
            fileout << o.second;
        }
    }
    catch (const std::exception& e) {
        LogPrintf("%s: Exception: %s\n", __func__, e.what());
        return;
    }

    if (!FileCommit(fileout.Get())) {
        // The replacement never reached the disk. Renaming it over the previous
        // file would trade a good copy for a truncated one, so keep what is
        // there; the .new file is overwritten on the next attempt.
        LogPrintf("%s: Failed to write the cache file; keeping the previous copy.\n", __func__);
        return;
    }
    fileout.fclose();
    if (!RenameOver(GetDataDir() / "skydoge" / "withdrawal.dat.new",
                    GetDataDir() /  "skydoge" / "withdrawal.dat")) {
        LogPrintf("%s: Failed to replace the previous file; the cache was not saved.\n", __func__);
        return;
    }

    LogPrintf("%s: Wrote %u Withdrawal, %u spent, %u failed\n", __func__, nWithdrawal, nSpent, nFailed);
}

bool LoadBMMCache()
{
    fs::path path = GetDataDir() / "skydoge" / "bmm.dat";
    std::vector<CDataStream> vCandidate;
    // A file that is there but will not open is not the same as no file at all.
    // Reporting "nothing to load" would let startup finish with an empty cache
    // and shutdown write that emptiness over data nothing can rebuild, so say
    // the load failed and leave the file alone.
    const CacheRead read = ReadCacheFileCandidates(path, vCandidate);
    if (read == CacheRead::MISSING)
        return true;
    if (read == CacheRead::UNOPENABLE)
        return error("%s: %s exists but could not be opened", __func__, path.string());

    std::set<uint256> setRemovedBMM;
    bool fParsed = false;
    bool fRecovered = false;
    for (size_t c = 0; c < vCandidate.size(); c++) {
        setRemovedBMM.clear();
        CDataStream& filein = vCandidate[c];
        try {
            uint64_t nVersion;
            filein >> nVersion;
            if (nVersion != SCDB_DUMP_VERSION)
                continue;

            int count = 0;
            filein >> count;
            for (int i = 0; i < count; i++) {
                uint256 txid;
                filein >> txid;
                setRemovedBMM.insert(txid);
            }
        }
        catch (const std::exception& e) {
            LogPrintf("%s: Exception: %s\n", __func__, e.what());
            continue;
        }
        // A parse that "succeeds" while leaving bytes behind is the
        // signature of the text-mode corruption: the extra 0x0D bytes shift
        // everything along, the reads still find enough data, and the loader
        // returns garbage without ever throwing. Insist the whole stream was
        // consumed before believing a candidate.
        if (!filein.empty())
            continue;
        fParsed = true;
        fRecovered = (c > 0);
        break;
    }
    if (!fParsed)
        return false;
    if (fRecovered)
        LogPrintf("%s: %s was written in text mode by an older build; recovered it. "
                  "It is rewritten in binary at the next clean shutdown.\n", __func__, path.string());

    // TODO add a function to take in the whole set
    for (const uint256& u : setRemovedBMM)
        scdb.AddRemovedBMM(u);

    return true;
}

void DumpBMMCache()
{
    std::set<uint256> setRemovedBMM = scdb.GetRemovedBMM();

    int count = setRemovedBMM.size();

    // Write the sidechain activation status cache
    fs::path path = GetDataDir() / "skydoge" / "bmm.dat.new";
    CAutoFile fileout(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return;
    }

    try {
        fileout << SCDB_DUMP_VERSION; // version required to read
        fileout << count; // Number of txid in file

        for (const uint256& u : setRemovedBMM) {
            fileout << u;
        }
    }
    catch (const std::exception& e) {
        // Serialisation stopped part way, so the replacement is incomplete.
        LogPrintf("%s: Exception: %s\n", __func__, e.what());
        return;
    }

    if (!FileCommit(fileout.Get())) {
        // The replacement never reached the disk. Renaming it over the previous
        // file would trade a good copy for a truncated one, so keep what is
        // there; the .new file is overwritten on the next attempt.
        LogPrintf("%s: Failed to write the cache file; keeping the previous copy.\n", __func__);
        return;
    }
    fileout.fclose();
    if (!RenameOver(GetDataDir() / "skydoge" / "bmm.dat.new",
                    GetDataDir() /  "skydoge" / "bmm.dat")) {
        LogPrintf("%s: Failed to replace the previous file; the cache was not saved.\n", __func__);
        return;
    }

    LogPrintf("%s: Wrote %u\n", __func__, count);
}

bool LoadSidechainProposalCache()
{
    fs::path path = GetDataDir() / "skydoge" / "sidechainproposals.dat";
    std::vector<CDataStream> vCandidate;
    // A file that is there but will not open is not the same as no file at all.
    // Reporting "nothing to load" would let startup finish with an empty cache
    // and shutdown write that emptiness over data nothing can rebuild, so say
    // the load failed and leave the file alone.
    const CacheRead read = ReadCacheFileCandidates(path, vCandidate);
    if (read == CacheRead::MISSING)
        return true;
    if (read == CacheRead::UNOPENABLE)
        return error("%s: %s exists but could not be opened", __func__, path.string());

    std::vector<Sidechain> vProposal;
    bool fParsed = false;
    bool fRecovered = false;
    for (size_t c = 0; c < vCandidate.size(); c++) {
        vProposal.clear();
        CDataStream& filein = vCandidate[c];
        try {
            uint64_t nVersion;
            filein >> nVersion;
            if (nVersion != SCDB_DUMP_VERSION)
                continue;

            int count = 0;
            filein >> count;
            for (int i = 0; i < count; i++) {
                Sidechain proposal;
                filein >> proposal;
                vProposal.push_back(proposal);
            }
        }
        catch (const std::exception& e) {
            LogPrintf("%s: Exception: %s\n", __func__, e.what());
            continue;
        }
        // A parse that "succeeds" while leaving bytes behind is the
        // signature of the text-mode corruption: the extra 0x0D bytes shift
        // everything along, the reads still find enough data, and the loader
        // returns garbage without ever throwing. Insist the whole stream was
        // consumed before believing a candidate.
        if (!filein.empty())
            continue;
        fParsed = true;
        fRecovered = (c > 0);
        break;
    }
    if (!fParsed)
        return false;
    if (fRecovered)
        LogPrintf("%s: %s was written in text mode by an older build; recovered it. "
                  "It is rewritten in binary at the next clean shutdown.\n", __func__, path.string());

    // Add to SCDB
    scdb.CacheSidechainProposals(vProposal);

    return true;
}

void DumpSidechainProposalCache()
{
    std::vector<Sidechain> vProposal = scdb.GetSidechainProposals();

    int count = vProposal.size();

    // Write the sidechain proposal cache
    fs::path path = GetDataDir() / "skydoge" / "sidechainproposals.dat.new";
    CAutoFile fileout(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return;
    }

    try {
        fileout << SCDB_DUMP_VERSION; // version required to read
        fileout << count; // Number of proposals in file

        for (const Sidechain& s : vProposal) {
            fileout << s;
        }
    }
    catch (const std::exception& e) {
        // Serialisation stopped part way, so the replacement is incomplete.
        LogPrintf("%s: Exception: %s\n", __func__, e.what());
        return;
    }

    if (!FileCommit(fileout.Get())) {
        // The replacement never reached the disk. Renaming it over the previous
        // file would trade a good copy for a truncated one, so keep what is
        // there; the .new file is overwritten on the next attempt.
        LogPrintf("%s: Failed to write the cache file; keeping the previous copy.\n", __func__);
        return;
    }
    fileout.fclose();
    if (!RenameOver(GetDataDir() / "skydoge" / "sidechainproposals.dat.new",
                    GetDataDir() /  "skydoge" / "sidechainproposals.dat")) {
        LogPrintf("%s: Failed to replace the previous file; the cache was not saved.\n", __func__);
        return;
    }

    LogPrintf("%s: Wrote %u\n", __func__, count);
}

bool LoadSidechainActivationHashCache()
{
    fs::path path = GetDataDir() / "skydoge" / "sidechainhashactivate.dat";
    std::vector<CDataStream> vCandidate;
    // A file that is there but will not open is not the same as no file at all.
    // Reporting "nothing to load" would let startup finish with an empty cache
    // and shutdown write that emptiness over data nothing can rebuild, so say
    // the load failed and leave the file alone.
    const CacheRead read = ReadCacheFileCandidates(path, vCandidate);
    if (read == CacheRead::MISSING)
        return true;
    if (read == CacheRead::UNOPENABLE)
        return error("%s: %s exists but could not be opened", __func__, path.string());

    std::vector<uint256> vHash;
    bool fParsed = false;
    bool fRecovered = false;
    for (size_t c = 0; c < vCandidate.size(); c++) {
        vHash.clear();
        CDataStream& filein = vCandidate[c];
        try {
            uint64_t nVersion;
            filein >> nVersion;
            if (nVersion != SCDB_DUMP_VERSION)
                continue;

            int count = 0;
            filein >> count;
            for (int i = 0; i < count; i++) {
                uint256 hash;
                filein >> hash;
                vHash.push_back(hash);
            }
        }
        catch (const std::exception& e) {
            LogPrintf("%s: Exception: %s\n", __func__, e.what());
            continue;
        }
        // A parse that "succeeds" while leaving bytes behind is the
        // signature of the text-mode corruption: the extra 0x0D bytes shift
        // everything along, the reads still find enough data, and the loader
        // returns garbage without ever throwing. Insist the whole stream was
        // consumed before believing a candidate.
        if (!filein.empty())
            continue;
        fParsed = true;
        fRecovered = (c > 0);
        break;
    }
    if (!fParsed)
        return false;
    if (fRecovered)
        LogPrintf("%s: %s was written in text mode by an older build; recovered it. "
                  "It is rewritten in binary at the next clean shutdown.\n", __func__, path.string());

    // Add to SCDB
    for (const uint256& u : vHash)
        scdb.CacheSidechainHashToAck(u);

    return true;
}

void DumpSidechainActivationHashCache()
{
    std::vector<uint256> vHash = scdb.GetSidechainsToActivate();

    int count = vHash.size();

    // Write the sidechain activation hash cache
    fs::path path = GetDataDir() / "skydoge" / "sidechainhashactivate.dat.new";
    CAutoFile fileout(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return;
    }

    try {
        fileout << SCDB_DUMP_VERSION; // version required to read
        fileout << count; // Number of hashes in file

        for (const uint256& u : vHash) {
            fileout << u;
        }
    }
    catch (const std::exception& e) {
        // Serialisation stopped part way, so the replacement is incomplete.
        LogPrintf("%s: Exception: %s\n", __func__, e.what());
        return;
    }

    if (!FileCommit(fileout.Get())) {
        // The replacement never reached the disk. Renaming it over the previous
        // file would trade a good copy for a truncated one, so keep what is
        // there; the .new file is overwritten on the next attempt.
        LogPrintf("%s: Failed to write the cache file; keeping the previous copy.\n", __func__);
        return;
    }
    fileout.fclose();
    if (!RenameOver(GetDataDir() / "skydoge" / "sidechainhashactivate.dat.new",
                    GetDataDir() /  "skydoge" / "sidechainhashactivate.dat")) {
        LogPrintf("%s: Failed to replace the previous file; the cache was not saved.\n", __func__);
        return;
    }

    LogPrintf("%s: Wrote %u\n", __func__, count);
}

//! Guess how far we are in the verification process at the given block index
double GuessVerificationProgress(const ChainTxData& data, const CBlockIndex *pindex) {
    if (pindex == nullptr)
        return 0.0;

    int64_t nNow = time(nullptr);

    double fTxTotal;

    if (pindex->nChainTx <= data.nTxCount) {
        fTxTotal = data.nTxCount + (nNow - data.nTime) * data.dTxRate;
    } else {
        fTxTotal = pindex->nChainTx + (nNow - pindex->GetBlockTime()) * data.dTxRate;
    }

    // The estimate extrapolates from a snapshot taken at build time, so a local
    // clock behind that snapshot makes the projected total shrink -- far enough
    // behind and it reaches zero or goes negative, which would otherwise be
    // reported as an infinite, NaN or negative progress. Keep the result a
    // sane fraction whatever the clock says; the chain data itself is fine.
    if (!(fTxTotal > 0))
        return 0.0;

    const double fProgress = pindex->nChainTx / fTxTotal;
    if (fProgress < 0.0)
        return 0.0;
    if (fProgress > 1.0)
        return 1.0;

    return fProgress;
}

bool GetTxOutProof(const uint256& txid, const uint256& hashBlock, std::string& strProof)
{
    LOCK(cs_main);

    CBlockIndex* pblockindex = NULL;

    if (!mapBlockIndex.count(hashBlock))
        return false;
    pblockindex = mapBlockIndex[hashBlock];

    CBlock block;
    if(!ReadBlockFromDisk(block, pblockindex, Params().GetConsensus()))
        return false;

    bool fTxFound = false;
    for (const auto& tx : block.vtx)
        if (tx->GetHash() == txid)
            fTxFound = true;

    if (!fTxFound)
        return false;

    std::set<uint256> setTxids;
    setTxids.insert(txid);

    CDataStream ssMB(SER_NETWORK, PROTOCOL_VERSION);
    CMerkleBlock mb(block, setTxids);
    ssMB << mb;
    strProof = HexStr(ssMB.begin(), ssMB.end());

    return true;
}

bool VerifyTxOutProof(const std::string& strProof)
{
    CDataStream ssMB(ParseHex(strProof), SER_NETWORK, PROTOCOL_VERSION);
    CMerkleBlock merkleBlock;
    ssMB >> merkleBlock;

    std::vector<uint256> vMatch;
    std::vector<unsigned int> vIndex;
    if (merkleBlock.txn.ExtractMatches(vMatch, vIndex) != merkleBlock.header.hashMerkleRoot)
        return false;

    LOCK(cs_main);

    if (!mapBlockIndex.count(merkleBlock.header.GetHash()) || !chainActive.Contains(mapBlockIndex[merkleBlock.header.GetHash()]))
        return false;

    return true;
}

void DumpSCDBCache()
{
    // TODO make configurable

    // Every one of these files describes state the caches only hold once startup
    // has loaded them. Shutdown runs on the failure paths too - a startup that
    // stops at a load error, or at a prompt the user declines, still reaches
    // here - and writing then would put default-constructed caches over the
    // user's votes, proposals, acknowledgements and withdrawal bundles, none of
    // which exist in any block. Write nothing rather than write emptiness.
    if (!fSCDBStateLoaded) {
        LogPrintf("%s: Sidechain state was not fully loaded; leaving the cache files alone.\n", __func__);
        return;
    }

    // Create ~/.skydoge/skydoge
    TryCreateDirectories(GetDataDir() / "skydoge");

    // Dump SidechainDB, sidechain activation & optional caches
    DumpDepositCache();
    DumpCustomVoteCache();
    DumpWithdrawalCache();
    DumpSidechainProposalCache();
    DumpSidechainActivationHashCache();
    DumpBMMCache();
}

//! Load the per-block sidechain record for pindex into the given database.
//!
//! Rebuild the failed and spent sets for pindex from the record chain.
//!
//! Only needed when pindex's own record is a DELTA: a cumulative record states
//! both sets in full and ApplyLDBData installs them directly, exactly as before
//! this existed.
//!
//! Walks back to the nearest ANCHOR (any cumulative-key record) collecting
//! records, then applies them ASCENDING BY HEIGHT - anchor first, deltas
//! oldest to newest.
//!
//! THE ORDER IS LOAD-BEARING AND THIS IS NOT A SET UNION. mapFailedWithdrawal
//! is keyed by withdrawal hash ALONE and installing is last-write-wins, while
//! HaveFailedWithdrawal matches on (hash, nSidechain). Apply the deltas
//! newest-first and a blind hash that failed on two slots ends up recorded
//! against the wrong one - after which AddWithdrawal, which is consensus and
//! sits behind NO flag-day height, accepts or rejects differently from a node
//! that connected the same blocks in order. The union is NOT commutative
//! here, which is why the order matters.
//!
//! A missing record mid-walk is fatal and says so: continuing would silently
//! produce a short set, which is indistinguishable from a legitimately short
//! one and re-admits bundles the chain has already failed.
static bool RestoreFailedSpentFromRecords(SidechainDB& db, const CBlockIndex* pindex)
{
    AssertLockHeld(cs_main);

    if (!psidechaintree)
        return false;

    const uint256 hashGenesis = Params().GetConsensus().hashGenesisBlock;

    // Newest first while walking; reversed before applying.
    std::vector<SidechainBlockData> vChain;
    bool fFoundAnchor = false;
    for (const CBlockIndex* p = pindex; p; p = p->pprev) {
        if (p->GetBlockHash() == hashGenesis)
            break;

        SidechainBlockData rec;
        if (!psidechaintree->GetBlockData(p->GetBlockHash(), rec)) {
            LogPrintf("%s: cannot rebuild failed/spent sets - record missing for %s "
                      "at height %d. Reindex required.\n",
                    __func__, p->GetBlockHash().ToString(), p->nHeight);
            return false;
        }

        vChain.push_back(rec);

        // Stop at the first record that is not a delta - but only a record that
        // states BOTH sets in full may serve as the base.
        //
        // !HasFailedSpentDelta() is true for FIVE keys, and three of those
        // state nothing: 'S' and 'V' carry no vTreasury/vFailed section at
        // all, and 'W' carries vFailed with a vSpent nothing ever wrote.
        // Stopping on one and clearing would EMPTY mapFailedWithdrawal and
        // mapSpentWithdrawal, which gate AddWithdrawal (consensus), so a node
        // upgraded in place could disagree with the rest of the network.
        if (!rec.HasFailedSpentDelta()) {
            fFoundAnchor = rec.IsFailedSpentAnchor();
            break;
        }
    }

    // NO ANCHOR, NO REBUILD, AND ABOVE ALL NO CLEAR. Leaving the sets as the
    // caller found them is the pre-delta behaviour and is safe; emptying them is
    // not. The write side should make this unreachable by forcing an anchor when
    // the parent cannot serve as a base - this is the second line of defence.
    if (!fFoundAnchor) {
        LogPrintf("%s: no usable anchor behind %s at height %d - the failed and "
                  "spent sets are LEFT UNCHANGED rather than emptied. A datadir "
                  "written by a build older than the spent key needs -reindex.\n",
                __func__, pindex->GetBlockHash().ToString(), pindex->nHeight);
        return false;
    }

    db.ClearFailedAndSpentWithdrawals();
    for (std::vector<SidechainBlockData>::const_reverse_iterator it = vChain.rbegin();
            it != vChain.rend(); ++it) {
        db.MergeFailedAndSpentWithdrawals(*it);
    }

    return true;
}

//! Takes the database to write to rather than always using the global one, so a
//! caller that must not leave partial state behind can work on a copy and commit
//! only once every step has succeeded.
static bool ResyncSCDBInto(SidechainDB& db, const CBlockIndex* pindex)
{
    // No sidechain data in the genesis block
    if (pindex->GetBlockHash() == Params().GetConsensus().hashGenesisBlock)
        return true;

    SidechainBlockData data;
    if (!psidechaintree->GetBlockData(pindex->GetBlockHash(), data)) {
        LogPrintf("%s: Failed to resync SCDB, cannot find block data in LDB!\n", __func__);
        return false;
    }

    db.ApplyLDBData(pindex->GetBlockHash(), data);

    // ApplyLDBData deliberately leaves the failed/spent sets alone for a delta
    // record, because a delta cannot state them. Rebuild them from the chain.
    if (data.HasFailedSpentDelta() && !RestoreFailedSpentFromRecords(db, pindex)) {
        LogPrintf("%s: Failed to resync SCDB, cannot rebuild failed/spent sets!\n", __func__);
        return false;
    }

    LogPrintf("%s: SCDB resync to block %s complete.\n",
            __func__, pindex->GetBlockHash().ToString());

    return true;
}

bool CheckSCDBRecordFormat(std::string& strError)
{
    LOCK(cs_main);
    if (!psidechaintree)
        return true;

    // A 0.44.08 node does not split at the fork: its gates are dormant, so it
    // keeps following the chain and writes legacy (narrow) records past
    // SidechainParamsHeight. A newer release never overwrites an existing
    // record and would seed its sidechain state from them - built under the
    // old rules - and stall. -reindex-chainstate keeps the sidechain tree,
    // so only a full -reindex repairs it. Cheap: three record reads.
    const int nParamsHeight = Params().GetConsensus().SidechainParamsHeight;
    std::vector<const CBlockIndex*> vCheck;
    if (chainActive.Tip() && chainActive.Height() >= nParamsHeight) {
        vCheck.push_back(chainActive.Tip());
        vCheck.push_back(chainActive[nParamsHeight]);
    }
    // Under -reindex-chainstate the chain state restarts from genesis while
    // the sidechain tree is kept, so look along the best header chain too.
    if (pindexBestHeader && pindexBestHeader->nHeight >= nParamsHeight)
        vCheck.push_back(pindexBestHeader->GetAncestor(nParamsHeight));

    for (const CBlockIndex* pindex : vCheck) {
        if (!pindex)
            continue;
        SidechainBlockData data;
        if (!psidechaintree->GetBlockData(pindex->GetBlockHash(), data))
            continue;   // a missing record already fails loudly elsewhere
        if (!data.HasWideWithdrawalState()) {
            strError = strprintf(_("The sidechain record for block %s (height %d) is in the pre-fork format: "
                                   "this data directory was run past the fork height %d by Skydoge 0.44.08 or older. "
                                   "Restart with -reindex (a FULL -reindex: -reindex-chainstate does not rebuild "
                                   "the sidechain database)."),
                                 pindex->GetBlockHash().ToString(), pindex->nHeight, nParamsHeight);
            return false;
        }
    }
    return true;
}

bool ResyncSCDB(const CBlockIndex* pindex)
{
    uiInterface.InitMessage(_("Resyncing sidechain database..."));

    return ResyncSCDBInto(scdb, pindex);
}

double GetNetworkHashPerSecond(int nLookup, int nHeight)
{
    CBlockIndex *pb = chainActive.Tip();

    if (nHeight >= 0 && nHeight < chainActive.Height())
        pb = chainActive[nHeight];

    if (pb == nullptr || !pb->nHeight)
        return 0;

    // If nLookup is -1, then use blocks since last difficulty change.
    if (nLookup <= 0)
        nLookup = pb->nHeight % Params().GetConsensus().DifficultyAdjustmentInterval() + 1;

    // If nLookup is larger than chain, then set it to chain length.
    if (nLookup > pb->nHeight)
        nLookup = pb->nHeight;

    CBlockIndex *pb0 = pb;
    int64_t minTime = pb0->GetBlockTime();
    int64_t maxTime = minTime;
    for (int i = 0; i < nLookup; i++) {
        pb0 = pb0->pprev;
        int64_t time = pb0->GetBlockTime();
        minTime = std::min(time, minTime);
        maxTime = std::max(time, maxTime);
    }

    // In case there's a situation where minTime == maxTime, we don't want a divide by zero exception.
    if (minTime == maxTime)
        return 0;

    arith_uint256 workDiff = pb->nChainWork - pb0->nChainWork;
    int64_t timeDiff = maxTime - minTime;

    return workDiff.getdouble() / timeDiff;
}

bool LoadAddressBook()
{
    fs::path path = GetDataDir() / "addressbook" / "addressbook.dat";
    std::vector<CDataStream> vCandidate;
    // A file that is there but will not open is not the same as no file at all.
    // Reporting "nothing to load" would let startup finish with an empty cache
    // and shutdown write that emptiness over data nothing can rebuild, so say
    // the load failed and leave the file alone.
    const CacheRead read = ReadCacheFileCandidates(path, vCandidate);
    if (read == CacheRead::MISSING)
        return true;
    if (read == CacheRead::UNOPENABLE)
        return error("%s: %s exists but could not be opened", __func__, path.string());

    std::vector<MultisigPartner> vPartner;
    bool fParsed = false;
    bool fRecovered = false;
    for (size_t c = 0; c < vCandidate.size(); c++) {
        vPartner.clear();
        CDataStream& filein = vCandidate[c];
        try {
            uint64_t nVersion;
            filein >> nVersion;
            if (nVersion != SCDB_DUMP_VERSION)
                continue;

            int count = 0;
            filein >> count;
            for (int i = 0; i < count; i++) {
                MultisigPartner partner;
                filein >> partner;
                vPartner.push_back(partner);
            }
        }
        catch (const std::exception& e) {
            LogPrintf("%s: Exception: %s\n", __func__, e.what());
            continue;
        }
        // A parse that "succeeds" while leaving bytes behind is the
        // signature of the text-mode corruption: the extra 0x0D bytes shift
        // everything along, the reads still find enough data, and the loader
        // returns garbage without ever throwing. Insist the whole stream was
        // consumed before believing a candidate.
        if (!filein.empty())
            continue;
        fParsed = true;
        fRecovered = (c > 0);
        break;
    }
    if (!fParsed)
        return false;
    if (fRecovered)
        LogPrintf("%s: %s was written in text mode by an older build; recovered it. "
                  "It is rewritten in binary at the next clean shutdown.\n", __func__, path.string());

    // Add to address book
    for (const MultisigPartner& p : vPartner)
        addressBook.AddMultisigPartner(p);

    return true;
}

void DumpAddressBook()
{
    // The address book is read near the end of startup, so a start that stopped
    // before that point holds an empty one. Writing it then would erase the
    // user's partners, and nothing can rebuild them.
    if (!fSCDBStateLoaded) {
        LogPrintf("%s: Startup did not reach the address book; leaving the file alone.\n", __func__);
        return;
    }

    // Create ~/.drivechain/addressbook
    TryCreateDirectories(GetDataDir() / "addressbook");

    std::vector<MultisigPartner> vPartner = addressBook.GetMultisigPartners();

    int count = vPartner.size();

    // Write the address book
    fs::path path = GetDataDir() / "addressbook" / "addressbook.dat.new";
    CAutoFile fileout(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
    if (fileout.IsNull()) {
        return;
    }

    try {
        fileout << SCDB_DUMP_VERSION; // version required to read
        fileout << count;

        for (const MultisigPartner& p : vPartner) {
            fileout << p;
        }
    }
    catch (const std::exception& e) {
        // Serialisation stopped part way, so the replacement is incomplete.
        LogPrintf("%s: Exception: %s\n", __func__, e.what());
        return;
    }

    if (!FileCommit(fileout.Get())) {
        // The replacement never reached the disk. Renaming it over the previous
        // file would trade a good copy for a truncated one, so keep what is
        // there; the .new file is overwritten on the next attempt.
        LogPrintf("%s: Failed to write the cache file; keeping the previous copy.\n", __func__);
        return;
    }
    fileout.fclose();
    if (!RenameOver(GetDataDir() / "addressbook" / "addressbook.dat.new",
                    GetDataDir() /  "addressbook" / "addressbook.dat")) {
        LogPrintf("%s: Failed to replace the previous file; the cache was not saved.\n", __func__);
        return;
    }

    LogPrintf("%s: Wrote %u\n", __func__, count);
}

class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() {
        // block headers
        BlockMap::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();
    }
} instance_of_cmaincleanup;
