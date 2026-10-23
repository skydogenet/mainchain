// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "miner.h"

#include "amount.h"
#include "base58.h"
#include "chain.h"
#include "chainparams.h"
#include "coins.h"
#include "consensus/consensus.h"
#include "consensus/tx_verify.h"
#include "consensus/merkle.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "hash.h"
#include "validation.h"
#include "net.h"
#include "policy/feerate.h"
#include "policy/policy.h"
#include "pow.h"
#include "primitives/transaction.h"
#include "script/standard.h"
#include "sidechain.h"
#include "sidechaindb.h"
#include "timedata.h"
#include "txmempool.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "validationinterface.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <algorithm>
#include <map>
#include <mutex>
#include <queue>
#include <set>
#include <utility>

#include <boost/thread.hpp>
#include <boost/tuple/tuple.hpp>

static const bool fMiningReqiresPeer = false;

//////////////////////////////////////////////////////////////////////////////
//
// BitcoinMiner
//

//
// Unconfirmed transactions in the memory pool often depend on other
// transactions in the memory pool. When we select transactions from the
// pool, we select by highest fee rate of a transaction combined with all
// its ancestors.

uint64_t nLastBlockTx = 0;
uint64_t nLastBlockWeight = 0;
uint256 hashTarget = uint256();
uint256 hashBest = uint256();
uint32_t nMiningNonce = 0;

int64_t UpdateTime(CBlockHeader* pblock, const Consensus::Params& consensusParams, const CBlockIndex* pindexPrev)
{
    // pindexPrev is chainActive.Tip() at every call site, and that is null until
    // the chain is loaded. The mining thread read it without cs_main and reached
    // here with null, dereferencing it below and killing the process. Refuse
    // the update rather than crash.
    //
    // Only the mining loop acts on this return, breaking out to recreate the
    // block. The other two callers ignore it and dereference pindexPrev
    // themselves, so they depend on their own guarantees that the tip is set
    // rather than on this check: CreateNewBlock asserts a non-null tip before
    // building, and getblocktemplate refuses to run during initial block
    // download, which a null tip implies.
    if (pindexPrev == nullptr)
        return -1;

    int64_t nOldTime = pblock->nTime;
    int64_t nNewTime = std::max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    // Timewarp guard: never produce a first-of-period block that dates backward
    // more than MAX_TIMEWARP from its parent (consensus rule from
    // TimewarpGuardHeight), even if the parent's timestamp is in the future.
    const int nHeight = pindexPrev->nHeight + 1;
    if (nHeight >= consensusParams.TimewarpGuardHeight &&
        nHeight % consensusParams.DifficultyAdjustmentInterval() == 0) {
        nNewTime = std::max(nNewTime, pindexPrev->GetBlockTime() - MAX_TIMEWARP);
    }

    if (nOldTime < nNewTime)
        pblock->nTime = nNewTime;

    // Updating time can change work required on testnet:
    if (consensusParams.fPowAllowMinDifficultyBlocks)
        pblock->nBits = GetNextWorkRequired(pindexPrev, pblock, consensusParams);

    return nNewTime - nOldTime;
}

BlockAssembler::Options::Options() {
    blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    nBlockMaxWeight = DEFAULT_BLOCK_MAX_WEIGHT;
}

BlockAssembler::BlockAssembler(const CChainParams& params, const Options& options) : chainparams(params)
{
    blockMinFeeRate = options.blockMinFeeRate;
    // Limit weight to between 4K and MAX_BLOCK_WEIGHT-4K for sanity:
    nBlockMaxWeight = std::max<size_t>(4000, std::min<size_t>(MAX_BLOCK_WEIGHT - 4000, options.nBlockMaxWeight));
}

static BlockAssembler::Options DefaultOptions(const CChainParams& params)
{
    // Block resource limits
    // If neither -blockmaxsize or -blockmaxweight is given, limit to DEFAULT_BLOCK_MAX_*
    // If only one is given, only restrict the specified resource.
    // If both are given, restrict both.
    BlockAssembler::Options options;
    options.nBlockMaxWeight = gArgs.GetArg("-blockmaxweight", DEFAULT_BLOCK_MAX_WEIGHT);
    if (gArgs.IsArgSet("-blockmintxfee")) {
        CAmount n = 0;
        ParseMoney(gArgs.GetArg("-blockmintxfee", ""), n);
        options.blockMinFeeRate = CFeeRate(n);
    } else {
        options.blockMinFeeRate = CFeeRate(DEFAULT_BLOCK_MIN_TX_FEE);
    }
    return options;
}

BlockAssembler::BlockAssembler(const CChainParams& params) : BlockAssembler(params, DefaultOptions(params)) {}

/** Whether a sidechain proposal is too big to commit to the coinbase. Used both
 *  to reserve room for the proposal and to decide whether to commit it; the two
 *  have to agree or the reserve does not cover what gets appended. */
static_assert(SIDECHAIN_PROPOSAL_MAX_COMMIT_BYTES <= SIDECHAIN_PROPOSAL_MAX_TEXT_BYTES,
        "the miner must never commit a proposal that consensus refuses");
static bool IsSidechainProposalTooLarge(const Sidechain& s)
{
    return s.title.size() + s.description.size() > SIDECHAIN_PROPOSAL_MAX_COMMIT_BYTES;
}

/**
 * Charge the coinbase commitment that one critical data transaction forces.
 *
 * GenerateCriticalHashCommitments appends one commitment output per critical
 * data transaction in the block, after selection has already finished, and
 * ContextualCheckBlock requires every such transaction to have one - a block
 * missing any is rejected as bad-critical-data-no-commit. The commitment
 * therefore cannot be dropped later to make an over-budget block fit, so its
 * cost has to be charged while there is still a choice to make: here, against
 * the same budgets the transaction itself is charged to.
 *
 * A fixed reserve cannot substitute for this. The number of critical data
 * transactions is set by whoever fills the mempool, not by us, so no constant
 * is large enough to be safe.
 *
 * Both figures matter. The weight is the smaller problem - the output is at
 * most 67 bytes. The sigop cost is the sharp one: the commitment script is
 * OP_RETURN followed by the transaction's own hashCritical and extra bytes,
 * both copied in raw, and CScript::GetSigOpCount does not stop at OP_RETURN.
 * Bytes that happen to equal OP_CHECKMULTISIG count twenty sigops each, so a
 * single commitment can carry 1060 of them - and CheckBlock counts the
 * coinbase's sigops along with everything else.
 *
 * The output is built by the same helper the miner will call, so what is
 * reserved here cannot drift from what is later appended. It is base data, so
 * neither figure gets the witness discount.
 */
static void AddCriticalDataOverhead(const CTransaction& tx, int64_t& nWeight, int64_t& nSigOpsCost)
{
    if (tx.criticalData.IsNull())
        return;

    const CTxOut out = GetCriticalHashCommitmentOut(tx.criticalData);
    nWeight += WITNESS_SCALE_FACTOR * ::GetSerializeSize(out, SER_NETWORK, PROTOCOL_VERSION);
    nSigOpsCost += WITNESS_SCALE_FACTOR * (int64_t)out.scriptPubKey.GetSigOpCount(false);

    // The critical fee transaction takes one input per critical data
    // transaction in the block to sweep its bid. That transaction is optional
    // and is dropped if it does not fit, but dropping it means giving up the
    // bids, so reserve for it here and let it fit. The small-block byte
    // reserve has always counted this input; the weight budget did not.
    nWeight += WITNESS_SCALE_FACTOR * CRITICAL_FEE_TX_INPUT_BYTES;
}

void BlockAssembler::resetBlock()
{
    inBlock.clear();

    // Reserve space for coinbase tx
    nBlockWeight = 4000;
    nBlockSigOpsCost = 400;
    fIncludeWitness = false;

    // Small-block accounting is initialized in CreateNewBlock once the
    // height of the block being assembled is known.
    fEnforceSmallBlock = false;
    nBlockSerializedSize = 0;

    // These counters do not include coinbase tx
    nBlockTx = 0;
    nFees = 0;
}

uint64_t SmallBlockCommitmentReserveBytes(int nHeight, size_t* pnSlots)
{
    // Per active sidechain: its SCDB update vote bytes and its
    // withdrawal-hash commitment.
    const std::vector<Sidechain> vActiveSidechain = scdb.GetActiveSidechains();
    uint64_t nReserveBytes = vActiveSidechain.size() * SMALL_BLOCK_PER_SIDECHAIN_RESERVE_BYTES;
    size_t nSlots = vActiveSidechain.size();

    // Per proposal waiting to activate: its activation commitment. A slot
    // leaves the activation cache once it activates, so this is a different
    // set from the active sidechains above and needs its own reserve. One
    // commitment per slot number, matching the dedupe at the commit site.
    std::set<uint8_t> setPending;
    for (const SidechainActivationStatus& s : scdb.GetSidechainActivationStatus())
        setPending.insert(s.proposal.nSidechain);
    nReserveBytes += setPending.size() * SIDECHAIN_ACTIVATION_COMMITMENT_BYTES;
    nSlots += setPending.size();

    // At most one sidechain proposal commitment, and its size is whatever
    // title and description the operator typed. Reserve for the largest of
    // the candidates rather than assuming it is small - this is the one
    // coinbase append with no inherent bound.
    uint64_t nProposalBytes = 0;
    for (const Sidechain& p : scdb.GetSidechainProposals()) {
        if (IsSidechainProposalTooLarge(p))
            continue;
        const CTxOut out(0, p.GetProposalScript());
        nProposalBytes = std::max(nProposalBytes,
                (uint64_t)::GetSerializeSize(out, SER_NETWORK, PROTOCOL_VERSION));
    }
    nReserveBytes += nProposalBytes;

    // The SCDB hash commitment: one fixed-size output, required in every
    // coinbase from SCDBCommitmentHeight, appended after everything else.
    if (nHeight >= Params().GetConsensus().SCDBCommitmentHeight) {
        nReserveBytes += SCDB_COMMITMENT_BYTES;
        nSlots += 1;
    }

    if (pnSlots)
        *pnSlots = nSlots;
    return nReserveBytes;
}

uint64_t SmallBlockPayoutRoomBytes(int nHeight)
{
    const uint64_t nReserved = SMALL_BLOCK_COINBASE_RESERVE_BYTES + SmallBlockCommitmentReserveBytes(nHeight, nullptr)
                               + SMALL_BLOCK_PAYOUT_OVERHEAD_BYTES;
    if (nReserved >= MAX_SMALL_BLOCK_SERIALIZED_SIZE)
        return 0;
    return MAX_SMALL_BLOCK_SERIALIZED_SIZE - nReserved;
}

/** Serialized bytes of all the outputs of the block's coinbase. */
static uint64_t CoinbaseOutputBytes(const CBlock& block)
{
    uint64_t nBytes = 0;
    for (const CTxOut& out : block.vtx[0]->vout)
        nBytes += ::GetSerializeSize(out, SER_NETWORK, PROTOCOL_VERSION);
    return nBytes;
}

CScript g_bmm_fee_script;

/** The script the critical fee transaction pays. */
static const CScript& CriticalFeeScript(const CScript& scriptPubKeyIn)
{
    return g_bmm_fee_script.empty() ? scriptPubKeyIn : g_bmm_fee_script;
}

/** Bytes of a small block that are there whatever is selected: the header,
 *  the transaction count, and the coinbase with its payout output, witness
 *  commitment and a scriptSig grown to the consensus maximum. With drivechain
 *  enabled also the frame of the critical fee transaction (its inputs are
 *  charged with the critical data transactions they sweep), so that taking a
 *  bid never costs the transaction that collects it. */
static uint64_t SmallBlockFixedBytes(const CScript& scriptPubKeyIn, bool fDrivechainEnabled)
{
    const uint64_t nPayoutOut = ::GetSerializeSize(CTxOut(0, scriptPubKeyIn), SER_NETWORK, PROTOCOL_VERSION);
    uint64_t nBytes = 80        // block header
            + 3                 // transaction count
            + 4 + 2             // coinbase nVersion, segwit marker and flag
            + 1 + 36 + 1 + SMALL_BLOCK_COINBASE_SCRIPTSIG_BYTES + 4 // its input
            + 3                 // output count
            + nPayoutOut        // the payout output
            + 8 + 1 + 38        // the witness commitment output
            + 1 + 1 + 32        // the coinbase witness (one reserved value)
            + 4;                // nLockTime
    if (fDrivechainEnabled) {
        // Sized from the script it actually pays (-bmmfeescript).
        const uint64_t nFeeOut = ::GetSerializeSize(CTxOut(0, CriticalFeeScript(scriptPubKeyIn)), SER_NETWORK, PROTOCOL_VERSION);
        nBytes += 4 + 3 + 1 + nFeeOut + 4; // critical fee tx without inputs
    }
    return nBytes;
}

uint64_t SmallBlockCriticalTxReserveBytes(const CTransaction& tx)
{
    if (tx.criticalData.IsNull())
        return 0;

    // The h* commitment, from the helper GenerateCriticalHashCommitments
    // appends it with.
    uint64_t nBytes = ::GetSerializeSize(GetCriticalHashCommitmentOut(tx.criticalData), SER_NETWORK, PROTOCOL_VERSION);
    // The critical fee transaction spends every bare OP_TRUE output of this
    // transaction, one input each.
    const CScript scriptBid = CScript() << OP_TRUE;
    for (const CTxOut& out : tx.vout) {
        if (out.scriptPubKey == scriptBid)
            nBytes += CRITICAL_FEE_TX_INPUT_BYTES;
    }
    return nBytes;
}

/** The withdrawal bundle each active sidechain announces in the block being
 *  built: the newest one in the local cache that the chain has not seen, has
 *  not paid out and has not failed. The lookup hashes every cached bundle of
 *  the sidechain, so CreateNewBlock does it once and both sizes the coinbase
 *  and writes the commitments from the result. Call with cs_main held. */
static std::map<uint8_t /* nSidechain */, uint256 /* hash withdrawal */> NewWithdrawalsToCommit(const std::vector<Sidechain>& vActiveSidechain, int nHeight)
{
    std::map<uint8_t, uint256> mapNewWithdrawal;
    for (const Sidechain& s : vActiveSidechain) {
        const std::vector<uint256> vHash = scdb.GetUncommittedWithdrawalCache(s.nSidechain);

        if (vHash.empty())
            continue;

        // Never build a block AddWithdrawal would refuse for
        // the pending cap. Only a slot whose every pending bundle is
        // payout-ready can be refused; anything else displaces the weakest.
        if (!scdb.WithdrawalSlotHasRoom(s.nSidechain, nHeight))
            continue;

        // A block that adds a withdrawal skips every
        // score change for that slot, and a bundle displaced from a full slot
        // stays cached, looks uncommitted again and used to be offered right
        // back - displacing another, every block - so a miner holding more
        // bundles than the cap froze the slot's votes indefinitely (>= 50 %
        // of the hashrate: its withdrawals stop). A bundle that slot DISPLACED
        // now comes back only when the slot has a free entry, or when this
        // node upvotes it (that bundle then outranks the score-1 entries, so
        // it cannot loop). A bundle never displaced still displaces the
        // weakest, which is the anti-griefing rule the cap relies on.
        // Newest first, as before; skipping one no longer skips the slot.
        const bool fSlotFull = nHeight >= Params().GetConsensus().SidechainParamsHeight &&
                scdb.GetState(s.nSidechain).size() >= SIDECHAIN_WITHDRAWAL_MAX_PENDING;
        for (std::vector<uint256>::const_reverse_iterator it = vHash.rbegin(); it != vHash.rend(); ++it) {
            const uint256& hash = *it;
            // Make sure that the Withdrawal hasn't previously been spent or failed.
            if (scdb.HaveFailedWithdrawal(hash, s.nSidechain))
                continue;
            if (scdb.HaveSpentWithdrawal(hash, s.nSidechain))
                continue;
            if (fSlotFull && scdb.WasWithdrawalDisplaced(s.nSidechain, hash) &&
                    !scdb.IsWithdrawalUpvotedHere(s.nSidechain, hash))
                continue;
            mapNewWithdrawal[s.nSidechain] = hash;
            break;
        }
    }
    return mapNewWithdrawal;
}

uint64_t SmallBlockCoinbaseCommitmentBytes(int nHeight, const std::vector<Sidechain>& vActiveSidechain, const std::map<uint8_t, uint256>& mapNewWithdrawal, bool fDrivechainEnabled)
{
    // Every commitment is generated here on a scratch block, with the same
    // predicates and the same helpers CreateNewBlock uses when it appends
    // them after transaction selection. cs_main is held from here to there,
    // so what is measured is what is appended. CreateNewBlock compares the
    // two, logs both, and logs an error if they ever differ the wrong way.
    CBlock scratch;
    scratch.vtx.push_back(MakeTransactionRef(CMutableTransaction()));
    uint64_t nAppendedLaterBytes = 0;

    if (fDrivechainEnabled) {
        for (const Sidechain& s : vActiveSidechain) {
            const std::map<uint8_t, uint256>::const_iterator it = mapNewWithdrawal.find(s.nSidechain);
            if (it != mapNewWithdrawal.end())
                GenerateWithdrawalHashCommitment(scratch, it->second, s.nSidechain);
        }

        if (scdb.HasState()) {
            const std::vector<std::string> vVote = scdb.GetVotes();
            std::vector<std::vector<SidechainWithdrawalState>> vOldScores;
            for (const Sidechain& s : vActiveSidechain) {
                const std::vector<SidechainWithdrawalState> vWithdrawal = scdb.GetState(s.nSidechain);
                if (vWithdrawal.size())
                    vOldScores.push_back(vWithdrawal);
            }
            // A failure here appends nothing, and makes CreateNewBlock throw
            // when it reaches the real commitment.
            CScript script;
            GenerateSCDBByteCommitment(scratch, script, vOldScores, vVote);
        }

        // The proposal commitment: the first of our proposals that is not
        // pending already, not identical to its slot's active sidechain
        // (IsSidechainProposalKnown - consensus ignores both from the fork)
        // and not too large. Must stay the same choice as CreateNewBlock's.
        const std::vector<SidechainActivationStatus> vActivation = scdb.GetSidechainActivationStatus();
        for (const Sidechain& p : scdb.GetSidechainProposals()) {
            if (scdb.IsSidechainProposalKnown(p) || IsSidechainProposalTooLarge(p))
                continue;
            GenerateSidechainProposalCommitment(scratch, p);
            break;
        }

        // The activation commitments: one per slot number this node acks,
        // less those the active-slot limit of a small block refuses. (This
        // function is only called for a block bound by the small-block rule.)
        // Which proposals are acked is MinerAcksSidechainProposal, the same
        // test CreateNewBlock uses, so the reserve and the block agree.
        std::set<uint8_t> setCommit;
        unsigned int nNewCommitted = 0;
        const unsigned int nActive = scdb.GetActiveSidechainCount();
        for (const SidechainActivationStatus& s : vActivation) {
            if (!MinerAcksSidechainProposal(s.proposal.GetSerHash()))
                continue;
            if (setCommit.count(s.proposal.nSidechain))
                continue;
            const bool fNewSlot = !scdb.IsSidechainActive(s.proposal.nSidechain);
            if (fNewSlot && nActive + nNewCommitted + 1 > SIDECHAIN_SMALL_BLOCK_MAX_ACTIVE)
                continue;
            GenerateSidechainActivationCommitment(scratch, s.proposal.GetSerHash());
            setCommit.insert(s.proposal.nSidechain);
            if (fNewSlot)
                nNewCommitted++;
        }
    }

    // The SCDB hash commitment, appended after everything else.
    if (nHeight >= Params().GetConsensus().SCDBCommitmentHeight)
        nAppendedLaterBytes += SCDB_COMMITMENT_BYTES;

    return CoinbaseOutputBytes(scratch) + nAppendedLaterBytes;
}

// -acksidechainproposal (see miner.h). Filled once by init before any
// template is built; the mutex is for tests and for safety, not contention.
static std::mutex cs_configuredSidechainAck;
static std::set<uint256> setConfiguredSidechainAck;

bool ParseSidechainProposalAcks(const std::vector<std::string>& vArg, std::set<uint256>& setOut, std::string& strError)
{
    setOut.clear();
    for (const std::string& str : vArg) {
        // Exactly 64 hex digits: no 0x prefix, no padding, no truncation -
        // a short value that uint256S would silently zero-extend could name
        // a different proposal than the operator meant.
        if (str.size() != 64 || !IsHex(str)) {
            strError = strprintf("Invalid -acksidechainproposal=%s: it must be the 64-hex-digit \"proposalhash\" "
                                 "that getsidechainactivationstatus prints", str);
            return false;
        }
        const uint256 hash = uint256S(str);
        if (hash.IsNull()) {
            strError = strprintf("Invalid -acksidechainproposal=%s: the null hash is not a proposal", str);
            return false;
        }
        setOut.insert(hash);
    }
    return true;
}

void SetConfiguredSidechainProposalAcks(const std::set<uint256>& setAck)
{
    std::lock_guard<std::mutex> lock(cs_configuredSidechainAck);
    setConfiguredSidechainAck = setAck;
}

std::set<uint256> GetConfiguredSidechainProposalAcks()
{
    std::lock_guard<std::mutex> lock(cs_configuredSidechainAck);
    return setConfiguredSidechainAck;
}

bool IsConfiguredSidechainProposalAck(const uint256& hashProposal)
{
    std::lock_guard<std::mutex> lock(cs_configuredSidechainAck);
    return setConfiguredSidechainAck.count(hashProposal) != 0;
}

// An identical re-proposal of the sidechain a slot already runs has the same
// hash as that sidechain's proposal (the active copy hashed with fActive
// false, as GetConfiguredSidechainProposalAckStatus does). Activating it
// changes nothing but resets the slot - treasury pointer, deposits,
// withdrawals and votes - so the miner never acks one, whatever the ack
// source. From the fork height consensus does not track such a proposal at
// all (SidechainDB::IsSidechainProposalKnown).
static bool IsActiveSidechainReproposal(const uint256& hashProposal)
{
    for (const Sidechain& s : scdb.GetActiveSidechains()) {
        Sidechain proposal = s;
        proposal.fActive = false;
        if (proposal.GetSerHash() == hashProposal)
            return true;
    }
    return false;
}

bool MinerAcksSidechainProposal(const uint256& hashProposal)
{
    if (IsActiveSidechainReproposal(hashProposal))
        return false;
    // -activatesidechains acks every proposal, a hijacker's included. Kept
    // for tests; mainnet pools name the proposal.
    if (gArgs.GetBoolArg("-activatesidechains", false))
        return true;
    if (scdb.GetAckSidechain(hashProposal))
        return true;
    return IsConfiguredSidechainProposalAck(hashProposal);
}

std::string ConfiguredSidechainAckStatusName(ConfiguredSidechainAckStatus::Status status)
{
    switch (status) {
    case ConfiguredSidechainAckStatus::PENDING:  return "pending";
    case ConfiguredSidechainAckStatus::ACTIVE:   return "active";
    case ConfiguredSidechainAckStatus::REVERSED: return "reversed";
    case ConfiguredSidechainAckStatus::NOMATCH:  return "nomatch";
    }
    return "unknown";
}

std::vector<ConfiguredSidechainAckStatus> GetConfiguredSidechainProposalAckStatus()
{
    std::vector<ConfiguredSidechainAckStatus> vOut;
    const std::set<uint256> setAck = GetConfiguredSidechainProposalAcks();
    if (setAck.empty())
        return vOut;

    std::set<uint256> setPending;
    for (const SidechainActivationStatus& s : scdb.GetSidechainActivationStatus())
        setPending.insert(s.proposal.GetSerHash());

    // An active sidechain is stored with fActive set, which is serialised, so
    // hash it as the proposal it was (fActive false) to compare.
    std::set<uint256> setActive;
    for (const Sidechain& s : scdb.GetActiveSidechains()) {
        Sidechain proposal = s;
        proposal.fActive = false;
        setActive.insert(proposal.GetSerHash());
    }

    for (const uint256& hash : setAck) {
        ConfiguredSidechainAckStatus st;
        st.hash = hash;
        st.hashMatch.SetNull();
        uint256 reversed;
        std::reverse_copy(hash.begin(), hash.end(), reversed.begin());
        if (setPending.count(hash)) {
            st.status = ConfiguredSidechainAckStatus::PENDING;
        } else if (setActive.count(hash)) {
            st.status = ConfiguredSidechainAckStatus::ACTIVE;
        } else if (setPending.count(reversed)) {
            st.status = ConfiguredSidechainAckStatus::REVERSED;
            st.hashMatch = reversed;
        } else {
            st.status = ConfiguredSidechainAckStatus::NOMATCH;
        }
        vOut.push_back(st);
    }
    return vOut;
}

int LogConfiguredSidechainProposalAckStatus(bool fStartup)
{
    // ACTIVE is reported once per change; the two warnings every call, on
    // purpose: a pool must not run for weeks believing it votes.
    static std::mutex cs_lastActive;
    static std::set<uint256> setLastActive;

    int nWarn = 0;
    const char* strWhen = fStartup ? "at startup" : "at the new tip";
    for (const ConfiguredSidechainAckStatus& st : GetConfiguredSidechainProposalAckStatus()) {
        switch (st.status) {
        case ConfiguredSidechainAckStatus::PENDING:
            if (fStartup)
                LogPrintf("Sidechain activation %s: -acksidechainproposal=%s names a pending proposal; this node's miner acks it\n",
                          strWhen, st.hash.ToString());
            break;
        case ConfiguredSidechainAckStatus::ACTIVE: {
            std::lock_guard<std::mutex> lock(cs_lastActive);
            if (fStartup || !setLastActive.count(st.hash))
                LogPrintf("Sidechain activation %s: -acksidechainproposal=%s names a sidechain that is now ACTIVE; there is nothing left to ack and the setting can be removed\n",
                          strWhen, st.hash.ToString());
            setLastActive.insert(st.hash);
            break;
        }
        case ConfiguredSidechainAckStatus::REVERSED:
            nWarn++;
            LogPrintf("WARNING: sidechain activation %s: -acksidechainproposal=%s matches NO pending sidechain proposal, but its byte-reversed form %s does: you gave the listhashsidechain byte order. "
                      "This node acks NOTHING until you set -acksidechainproposal=%s (the \"proposalhash\" of getsidechainactivationstatus)\n",
                      strWhen, st.hash.ToString(), st.hashMatch.ToString(), st.hashMatch.ToString());
            break;
        case ConfiguredSidechainAckStatus::NOMATCH:
            nWarn++;
            LogPrintf("WARNING: sidechain activation %s: -acksidechainproposal=%s matches NO pending sidechain proposal (nor an active sidechain); this node's miner acks nothing for it. "
                      "Check the value against the \"proposalhash\" of getsidechainactivationstatus\n",
                      strWhen, st.hash.ToString());
            break;
        }
        if (st.status != ConfiguredSidechainAckStatus::ACTIVE) {
            std::lock_guard<std::mutex> lock(cs_lastActive);
            setLastActive.erase(st.hash);
        }
    }
    return nWarn;
}


std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, bool fMineWitnessTx)
{
    bool fAddedBMM = false;
    return CreateNewBlock(scriptPubKeyIn, fMineWitnessTx, fAddedBMM);
}

std::unique_ptr<CBlockTemplate> BlockAssembler::CreateNewBlock(const CScript& scriptPubKeyIn, bool fMineWitnessTx, bool& fAddedBMM)
{
    int64_t nTimeStart = GetTimeMicros();

    resetBlock();

    pblocktemplate.reset(new CBlockTemplate());

    if(!pblocktemplate.get())
        return nullptr;
    pblock = &pblocktemplate->block; // pointer for convenience

    // Add dummy coinbase tx as first transaction
    pblock->vtx.emplace_back();
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOpsCost.push_back(-1); // updated at end

    LOCK2(cs_main, mempool.cs);
    CBlockIndex* pindexPrev = chainActive.Tip();
    assert(pindexPrev != nullptr);
    nHeight = pindexPrev->nHeight + 1;

    pblock->nVersion = ComputeBlockVersion(pindexPrev, chainparams.GetConsensus());
    // -regtest only: allow overriding block.nVersion with
    // -blockversion=N to test forking scenarios
    if (chainparams.MineBlocksOnDemand())
        pblock->nVersion = gArgs.GetArg("-blockversion", pblock->nVersion);

    pblock->nTime = GetAdjustedTime();
    const int64_t nMedianTimePast = pindexPrev->GetMedianTimePast();

    nLockTimeCutoff = (STANDARD_LOCKTIME_VERIFY_FLAGS & LOCKTIME_MEDIAN_TIME_PAST)
                       ? nMedianTimePast
                       : pblock->GetBlockTime();

    // Decide whether to include witness transactions
    // This is only needed in case the witness softfork activation is reverted
    // (which would require a very deep reorganization) or when
    // -promiscuousmempoolflags is used.
    // TODO: replace this with a call to main to assess validity of a mempool
    // transaction (which in most cases can be a no-op).
    fIncludeWitness = IsWitnessEnabled(pindexPrev, chainparams.GetConsensus()) && fMineWitnessTx;

    // Small-block soft fork: blocks at and after SmallBlockHeight must not
    // exceed MAX_SMALL_BLOCK_SERIALIZED_SIZE COMMITTED bytes (witness at par,
    // criticalData excluded, a fixed charge per nVersion-3 transaction - see
    // GetCommittedSerializedSize), so transaction selection switches to exact
    // byte accounting IN THAT MEASURE. Every charge to nBlockSerializedSize
    // and every check of the assembled block below uses the enforced measure
    // itself, never the wire size: the two differ on nVersion-3 transactions
    // in both directions (a null criticalData is charged more than it
    // occupies, a padded one less than the wire), and a miner that counted
    // wire bytes would pass its own check and fail TestBlockValidity from a
    // handful of BMM requests in a full block.
    fEnforceSmallBlock = nHeight >= chainparams.GetConsensus().SmallBlockHeight;

    bool fDrivechainEnabled = IsSkydogeEnabled(pindexPrev, chainparams.GetConsensus());

    // This pass used to sit inside
    // #ifdef ENABLE_WALLET although it uses only the memory pool and the
    // SCDB. A node built --disable-wallet therefore kept every BMM request
    // in its templates; two requests for one slot (both admissible to the
    // pool) made every block it built fail bad-critical-bmm-nsidechain-multiple
    // until they expired. Template policy only - no consensus rule changes,
    // and wallet builds run exactly the code they ran before.
    std::map<uint8_t, std::vector<uint256>> mapBMMRanked;
    if (fDrivechainEnabled) {
        // Make sure that the mempool has only valid deposits to choose from.
        //
        // Suspended by -drivechainpolicybypass, because this pass is what
        // drops a deposit that does not extend the treasury pointer - so
        // leaving it in place would remove the one transaction a test of that
        // shape has to get into a block, after relay policy had already been
        // told to let it through. It is memory pool hygiene rather than a
        // rule about blocks: every check ConnectBlock makes on the block this
        // template becomes is untouched, and the flag cannot be set on any
        // network but regtest.
        if (!fDrivechainPolicyBypass)
            mempool.UpdateCTIPFromBlock(scdb.GetCTIP(), false /* fDisconnect */);

        // Remove expired BMM requests from our memory pool
        std::vector<uint256> vHashRemoved;
        mempool.RemoveExpiredCriticalRequests(vHashRemoved);
        // Remove the requests no block on this tip can carry (stale ones
        // first). Valid competitors stay in the memory pool.
        mempool.RemoveInvalidBMMRequests(vHashRemoved);

        // Track what was removed from the mempool so that we can abandon later
        for (const uint256& u : vHashRemoved)
            scdb.AddRemovedBMM(u);

        // The requests each slot may carry, highest fee + bid first. Which
        // one this template takes is decided just before selection, when
        // the room left in the block is known (PickBMMRequests).
        mapBMMRanked = mempool.RankBMMRequests(blockMinFeeRate);
    }

    // Collect active sidechains
    std::vector<Sidechain> vActiveSidechain;
    if (fDrivechainEnabled)
        vActiveSidechain = scdb.GetActiveSidechains();

    // The new withdrawal bundle each of them announces in this block, if any.
    // Looked up ONCE: it is read to size the coinbase before transaction
    // selection and again to write the commitments after it, and each lookup
    // hashes every bundle in the local cache. cs_main is held from here to
    // there and nothing in between changes the cache, the withdrawal status
    // or the spent and failed records, so one reading is what two gave.
    const std::map<uint8_t /* nSidechain */, uint256 /* hash withdrawal */> mapNewWithdrawal = NewWithdrawalsToCommit(vActiveSidechain, nHeight);

    // Reserve for the commitments this fork appends to the coinbase after
    // transaction selection has finished. resetBlock()'s flat reserve is
    // upstream's, sized for a coinbase carrying one or two outputs; none of
    // what follows fits in it, and a block that outgrows it is rejected by
    // consensus, which aborts the template and stops block production.
    //
    // Only the commitments whose count comes from chain state are reserved
    // here. The critical data commitments are not: how many of those there are
    // is decided by whoever fills the mempool, so no reservation could be large
    // enough and they are charged per transaction instead, as each one is
    // selected. See AddCriticalDataOverhead.
    if (fDrivechainEnabled) {
        size_t nSlots = 0;
        const uint64_t nReserveBytes = SmallBlockCommitmentReserveBytes(nHeight, &nSlots);

        // These commitments are OP_RETURN outputs holding 32-byte hashes, and
        // GetSigOpCount reads straight through OP_RETURN, so hash bytes that
        // happen to be OP_CHECKSIG or OP_CHECKMULTISIG are charged to the
        // block. Unlike a critical data transaction's hash these are hash
        // outputs nobody can choose, so a generous typical is enough.
        nBlockWeight += WITNESS_SCALE_FACTOR * nReserveBytes;
        nBlockSigOpsCost += nSlots * PER_SIDECHAIN_COINBASE_SIGOPS_RESERVE;
    }

    // The small-block byte budget starts from what this block will carry
    // whatever is selected, not from a flat figure: the fixed frame, the
    // commitments the sidechain state calls for at this height (measured, see
    // SmallBlockCoinbaseCommitmentBytes), and the allowance left to whoever
    // finishes the template. A flat 6000 + 112 per active sidechain held back
    // 13,214 bytes at 64 sidechains for a coinbase that needs 3,345 at most
    // before critical data, which kept a standard 40,000-byte transaction out
    // of every block from 36 active sidechains up. The h* commitments are not
    // in here: they are charged with the transaction that causes each one.
    uint64_t nStateCommitmentReserve = 0;
    if (fEnforceSmallBlock) {
        nStateCommitmentReserve = SmallBlockCoinbaseCommitmentBytes(nHeight, vActiveSidechain, mapNewWithdrawal, fDrivechainEnabled);
        nBlockSerializedSize = SmallBlockFixedBytes(scriptPubKeyIn, fDrivechainEnabled)
                               + SMALL_BLOCK_MINER_ALLOWANCE_BYTES + nStateCommitmentReserve;
    }

    // The sidechain activation commitments this block will carry, for
    // proposals in the activation status cache that this node acks
    // (MinerAcksSidechainProposal): every one under -activatesidechains, else
    // those in the acksidechain RPC list and those named by
    // -acksidechainproposal. The last is read from the configuration for
    // every template, so it is never lost with the SCDB.
    //
    // These are chosen here, before the
    // payouts and the vote bytes, rather than where they are written after
    // transaction selection, because both depend on them - see
    // setClearedByActivation. Nothing between here and there changes the
    // activation status (cs_main is held).
    std::vector<uint256> vActivationCommit;
    if (fDrivechainEnabled) {
        std::vector<SidechainActivationStatus> vActivationStatus;
        vActivationStatus = scdb.GetSidechainActivationStatus();
        std::map<uint8_t, bool> mapCommit;
        // From SmallBlockHeight consensus refuses a commitment that would take
        // the active count past SIDECHAIN_SMALL_BLOCK_MAX_ACTIVE, so mirror
        // that here: an acked proposal for an inactive slot beyond the limit
        // is skipped, not committed into a template our own node would reject.
        unsigned int nNewCommitted = 0;
        const unsigned int nActive = scdb.GetActiveSidechainCount();
        for (const SidechainActivationStatus& s : vActivationStatus) {
            if (MinerAcksSidechainProposal(s.proposal.GetSerHash())) {
                // Don't generate more than one commit for the same SC #
                if (mapCommit.find(s.proposal.nSidechain) == mapCommit.end()) {
                    const bool fNewSlot = !scdb.IsSidechainActive(s.proposal.nSidechain);
                    if (fEnforceSmallBlock && fNewSlot &&
                            nActive + nNewCommitted + 1 > SIDECHAIN_SMALL_BLOCK_MAX_ACTIVE) {
                        LogPrintf("%s: not committing to activate sidechain %u - %u active, limit %u\n",
                                  __func__, s.proposal.nSidechain, nActive, SIDECHAIN_SMALL_BLOCK_MAX_ACTIVE);
                        continue;
                    }
                    vActivationCommit.push_back(s.proposal.GetSerHash());
                    mapCommit[s.proposal.nSidechain] = true;
                    if (fNewSlot)
                        nNewCommitted++;
                }
            }
        }
    }

    // The slots whose bundles the
    // activation step of this block clears - a replacement that activates
    // here. ApplyUpdate runs that step BEFORE it parses the vote bytes and
    // before it removes the bundles this block pays out, so this block must
    // neither vote on nor pay a bundle of such a slot: with either, every
    // miner built the same invalid block and the chain could not grow at the
    // replacement height. The bundles are dropped by
    // consensus in this very block whatever the miner does, so skipping them
    // gives up nothing a valid block could carry. Policy only: the parse and
    // every block-validity rule are unchanged.
    std::set<uint8_t> setClearedByActivation;
    // The slots whose replacement is due in this
    // block. The simulation above reads the treasury pointers BEFORE the
    // block, but ConnectBlock adds the block's deposits before the activation
    // step, so a deposit into such a slot can turn the escrow refusal
    // around and the block would then be judged against a different state
    // than the one its vote bytes were written for. This block therefore
    // takes no deposit into those slots: the pointer the simulation read is
    // then the one validation reads. A deposit left out waits in the memory
    // pool. (A payout cannot change the decision: the miner never builds one
    // that leaves the treasury at zero, see CreateWithdrawalPayout.)
    std::set<uint8_t> setReplacementDue;
    if (fDrivechainEnabled) {
        setClearedByActivation = scdb.GetSlotsClearedByActivation(vActivationCommit, nHeight);
        setReplacementDue = scdb.GetSlotsWithReplacementDue(nHeight);
    }

    // Generate payout transactions for any approved withdrawals
    //
    // Keep track of which sidechains will have a Withdrawal in this block. We will
    // need this when deciding what transactions to add from the mempool.
    std::set<uint8_t> setSidechainsWithWithdrawal;
    // Keep track of the created Withdrawal(s) to be added to the block later
    std::vector<CMutableTransaction> vWithdrawal;
    // Keep track of mainchain fees
    CAmount nWithdrawalFees = 0;
    if (fDrivechainEnabled) {
        for (const Sidechain& s : vActiveSidechain) {
            // see setClearedByActivation.
            if (setClearedByActivation.count(s.nSidechain)) {
                LogPrintf("%s: not paying a withdrawal for sidechain %u - its replacement activates in this block and clears its bundles\n",
                          __func__, s.nSidechain);
                continue;
            }
            CMutableTransaction wtx;
            CAmount nFee = 0;
            bool fCreated = CreateWithdrawalPayout(s.nSidechain, wtx, nFee);
            if (fCreated && wtx.vout.size() && wtx.vin.size()) {
                // A payout spends exactly one input, the CTIP, so its outputs
                // cannot be worth more than the CTIP holds. Check that here and
                // drop the payout if it fails.
                //
                // Withdrawal bundles arrive over RPC from a sidechain, and the
                // payout is built from one. Until this check existed a bundle
                // that did not add up surfaced only as a TestBlockValidity
                // failure, which aborts CreateNewBlock - so generatetoaddress and
                // getblocktemplate both failed and the node stopped producing
                // blocks entirely. It could not recover by waiting, because the
                // bundle expires on a block count that could no longer advance,
                // and it survived restart because the bundle is persisted to
                // withdrawal.dat. A format error at the sidechain end must never
                // be able to halt block production here: skip the payout and mine
                // the block without it.
                SidechainCTIP ctip;
                if (!scdb.GetCTIP(s.nSidechain, ctip)) {
                    LogPrintf("%s: Skipping Withdrawal payout for sidechain %u - no CTIP.\n",
                            __func__, s.nSidechain);
                    continue;
                }

                CAmount nPayoutValueOut = 0;
                bool fPayoutAmountInvalid = false;
                for (const CTxOut& out : wtx.vout) {
                    // Ordered so the subtraction cannot underflow: nValue is
                    // known to be in range before it is used as the bound.
                    if (!MoneyRange(out.nValue) || nPayoutValueOut > MAX_MONEY - out.nValue) {
                        fPayoutAmountInvalid = true;
                        break;
                    }
                    nPayoutValueOut += out.nValue;
                }
                if (fPayoutAmountInvalid || nPayoutValueOut > ctip.amount) {
                    LogPrintf("%s: Skipping invalid Withdrawal payout for sidechain %u - outputs total %d against a CTIP of %d.\n",
                            __func__, s.nSidechain, nPayoutValueOut, ctip.amount);
                    continue;
                }

                // The value check above is necessary but not sufficient, and on
                // its own it is easy to slip past. A bundle carrying its own
                // zero-value sidechain output, for instance, is copied here and
                // then joined by the appended change return; the totals still
                // balance, but consensus rejects the result for having two
                // sidechain return outputs. Any bundle already sitting in
                // withdrawal.dat reaches this point without passing the checks
                // in receivewithdrawalbundle, because LoadWithdrawalCache
                // deliberately re-caches whatever it finds.
                //
                // So ask consensus itself rather than approximating it.
                // fJustCheck makes SpendWithdrawal read-only, and it is the same
                // predicate ConnectBlock will apply to this transaction, so
                // anything it rejects would otherwise have aborted the template.
                if (!scdb.SpendWithdrawal(s.nSidechain, uint256(), CTransaction(wtx),
                                          0 /* nTx */, nHeight, true /* fJustCheck */)) {
                    LogPrintf("%s: Skipping Withdrawal payout for sidechain %u - consensus would reject it.\n",
                            __func__, s.nSidechain);
                    continue;
                }

                // Withdrawal payouts are appended to the block after
                // transaction selection, so consume their exact serialized
                // size from the small-block budget up front. If the payouts
                // of several sidechains cannot all fit in one small block,
                // defer the ones that don't fit to a later block instead of
                // assembling a block that consensus would reject.
                const uint64_t nPayoutSize = GetChargedSerializedSize(CTransaction(wtx));
                if (fEnforceSmallBlock &&
                        nBlockSerializedSize + nPayoutSize > MAX_SMALL_BLOCK_SERIALIZED_SIZE) {
                    LogPrintf("%s: Deferring Withdrawal payout for sidechain %u (%u bytes) - no room in small block.\n",
                            __func__, s.nSidechain, nPayoutSize);
                    continue;
                }

                // The same reasoning applies to the weight and sigop budgets,
                // which are in force today while the small-block one is not.
                // addPackageTxs below fills the block up to nBlockMaxWeight and
                // knows nothing about anything appended after it, so a payout
                // that is not charged here can push the assembled block past
                // MAX_BLOCK_WEIGHT - at which point the miner's own validity
                // check refuses it and no block is produced at all.
                const int64_t nPayoutWeight = GetTransactionWeight(wtx);
                const int64_t nPayoutSigOps = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(CTransaction(wtx));
                if (nBlockWeight + nPayoutWeight >= nBlockMaxWeight ||
                        nBlockSigOpsCost + nPayoutSigOps >= MAX_BLOCK_SIGOPS_COST) {
                    LogPrintf("%s: Deferring Withdrawal payout for sidechain %u (%u weight) - no room in the block.\n",
                            __func__, s.nSidechain, nPayoutWeight);
                    continue;
                }

                LogPrintf("%s: Created Withdrawal payout for sidechain: %u with: %u outputs!\ntxid: %s.\n",
                        __func__, s.nSidechain, wtx.vout.size(), wtx.GetHash().ToString());
                vWithdrawal.push_back(wtx);
                setSidechainsWithWithdrawal.insert(s.nSidechain);

                nWithdrawalFees += nFee;
                nBlockSerializedSize += nPayoutSize;
                nBlockWeight += nPayoutWeight;
                nBlockSigOpsCost += nPayoutSigOps;
            }
        }
    }

    // A transaction the node's operator has placed by hand, taken from
    // -blockplacetx=<hex> rather than from the memory pool.
    //
    // Some transactions are consensus-valid and cannot be relayed (relay
    // policy refuses them by design). A miner willing to place such a
    // transaction does not consult a memory pool; this is that miner's
    // hands, and nothing more.
    //
    // It suspends NO check. The transaction is placed in the block and then
    // judged by every rule that judges any block, including TestBlockValidity
    // below. If it is invalid the block is invalid, which is the correct
    // outcome and the reason this is safe to have on a mainnet node in a way
    // that -drivechainpolicybypass is not: that flag makes a node accept what
    // it would otherwise turn away, while this one only decides what goes in a
    // template the network still gets to reject.
    //
    // It is judged and charged to the block's budgets HERE, before the
    // package selection, and appended to the block after it.
    //
    // Charged first so that the memory pool gives way to it, rather than
    // taking its bytes out of the allowance left to whoever finishes the
    // template (SMALL_BLOCK_MINER_ALLOWANCE_BYTES, which is promised as free
    // space). A placement the small-block budget has no room for even before
    // selection is refused here, by the test addPackageTxs applies to a
    // package, instead of being built into a template that is over budget.
    //
    // Appended after the package selection and before the coinbase, where it
    // always was: the coinbase pays out nFees, and both the witness commitment
    // and the SCDB commitment are computed from the finished transaction list
    // further down. Appending afterwards would leave the block committing to a
    // state that does not include this transaction, which the SCDB commitment
    // flag day would then reject. None of the checks below reads anything the
    // selection changes - the coin view is the chain's, and the memory pool is
    // locked for the whole build - so making them first decides nothing
    // differently.
    uint256 hashPlaced;
    CTransactionRef txPlaced;
    CAmount nPlaceFee = 0;
    const std::string strPlaceTx = fPlacementDisabled
            ? "" : gArgs.GetArg("-blockplacetx", "");
    if (!strPlaceTx.empty()) {
        // Every failure below drops the transaction and builds the block
        // WITHOUT it. It must never throw: this runs on a mining node, and a
        // template that cannot be built stops block production entirely.
        std::string strPlaceFail;
        CMutableTransaction placed;
        if (!IsHex(strPlaceTx) || !DecodeHexTx(placed, strPlaceTx)) {
            strPlaceFail = "it is not a decodable transaction";
        } else {
            const CTransaction tx(placed);
            CValidationState txState;
            CCoinsViewCache view(pcoinsTip.get());
            CAmount nValueIn = 0;
            if (!CheckTransaction(tx, txState)) {
                // Drop a structurally invalid placement here rather than let it
                // reach the coin-view walk below (and, past the commitment flag
                // day, the SCDB commitment simulation): UpdateCoins asserts that
                // every input spends a coin, so a duplicate input would abort
                // the miner rather than fail gracefully. Every transaction in a
                // connected block has passed this check; a hand-placed one has
                // not until here.
                strPlaceFail = "it is not a valid transaction";
            } else if (tx.IsCoinBase()) {
                strPlaceFail = "it is a coinbase";
            } else if (!view.HaveInputs(tx)) {
                strPlaceFail = "its inputs are missing or already spent";
            } else {
                // Sum the input value and, alongside it, the sidechain
                // treasury value this transaction spends. A transaction that
                // takes more out of a sidechain than it returns is a
                // withdrawal, which ConnectBlock routes through SpendWithdrawal
                // by the same amountSidechainIn > amountSidechainOut test.
                CAmount amountSidechainIn = 0;
                uint8_t nSidechainDummy;
                for (const CTxIn& in : tx.vin) {
                    const CTxOut& prev = view.AccessCoin(in.prevout).out;
                    nValueIn += prev.nValue;
                    if (prev.scriptPubKey.IsDrivechain(nSidechainDummy))
                        amountSidechainIn += prev.nValue;
                }
                CAmount amountSidechainOut = 0;
                for (const CTxOut& out : tx.vout) {
                    if (out.scriptPubKey.IsDrivechain(nSidechainDummy))
                        amountSidechainOut += out.nValue;
                }

                // GetValueOut throws when an output value is outside the money
                // range. It must not escape: this block promises never to
                // throw, because a template that cannot be built stops block
                // production. Drop the placement instead.
                CAmount nValueOut = 0;
                bool fValueOutOfRange = false;
                try {
                    nValueOut = tx.GetValueOut();
                } catch (const std::runtime_error&) {
                    fValueOutOfRange = true;
                }

                if (fValueOutOfRange) {
                    strPlaceFail = "its output values are out of range";
                } else if (nValueIn < nValueOut) {
                    strPlaceFail = "it spends more than it takes in";
                } else if (amountSidechainIn > amountSidechainOut) {
                    // A withdrawal payout. Those are assembled from an approved
                    // bundle so they enter the SCDB commitment simulation below;
                    // a hand-placed one is invisible to it, and once the
                    // commitment flag day is active this node would commit a
                    // hash its own ConnectBlock then rejects. A re-chaining
                    // deposit - the intended use - returns at least what it
                    // spends and is not caught by this.
                    strPlaceFail = "it is a withdrawal payout, which must come "
                                   "from an approved bundle to be committed to";
                } else if (mempool.exists(tx.GetHash())) {
                    // The memory pool holds it, so addPackageTxs below can
                    // select it, and placing it as well would duplicate it
                    // and invalidate the block.
                    strPlaceFail = "it is in the memory pool, which selects it";
                } else {
                    // What AddToBlock charges for a selected transaction: its
                    // own bytes in the enforced measure, and what a critical
                    // data transaction makes the miner append beside it (the
                    // h* commitment in the coinbase and its input in the
                    // critical fee transaction). Zero for the re-chaining
                    // deposit this exists for.
                    const uint64_t nPlaceBytes = GetChargedSerializedSize(tx) + SmallBlockCriticalTxReserveBytes(tx);
                    if (fEnforceSmallBlock && nBlockSerializedSize + nPlaceBytes > MAX_SMALL_BLOCK_SERIALIZED_SIZE) {
                        // nBlockSerializedSize holds, at this point, the block
                        // frame and coinbase, the state commitments, the miner
                        // allowance and any withdrawal payout.
                        strPlaceFail = strprintf("it does not fit a small block: it is charged %u bytes and %u are free "
                                                 "beside the coinbase, its commitments, the withdrawal payouts and "
                                                 "the %u bytes left to the miner",
                                                 nPlaceBytes,
                                                 MAX_SMALL_BLOCK_SERIALIZED_SIZE - std::min<uint64_t>(nBlockSerializedSize, MAX_SMALL_BLOCK_SERIALIZED_SIZE),
                                                 SMALL_BLOCK_MINER_ALLOWANCE_BYTES);
                    } else {
                        // The weight and sigop budgets are charged here too, so
                        // the selection leaves room in them, but they are not
                        // grounds to refuse: both start from reservations that
                        // are deliberately generous, and a placement they
                        // would turn away can still make a valid block. As
                        // before, consensus judges that below and an invalid
                        // block is rebuilt without the placement.
                        int64_t nPlaceWeight = GetTransactionWeight(tx);
                        int64_t nPlaceSigOpsCost = GetLegacySigOpCount(tx) * WITNESS_SCALE_FACTOR;
                        AddCriticalDataOverhead(tx, nPlaceWeight, nPlaceSigOpsCost);
                        nBlockWeight += nPlaceWeight;
                        nBlockSerializedSize += nPlaceBytes;
                        nBlockSigOpsCost += nPlaceSigOpsCost;
                        txPlaced = MakeTransactionRef(tx);
                        nPlaceFee = nValueIn - nValueOut;
                    }
                }
            }
        }
        if (!strPlaceFail.empty()) {
            LogPrintf("%s: REFUSING to place -blockplacetx: %s. Building the "
                      "block without it.\n", __func__, strPlaceFail);
        }
    }

    int nPackagesSelected = 0;
    int nDescendantsUpdated = 0;
    bool fNeedCriticalFeeTx = false;
    // 0.45.2: one BMM request per slot,
    // the best-ranked one whose whole cost fits the block. The winner used to
    // be picked by fee + bid alone, and the assembler excluded every other
    // request for its slot; a winner that could not be placed - 1,000 OP_TRUE
    // bid outputs cost 1,000 x (10 + 41) bytes with their collection inputs,
    // more than a whole small block - left the slot with no BMM in the block,
    // a free way to deny a sidechain its blocks. Now a request that cannot fit
    // never competes, and when the chosen one is still not placed (the block
    // filled up with better-paying packages first) the next candidate for that
    // slot gets a further pass. Template policy only: consensus allows one
    // request per slot, any one.
    std::set<uint8_t> setBMMSlotTaken;
    std::set<uint256> setBMMTried;
    for (int nBMMPass = 0; ; ++nBMMPass) {
        const std::map<uint8_t, uint256> mapPick = fDrivechainEnabled ?
                PickBMMRequests(mapBMMRanked, setBMMSlotTaken, setBMMTried) : std::map<uint8_t, uint256>();
        // The first pass selects every package; a further one only runs to
        // place a fallback request.
        if (nBMMPass > 0 && mapPick.empty())
            break;
        std::set<uint256> setBMMChosen;
        for (const auto& p : mapPick) {
            setBMMChosen.insert(p.second);
            setBMMTried.insert(p.second);
        }
        if (nBMMPass > 0) {
            LogPrint(BCLog::BENCH, "%s: BMM fallback pass %d for %u slot(s)\n", __func__, nBMMPass, mapPick.size());
        }
        // No deposit into a slot paid out in this block, nor into one whose
        // replacement is due in it (see setReplacementDue).
        std::set<uint8_t> setNoDeposit = setSidechainsWithWithdrawal;
        setNoDeposit.insert(setReplacementDue.begin(), setReplacementDue.end());
        addPackageTxs(nPackagesSelected, nDescendantsUpdated, fDrivechainEnabled, fNeedCriticalFeeTx, setNoDeposit, setBMMChosen, setBMMSlotTaken);
        bool fMissed = false;
        for (const auto& p : mapPick) {
            if (!setBMMSlotTaken.count(p.first))
                fMissed = true;
        }
        // Each further pass walks the memory pool again, so they are capped.
        if (!fMissed || nBMMPass >= MAX_BMM_FALLBACK_PASSES)
            break;
    }

    // The hand-placed transaction goes in after the selected packages. Its
    // bytes, weight and sigops were charged before the selection.
    if (txPlaced) {
        pblock->vtx.emplace_back(txPlaced);
        pblocktemplate->vTxFees.push_back(nPlaceFee);
        pblocktemplate->vTxSigOpsCost.push_back(
                GetLegacySigOpCount(*txPlaced) * WITNESS_SCALE_FACTOR);
        ++nBlockTx;
        nFees += nPlaceFee;
        hashPlaced = txPlaced->GetHash();
        LogPrintf("%s: PLACED operator transaction %s by hand, fee %d. "
                  "It was not relayed and is judged only by consensus.\n",
                  __func__, hashPlaced.ToString(), nPlaceFee);
    }

    int64_t nTime1 = GetTimeMicros();

    nLastBlockTx = nBlockTx;

    // Create coinbase transaction.
    CMutableTransaction coinbaseTx;
    coinbaseTx.vin.resize(1);
    coinbaseTx.vin[0].prevout.SetNull();
    coinbaseTx.vout.resize(1);
    coinbaseTx.vout[0].scriptPubKey = scriptPubKeyIn;

    // Coinbase subsidy + fees
    coinbaseTx.vout[0].nValue = nWithdrawalFees + nFees + GetBlockSubsidy(nHeight, chainparams.GetConsensus());
    coinbaseTx.vin[0].scriptSig = CScript() << nHeight << OP_0;

    // Add coinbase to block
    pblock->vtx[0] = MakeTransactionRef(std::move(coinbaseTx));

    // Measured so that what the commitments below take can be compared with
    // what was reserved for them before transaction selection.
    const uint64_t nCoinbaseOutBytesBefore = CoinbaseOutputBytes(*pblock);
    uint64_t nCriticalCommitmentBytes = 0;

    // Commit new withdrawals which we have received locally: the ones looked
    // up before transaction selection, in the order of the active sidechains.
    for (const Sidechain& s : vActiveSidechain) {
        const std::map<uint8_t, uint256>::const_iterator it = mapNewWithdrawal.find(s.nSidechain);
        if (it == mapNewWithdrawal.end())
            continue;

        // A slot cleared by this block's
        // activation step belongs to the incoming sidechain once the step has
        // run, so a new bundle committed for it here would be tracked under
        // the new occupant. The outgoing sidechain's bundle is not committed.
        if (setClearedByActivation.count(s.nSidechain)) {
            LogPrintf("%s: not committing a new withdrawal for sidechain %u - its replacement activates in this block\n",
                      __func__, s.nSidechain);
            continue;
        }

        const uint256& hash = it->second;

        GenerateWithdrawalHashCommitment(*pblock, hash, s.nSidechain);

        LogPrintf("%s: Miner found new withdrawal: %u : %s at height %u.\n", __func__, s.nSidechain, hash.ToString(), nHeight);
    }

    // Handle Withdrawal updates
    if (fDrivechainEnabled && scdb.HasState()) {
        // Get withdrawal vote settings
        std::vector<std::string> vVote = scdb.GetVotes();

        // Build the bytes against the
        // state ParseSCDBBytes will read them against, which has no entry for
        // a slot in setClearedByActivation. From the pre-block state the bytes
        // carried one pair too many and the block was invalid.
        std::vector<std::vector<SidechainWithdrawalState>> vOldScores;
        for (const Sidechain& s : vActiveSidechain) {
            if (setClearedByActivation.count(s.nSidechain))
                continue;
            std::vector<SidechainWithdrawalState> vWithdrawal = scdb.GetState(s.nSidechain);
            if (vWithdrawal.size())
                vOldScores.push_back(vWithdrawal);
        }

        // When the only slots with bundles are
        // cleared by this block's activation step there is nothing to vote
        // on, and no M4 output is written at all. ApplyUpdate then reads no
        // update bytes and applies the default abstain votes, which is valid
        // whether or not the block also commits a new bundle. Writing the
        // bare M4 header instead failed the parse check below, and
        // CreateNewBlock threw at that height on every node.
        if (vOldScores.empty()) {
            LogPrintf("%s: no scdb bytes at height %u - no slot keeps bundles after this block's activation step\n",
                      __func__, nHeight);
        } else {
            LogPrintf("%s: Miner generating scdb bytes at height %u.\n", __func__, nHeight);
            CScript script;
            if (!GenerateSCDBByteCommitment(*pblock, script, vOldScores, vVote)) {
                LogPrintf("%s: Miner failed to generate scdb bytes at height %u.\n", __func__, nHeight);
                throw std::runtime_error(strprintf("%s: Miner failed to generate scdb bytes at height %u.\n",
                                                   __func__, nHeight));
            }

            // Make sure that we can read the update bytes
            std::vector<std::string> vVoteParsed;
            if (!ParseSCDBBytes(script, vOldScores, vVoteParsed)) {
                LogPrintf("%s: Miner failed to parse its own scdb bytes at height %u.\n", __func__, nHeight);
                throw std::runtime_error(strprintf("%s: Miner failed to parse its own update bytes at height %u.\n",
                                                   __func__, nHeight));
            }
        }
    }

    if (fDrivechainEnabled) {
        // Generate critical hash commitments (usually for BMM commitments)
        const uint64_t nBeforeCritical = CoinbaseOutputBytes(*pblock);
        GenerateCriticalHashCommitments(*pblock);
        nCriticalCommitmentBytes = CoinbaseOutputBytes(*pblock) - nBeforeCritical;

        // Scan through our sidechain proposals and commit the first one we find
        // that hasn't already been committed and is tracked by SCDB.
        //
        // If we commit a proposal, save the hash to easily ACK it later
        uint256 hashProposal;
        std::vector<Sidechain> vProposal = scdb.GetSidechainProposals();
        if (!vProposal.empty()) {
            for (const Sidechain& p : vProposal) {
                // Skip a proposal already pending, or identical to its slot's
                // active sidechain: from the fork consensus does not track it
                // again (IsSidechainProposalKnown), and below it a copy would
                // only add a second entry or a self-replacement.
                if (scdb.IsSidechainProposalKnown(p))
                    continue;

                // Proposal commitments live in the coinbase, which has a fixed
                // reserve. Skip one too large to leave room for the rest.
                // Must stay the same test the reserve above was computed from,
                // or the block outgrows what was set aside for it.
                if (IsSidechainProposalTooLarge(p)) {
                    LogPrintf("%s: Skipping sidechain proposal %s - too large for the coinbase!\n",
                            __func__, p.GetSerHash().ToString());
                    continue;
                }

                GenerateSidechainProposalCommitment(*pblock, p);
                hashProposal = p.GetSerHash();
                LogPrintf("%s: Generated sidechain proposal commitment for:\n%s\n", __func__, p.ToString());
                break;
            }
        }

        // Commit sidechain activation for the proposals in vActivationCommit,
        // chosen before the payouts.
        for (const uint256& hashActivation : vActivationCommit)
            GenerateSidechainActivationCommitment(*pblock, hashActivation);
    }

    // What the state commitments took against what was reserved for them. The
    // two are computed from the same state under one lock; a difference means
    // the commit code above and SmallBlockCoinbaseCommitmentBytes have drifted
    // apart. It is not fatal while it stays inside the miner allowance - the
    // size check below is the backstop - but it must not pass unnoticed.
    uint64_t nStateCommitmentUsed = CoinbaseOutputBytes(*pblock) - nCoinbaseOutBytesBefore - nCriticalCommitmentBytes;
    if (nHeight >= chainparams.GetConsensus().SCDBCommitmentHeight)
        nStateCommitmentUsed += SCDB_COMMITMENT_BYTES; // appended last, below
    if (fEnforceSmallBlock && nStateCommitmentUsed > nStateCommitmentReserve) {
        LogPrintf("%s: ERROR: coinbase state commitments take %u bytes but %u were reserved - the reserve is out of step with the commit code\n",
                __func__, nStateCommitmentUsed, nStateCommitmentReserve);
    }

    // TODO reserve room when selecting txns so that there's always space for
    // the Withdrawal(s)
    // Add Withdrawal(s) that we created earlier to the block
    // Non-const so the move below actually moves: std::move on a const
    // reference yields a const rvalue, which binds to the copy constructor.
    // vWithdrawal is not read again after this loop.
    //
    // The SCDB commitment simulation discovers these payouts from the finished
    // block itself, so no parallel index is kept here.
    for (size_t i = 0; i < vWithdrawal.size(); i++) {
        pblock->vtx.push_back(MakeTransactionRef(std::move(vWithdrawal[i])));
        // vTxFees / vTxSigOpsCost are kept parallel to vtx: getblocktemplate
        // indexes them by the transaction's position, so every transaction
        // appended here needs its own entry or that RPC reads past the end.
        // A withdrawal payout pays no fee (it spends the sidechain's CTIP).
        pblocktemplate->vTxFees.push_back(0);
        pblocktemplate->vTxSigOpsCost.push_back(
                WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx.back()));
    }

    // Handle / create critical fee tx (collects bmm / critical data fees)
    if (fDrivechainEnabled && fNeedCriticalFeeTx) {
        fAddedBMM = true;
        // Create critical fee tx
        CMutableTransaction feeTx;
        feeTx.vout.resize(1);
        // Pay the fees to the same script as the coinbase, or to -bmmfeescript
        feeTx.vout[0].scriptPubKey = CriticalFeeScript(scriptPubKeyIn);
        feeTx.vout[0].nValue = CAmount(0);

        // A bid output is claimable only if nothing else in this block already
        // claims it. The output is a bare OP_TRUE, which anyone can spend
        // without a signature, so a transaction spending one relays normally
        // and can be selected into the same block as the request that created
        // it. Taking it twice makes the assembled block spend a coin that is
        // already gone, which fails validation and stops template creation
        // entirely - for free, since a block that is never mined pays no fees.
        std::set<COutPoint> setSpent;
        for (const CTransactionRef& tx : pblock->vtx) {
            if (!tx)
                continue;
            for (const CTxIn& txin : tx->vin)
                setSpent.insert(txin.prevout);
        }

        // Find all of the critical data transactions included in the block
        // and take their input and total amount
        for (const CTransactionRef& tx : pblock->vtx) {
            if (tx && !tx->criticalData.IsNull()) {
                // Try to find the critical data fee output and take it
                for (uint32_t i = 0; i < tx->vout.size(); i++) {
                    if (tx->vout[i].scriptPubKey == CScript() << OP_TRUE) {
                        const COutPoint out(tx->GetHash(), i);
                        if (setSpent.count(out))
                            continue;
                        feeTx.vin.push_back(CTxIn(out));
                        feeTx.vout[0].nValue += tx->vout[i].nValue;
                    }
                }
            }
        }

        // TODO calculate the fee tx as part of the block's txn package so that
        // we always make room for it.
        //
        // Add the fee tx to the block if we can
        if (CTransaction(feeTx).GetValueOut()) {
            // Check if block weight after adding transaction would be too large.
            //
            // Measure the block rather than consulting the budget. The budget
            // carries reservations - the coinbase allowance, the per-sidechain
            // commitments, one input here per critical data transaction - and
            // testing against it would refuse this transaction on a full block
            // for room that was set aside for this transaction. It exists to
            // collect the bids, so a false refusal hands them back.
            //
            // The margin covers what is still to be appended after this point:
            // the witness commitment, the SCDB hash commitment once its height
            // is reached, and the extra nonce the miner grows in the coinbase
            // scriptSig after the template is handed over.
            const int64_t nFeeTxWeight = GetTransactionWeight(feeTx);
            const int64_t nFeeTxSigOpsCost = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(CTransaction(feeTx));
            bool fRoom = GetBlockWeight(*pblock) + nFeeTxWeight + COINBASE_FINALIZE_RESERVE_WEIGHT <= MAX_BLOCK_WEIGHT &&
                    (nBlockSigOpsCost + nFeeTxSigOpsCost) < MAX_BLOCK_SIGOPS_COST;
            // Small-block soft fork: also check the actual serialized size of
            // the block assembled so far, leaving margin for what is still
            // appended to the coinbase below: the witness commitment output,
            // its witness nonce, the extranonce the miner grows in the
            // scriptSig, and - from SCDBCommitmentHeight - the SCDB hash
            // commitment, which no fixed margin sized before it can cover.
            if (fRoom && fEnforceSmallBlock) {
                uint64_t nFinalizeMargin = 128;
                if (nHeight >= chainparams.GetConsensus().SCDBCommitmentHeight)
                    nFinalizeMargin += SCDB_COMMITMENT_BYTES;
                fRoom = GetCommittedSerializedSize(*pblock) +
                        GetChargedSerializedSize(CTransaction(feeTx)) + nFinalizeMargin <= MAX_SMALL_BLOCK_SERIALIZED_SIZE;
            }
            if (fRoom) {
                pblock->vtx.push_back(MakeTransactionRef(std::move(feeTx)));
                pblocktemplate->vTxSigOpsCost.push_back(WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx.back()));
                pblocktemplate->vTxFees.push_back(0);
                nBlockWeight += nFeeTxWeight;
                nBlockSigOpsCost += nFeeTxSigOpsCost;
            } else {
                LogPrintf("%s: Miner could not add BMM fee tx, not enough room in block ", __func__);
            }
        }
    }

    pblocktemplate->vchCoinbaseCommitment = GenerateCoinbaseCommitment(*pblock, pindexPrev, chainparams.GetConsensus());
    pblocktemplate->vTxFees[0] = -nFees;

    // Every failure point from here down can be caused by the one input the
    // node's operator chose and consensus has not yet judged: the hand-placed
    // transaction. At all three points the answer is the same - drop the
    // placement and rebuild - because a placed transaction that conflicts
    // with a mempool-selected one would otherwise stop getblocktemplate
    // answering at all, and a mining outage is worse than a missing placement.
    //
    // The retry cannot loop: it sets fPlacementDisabled, which empties
    // strPlaceTx in the nested call, so the nested build leaves hashPlaced
    // null and CanRetryWithoutPlacement() is false there.
    auto CanRetryWithoutPlacement = [&]() {
        return !hashPlaced.IsNull() && !fPlacementDisabled;
    };
    auto RetryWithoutPlacement = [&](const std::string& strWhy) {
        LogPrintf("%s: the block carrying hand-placed %s is INVALID (%s). "
                  "Dropping it and rebuilding WITHOUT it - block production "
                  "continues, but -blockplacetx did NOT take. Fix the "
                  "transaction; do not assume it was mined.\n",
                  __func__, hashPlaced.ToString(), strWhy);
        // Restored on the way out however the nested build ends. It used to
        // be cleared only on the success path, so a nested build that threw
        // left the flag set and this assembler silently refusing every later
        // placement. That was reachable from one caller before and is
        // reachable from three now.
        fPlacementDisabled = true;
        std::unique_ptr<CBlockTemplate> retried;
        try {
            retried = CreateNewBlock(scriptPubKeyIn, fMineWitnessTx, fAddedBMM);
        } catch (...) {
            fPlacementDisabled = false;
            throw;
        }
        fPlacementDisabled = false;
        return retried;
    };

    // SCDB commitment soft fork, the miner's half: commit to the hash of the
    // sidechain state this block produces. Generated LAST - every transaction
    // and every other coinbase output above changes the state being committed
    // to, so nothing may be appended after it. Appending it after its own
    // simulation is sound because the tag is unknown to Update's parsers: the
    // output cannot change the state it commits to. Nonce iteration and
    // extranonce rolling cannot invalidate it by construction (the committed
    // form is invariant under the block hash), but pool software that strips
    // or reorders coinbase outputs would mine invalid blocks - the same
    // exposure the update-bytes and activation commitments already carry.
    if (nHeight >= chainparams.GetConsensus().SCDBCommitmentHeight) {
        uint256 hashCommitment;
        if (!ComputeSCDBCommitment(*pblock, pindexPrev, hashCommitment)) {
            // The simulation walks every transaction in the assembled block,
            // so a placed transaction that CheckTransaction refuses, whose
            // inputs the view does not hold (the conflict case), or whose
            // withdrawal spend the SCDB rejects, fails here - before the
            // rebuild path at the end of this function could ever be reached.
            if (CanRetryWithoutPlacement())
                return RetryWithoutPlacement("the SCDB commitment could not be computed over it");
            throw std::runtime_error(strprintf("%s: failed to compute SCDB commitment", __func__));
        }
        GenerateSCDBHashCommitment(*pblock, hashCommitment);
    }

    // Report what was assembled, not what was budgeted. The budget carries
    // reservations for coinbase commitments that may not all be used, and it
    // is captured before the payouts and the fee transaction are appended, so
    // reading it back would misreport in both directions.
    nLastBlockWeight = GetBlockWeight(*pblock);

    // Small-block soft fork: the reservations above should guarantee this
    // never triggers; if the coinbase somehow outgrew its reserve the block
    // would be rejected by consensus, so fail loudly here instead of mining
    // a doomed block. TestBlockValidity below would also catch this.
    if (fEnforceSmallBlock) {
        const uint64_t nSerializedSize = GetCommittedSerializedSize(*pblock);
        if (nSerializedSize > MAX_SMALL_BLOCK_SERIALIZED_SIZE) {
            LogPrintf("%s: ERROR: assembled block is %u committed bytes > MAX_SMALL_BLOCK_SERIALIZED_SIZE! Coinbase reserve exceeded?\n",
                    __func__, nSerializedSize);
            // A hand-placed transaction is not held to the 40,000-byte
            // standardness cap - placement exists precisely to carry what
            // relay will not - so it is the one input that can push the
            // assembled block past the limit. Same trade as above: drop it and
            // keep producing blocks. If the block is still oversize without
            // it, the nested build throws and the operator gets the loud
            // failure this branch was written for.
            if (CanRetryWithoutPlacement())
                return RetryWithoutPlacement(strprintf("the assembled block is %u bytes, over the small-block limit", nSerializedSize));
            throw std::runtime_error(strprintf("%s: assembled block exceeds MAX_SMALL_BLOCK_SERIALIZED_SIZE", __func__));
        }
        LogPrintf("%s: small block committed=%u budget=%u state_reserved=%u state_used=%u critical_commit=%u allowance=%u\n",
                __func__, nSerializedSize, nBlockSerializedSize, nStateCommitmentReserve, nStateCommitmentUsed,
                nCriticalCommitmentBytes, SMALL_BLOCK_MINER_ALLOWANCE_BYTES);
    }

    // Fill in header
    pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
    UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev);
    pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock, chainparams.GetConsensus());
    pblock->nNonce         = 0;
    pblocktemplate->vTxSigOpsCost[0] = WITNESS_SCALE_FACTOR * GetLegacySigOpCount(*pblock->vtx[0]);

    LogPrintf("CreateNewBlock(): block weight: %u txs: %u fees: %ld sigops %d\n", GetBlockWeight(*pblock), nBlockTx, nFees, nBlockSigOpsCost);

    CValidationState state;
    if (!TestBlockValidity(state, chainparams, *pblock, pindexPrev, false, false)) {
        // The last of the three points, and the one that always behaved this
        // way; the other two were brought up to it rather than the other way
        // round.
        if (CanRetryWithoutPlacement())
            return RetryWithoutPlacement(FormatStateMessage(state));
        throw std::runtime_error(strprintf("%s: TestBlockValidity failed: %s", __func__, FormatStateMessage(state)));
    }
    int64_t nTime2 = GetTimeMicros();

    LogPrint(BCLog::BENCH, "CreateNewBlock() packages: %.2fms (%d packages, %d updated descendants), validity: %.2fms (total %.2fms)\n", 0.001 * (nTime1 - nTimeStart), nPackagesSelected, nDescendantsUpdated, 0.001 * (nTime2 - nTime1), 0.001 * (nTime2 - nTimeStart));

    return std::move(pblocktemplate);
}

void BlockAssembler::onlyUnconfirmed(CTxMemPool::setEntries& testSet)
{
    for (CTxMemPool::setEntries::iterator iit = testSet.begin(); iit != testSet.end(); ) {
        // Only test txs not already in the block
        if (inBlock.count(*iit)) {
            testSet.erase(iit++);
        }
        else {
            iit++;
        }
    }
}

bool BlockAssembler::TestPackage(uint64_t packageSize, int64_t packageSigOpsCost) const
{
    // TODO: switch to weight-based accounting for packages instead of vsize-based accounting.
    if (nBlockWeight + WITNESS_SCALE_FACTOR * packageSize >= nBlockMaxWeight)
        return false;
    if (nBlockSigOpsCost + packageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
        return false;
    return true;
}

// Perform transaction-level checks before adding to block:
// - transaction finality (locktime)
// - premature witness (in case segwit transactions are added to mempool before
//   segwit activation)
// - critical data request height
bool BlockAssembler::TestPackageTransactions(const CTxMemPool::setEntries& package)
{
    for (const CTxMemPool::txiter it : package) {
        if (!IsFinalTx(it->GetTx(), nHeight, nLockTimeCutoff))
            return false;
        if (!fIncludeWitness && it->GetTx().HasWitness())
            return false;
        if (!it->GetTx().criticalData.IsNull()) {
            if (nHeight != (int64_t)it->GetTx().nLockTime + 1)
                return false;
            // A null hash cannot be committed to: the commit this block would
            // write for it is one IsCriticalHashCommit refuses to read back, so
            // consensus rejects the assembled block and no template can be
            // built while the transaction is held. The mempool refuses these,
            // but one can still arrive from a file written by an older build.
            if (it->GetTx().criticalData.hashCritical.IsNull())
                return false;
        }
    }
    return true;
}

void BlockAssembler::AddToBlock(CTxMemPool::txiter iter)
{
    pblock->vtx.emplace_back(iter->GetSharedTx());
    pblocktemplate->vTxFees.push_back(iter->GetFee());
    pblocktemplate->vTxSigOpsCost.push_back(iter->GetSigOpCost());
    nBlockWeight += iter->GetTxWeight();
    nBlockSerializedSize += GetChargedSerializedSize(iter->GetTx());
    nBlockSerializedSize += SmallBlockCriticalTxReserveBytes(iter->GetTx());
    ++nBlockTx;
    nBlockSigOpsCost += iter->GetSigOpCost();

    // The coinbase commitment this transaction obliges us to add later is part
    // of the block too, so charge it to the same budgets. No-op for anything
    // without critical data, which is almost everything.
    int64_t nCommitmentWeight = 0;
    int64_t nCommitmentSigOpsCost = 0;
    AddCriticalDataOverhead(iter->GetTx(), nCommitmentWeight, nCommitmentSigOpsCost);
    nBlockWeight += nCommitmentWeight;
    nBlockSigOpsCost += nCommitmentSigOpsCost;
    nFees += iter->GetFee();
    inBlock.insert(iter);

    bool fPrintPriority = gArgs.GetBoolArg("-printpriority", DEFAULT_PRINTPRIORITY);
    if (fPrintPriority) {
        LogPrintf("fee %s txid %s\n",
                  CFeeRate(iter->GetModifiedFee(), iter->GetTxSize()).ToString(),
                  iter->GetTx().GetHash().ToString());
    }
}

int BlockAssembler::UpdatePackagesForAdded(const CTxMemPool::setEntries& alreadyAdded,
        indexed_modified_transaction_set &mapModifiedTx)
{
    int nDescendantsUpdated = 0;
    for (const CTxMemPool::txiter it : alreadyAdded) {
        CTxMemPool::setEntries descendants;
        mempool.CalculateDescendants(it, descendants);
        // Insert all descendants (not yet in block) into the modified set
        for (CTxMemPool::txiter desc : descendants) {
            if (alreadyAdded.count(desc))
                continue;
            ++nDescendantsUpdated;
            modtxiter mit = mapModifiedTx.find(desc);
            if (mit == mapModifiedTx.end()) {
                CTxMemPoolModifiedEntry modEntry(desc);
                modEntry.nSizeWithAncestors -= it->GetTxSize();
                modEntry.nModFeesWithAncestors -= it->GetModifiedFee();
                modEntry.nSigOpCostWithAncestors -= it->GetSigOpCost();
                mapModifiedTx.insert(modEntry);
            } else {
                mapModifiedTx.modify(mit, update_for_parent_inclusion(it));
            }
        }
    }
    return nDescendantsUpdated;
}

bool BlockAssembler::CreateWithdrawalPayout(uint8_t nSidechain, CMutableTransaction& tx, CAmount& nFees)
{
    // TODO log all false returns

    // The Withdrawal that will be created
    CMutableTransaction mtx;
    mtx.nVersion = 2;

    if (!IsSkydogeEnabled(chainActive.Tip(), chainparams.GetConsensus()))
        return false;

#ifdef ENABLE_WALLET
    if (!scdb.HasState())
        return false;
    if (!scdb.IsSidechainActive(nSidechain))
        return false;

    Sidechain sidechain;
    if (!scdb.GetSidechain(nSidechain, sidechain))
        return false;

    // Select the highest scoring withdrawal for sidechain. There is no
    // "next best" to fall back to under the small-block cap: every block's
    // vote for a slot upvotes one withdrawal and downvotes the rest
    // (SidechainDB::UpdateSCDBIndex), so two withdrawals of one slot can
    // never both hold the threshold score. A withdrawal that no block this
    // node builds could carry must instead be kept OUT of the cache -
    // receivewithdrawalbundle checks it against SmallBlockPayoutRoomBytes.
    uint256 hashBest = uint256();
    uint32_t scoreBest = 0;   // must track SidechainWithdrawalState::nWorkScore's width
    SidechainWithdrawalState stateBest;
    std::vector<SidechainWithdrawalState> vState = scdb.GetState(nSidechain);
    for (const SidechainWithdrawalState& state : vState) {
        if (state.nWorkScore > scoreBest || scoreBest == 0) {
            hashBest = state.hash;
            scoreBest = state.nWorkScore;
            stateBest = state;
        }
    }
    if (hashBest == uint256())
        return false;

    // Does the selected withdrawal have sufficient work score?
    // Use the height-gated threshold for the block being assembled (the payout
    // will be included in the next block). CreateNewBlock holds cs_main across
    // this call, so chainActive.Height() is consistent with the template.
    if (scoreBest < GetSidechainMinWorkScore(chainActive.Height() + 1))
        return false;

    // Never
    // pay a bundle that this very block expires. The spend is checked against
    // the parent state, where the bundle is still there and approved, but the
    // block's own SCDB update removes expired bundles FIRST and then cannot
    // find the spent one to remove (SidechainDB::Update, "Failed to remove
    // spent Withdrawal") - the block is invalid. Reachable whenever a bundle
    // reaches the threshold in the block that also takes its last block left;
    // from SCDBCommitmentHeight the commitment simulation then fails and NO
    // template can be built at that height, below it this node mines a block
    // every node (itself included) rejects. Skipping costs nothing: the
    // bundle is gone after this block whatever is in it.
    if (SidechainDB::WithdrawalExpiresAt(stateBest, chainActive.Height() + 1)) {
        LogPrintf("%s: Not paying withdrawal %s for sidechain %u: it expires in the block being built (blocks left %u, workscore %u).\n",
                  __func__, hashBest.ToString(), nSidechain, stateBest.nBlocksLeft, stateBest.nWorkScore);
        return false;
    }

    // Copy outputs from withdrawal tx
    std::vector<std::pair<uint8_t, CMutableTransaction>> vTx = scdb.GetWithdrawalTxCache();
    for (const std::pair<uint8_t, CMutableTransaction>& pair : vTx) {
        if (pair.second.GetHash() == hashBest) {
            for (const CTxOut& out : pair.second.vout)
                mtx.vout.push_back(out);
            break;
        }
    }
    // Withdrawal should have at least the encoded dest output, encoded fee output,
    // and change return output.
    if (mtx.vout.size() < 3)
        return false;

    // Get the mainchain fee amount from the second Withdrawal output which encodes the
    // sum of withdrawal fees.
    CAmount amountRead = 0;
    if (!DecodeWithdrawalFees(mtx.vout[1].scriptPubKey, amountRead)) {
        LogPrintf("%s: Failed to decode withdrawal fees!\n", __func__);
        return false;
    }
    nFees = amountRead;

    // Calculate the amount to be withdrawn by Withdrawal
    CAmount amountWithdrawn = CAmount(0);
    for (const CTxOut& out : mtx.vout) {
        uint8_t nSidechain;
        if (!out.scriptPubKey.IsDrivechain(nSidechain))
            amountWithdrawn += out.nValue;
    }

    // Add mainchain fees from withdrawal
    amountWithdrawn += nFees;

    // Get sidechain change return script. We will pay the sidechain the change
    // left over from this Withdrawal. This Withdrawal transaction will look like a normal
    // sidechain deposit but with more outputs and the destination string will
    // be SIDECHAIN_WITHDRAWAL_RETURN_DEST.
    CScript sidechainScript;
    if (!scdb.GetSidechainScript(nSidechain, sidechainScript))
        return false;

    // Note: Withdrawal change return must be the final output
    // Add placeholder change return as the final output.
    mtx.vout.push_back(CTxOut(0, sidechainScript));

    // Get sidechain's CTIP
    SidechainCTIP ctip;
    if (!scdb.GetCTIP(nSidechain, ctip))
        return false;

    mtx.vin.push_back(CTxIn(ctip.out));

    LogPrintf("%s: Withdrawal will spend CTIP: %s : %u.\n", __func__,
            ctip.out.hash.ToString(), ctip.out.n);

    // Start calculating amount returning to sidechain
    CAmount returnAmount = ctip.amount;
    mtx.vout.back().nValue += returnAmount;

    // Subtract payout amount from sidechain change return
    mtx.vout.back().nValue -= amountWithdrawn;

    // Zero is refused as well as negative. A treasury output of zero value is
    // outside drivechain's rules - both amount guards are strict inequalities
    // that are false at zero - so it becomes an ordinary anyone-can-spend coin
    // that the first passer-by can destroy, leaving every node pointing at an
    // outpoint that no longer exists and the slot closed in both directions.
    if (mtx.vout.back().nValue <= 0)
        return false;
    if (!mtx.vin.size())
        return false;

    // Check to make sure that all of the outputs in this Withdrawal are unknown / new
    for (size_t o = 0; o < mtx.vout.size(); o++) {
        if (pcoinsTip->HaveCoin(COutPoint(mtx.GetHash(), o))) {
            return false;
        }
    }
#endif

    tx = mtx;

    return true;
}

// Skip entries in mapTx that are already in a block or are present
// in mapModifiedTx (which implies that the mapTx ancestor state is
// stale due to ancestor inclusion in the block)
// Also skip transactions that we've already failed to add. This can happen if
// we consider a transaction in mapModifiedTx and it fails: we can then
// potentially consider it again while walking mapTx.  It's currently
// guaranteed to fail again, but as a belt-and-suspenders check we put it in
// failedTx and avoid re-evaluation, since the re-evaluation would be using
// cached size/sigops/fee values that are not actually correct.
bool BlockAssembler::SkipMapTxEntry(CTxMemPool::txiter it, indexed_modified_transaction_set &mapModifiedTx, CTxMemPool::setEntries &failedTx)
{
    assert (it != mempool.mapTx.end());
    return mapModifiedTx.count(it) || inBlock.count(it) || failedTx.count(it);
}

void BlockAssembler::SortForBlock(const CTxMemPool::setEntries& package, CTxMemPool::txiter entry, std::vector<CTxMemPool::txiter>& sortedEntries)
{
    // Sort package by ancestor count
    // If a transaction A depends on transaction B, then A's ancestor count
    // must be greater than B's.  So this is sufficient to validly order the
    // transactions for block inclusion.
    sortedEntries.clear();
    sortedEntries.insert(sortedEntries.begin(), package.begin(), package.end());
    std::sort(sortedEntries.begin(), sortedEntries.end(), CompareTxIterByAncestorCount());
}

std::map<uint8_t, uint256> BlockAssembler::PickBMMRequests(const std::map<uint8_t, std::vector<uint256>>& mapBMMRanked,
                                                           const std::set<uint8_t>& setBMMSlotTaken,
                                                           const std::set<uint256>& setBMMTried)
{
    std::map<uint8_t, uint256> mapPick;
    for (const auto& slot : mapBMMRanked) {
        if (setBMMSlotTaken.count(slot.first))
            continue;
        for (const uint256& hash : slot.second) {
            if (setBMMTried.count(hash))
                continue;
            CTxMemPool::txiter it = mempool.mapTx.find(hash);
            if (it == mempool.mapTx.end() || inBlock.count(it))
                continue;

            // What addPackageTxs charges for the package that would carry
            // this request: its unconfirmed ancestors not yet in the block
            // and itself, each with its h* commitment and its collection
            // inputs (SmallBlockCriticalTxReserveBytes, AddCriticalDataOverhead).
            CTxMemPool::setEntries ancestors;
            const uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
            std::string dummy;
            mempool.CalculateMemPoolAncestors(*it, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);
            onlyUnconfirmed(ancestors);
            ancestors.insert(it);
            uint64_t nPackageBytes = 0;
            int64_t nPackageWeight = 0;
            int64_t nPackageSigOpsCost = 0;
            for (CTxMemPool::txiter ait : ancestors) {
                nPackageWeight += GetTransactionWeight(ait->GetTx());
                nPackageSigOpsCost += ait->GetSigOpCost();
                AddCriticalDataOverhead(ait->GetTx(), nPackageWeight, nPackageSigOpsCost);
                if (fEnforceSmallBlock) {
                    nPackageBytes += GetChargedSerializedSize(ait->GetTx());
                    nPackageBytes += SmallBlockCriticalTxReserveBytes(ait->GetTx());
                }
            }
            if (fEnforceSmallBlock && nBlockSerializedSize + nPackageBytes > MAX_SMALL_BLOCK_SERIALIZED_SIZE) {
                LogPrint(BCLog::BENCH, "%s: BMM request %s for slot %u cannot fit: charged %u bytes, %u free\n",
                         __func__, hash.ToString(), (unsigned)slot.first, nPackageBytes,
                         MAX_SMALL_BLOCK_SERIALIZED_SIZE - std::min<uint64_t>(nBlockSerializedSize, MAX_SMALL_BLOCK_SERIALIZED_SIZE));
                continue;
            }
            if (nBlockWeight + nPackageWeight >= nBlockMaxWeight ||
                    nBlockSigOpsCost + nPackageSigOpsCost >= MAX_BLOCK_SIGOPS_COST)
                continue;
            mapPick[slot.first] = hash;
            break;
        }
    }
    return mapPick;
}

// This transaction selection algorithm orders the mempool based
// on feerate of a transaction including all unconfirmed ancestors.
// Since we don't remove transactions from the mempool as we select them
// for block inclusion, we need an alternate method of updating the feerate
// of a transaction with its not-yet-selected ancestors as we go.
// This is accomplished by walking the in-mempool descendants of selected
// transactions and storing a temporary modified state in mapModifiedTxs.
// Each time through the loop, we compare the best transaction in
// mapModifiedTxs with the next transaction in the mempool to decide what
// transaction package to work on next.
void BlockAssembler::addPackageTxs(int &nPackagesSelected, int &nDescendantsUpdated, bool fDrivechainEnabled, bool& fNeedCriticalFeeTx, const std::set<uint8_t>& setSidechainsWithWithdrawal, const std::set<uint256>& setBMMChosen, std::set<uint8_t>& setBMMSlotTaken)
{
    // mapModifiedTx will store sorted packages after they are modified
    // because some of their txs are already in the block
    indexed_modified_transaction_set mapModifiedTx;
    // Keep track of entries that failed inclusion, to avoid duplicate work
    CTxMemPool::setEntries failedTx;
    // setBMMSlotTaken: sidechain slots that already have their one BMM
    // request in this block. Kept by the caller across fallback passes.

    // Start by adding all descendants of previously added txs to mapModifiedTx
    // and modifying them for their already included ancestors
    UpdatePackagesForAdded(inBlock, mapModifiedTx);

    CTxMemPool::indexed_transaction_set::index<ancestor_score>::type::iterator mi = mempool.mapTx.get<ancestor_score>().begin();
    CTxMemPool::txiter iter;

    // Limit the number of attempts to add transactions to the block when it is
    // close to full; this is just a simple heuristic to finish quickly if the
    // mempool has a lot of entries.
    const int64_t MAX_CONSECUTIVE_FAILURES = 1000;
    int64_t nConsecutiveFailed = 0;

    while (mi != mempool.mapTx.get<ancestor_score>().end() || !mapModifiedTx.empty())
    {
        // Don't add deposits to the same block as a Withdrawal for this sidechain
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
                mi->IsSidechainDeposit() &&
                setSidechainsWithWithdrawal.count(mi->GetSidechainNumber())) {
            ++mi;
            continue;
        }
        // First try to find a new transaction in mapTx to evaluate.
        if (mi != mempool.mapTx.get<ancestor_score>().end() &&
                SkipMapTxEntry(mempool.mapTx.project<0>(mi), mapModifiedTx, failedTx)) {
            ++mi;
            continue;
        }

        // Now that mi is not stale, determine which transaction to evaluate:
        // the next entry from mapTx, or the best from mapModifiedTx?
        bool fUsingModified = false;

        modtxscoreiter modit = mapModifiedTx.get<ancestor_score>().begin();
        if (mi == mempool.mapTx.get<ancestor_score>().end()) {
            // We're out of entries in mapTx; use the entry from mapModifiedTx
            iter = modit->iter;
            fUsingModified = true;
        } else {
            // Try to compare the mapTx entry to the mapModifiedTx entry
            iter = mempool.mapTx.project<0>(mi);
            if (modit != mapModifiedTx.get<ancestor_score>().end() &&
                    CompareTxMemPoolEntryByAncestorFee()(*modit, CTxMemPoolModifiedEntry(iter))) {
                // The best entry in mapModifiedTx has higher score
                // than the one from mapTx.
                // Switch which transaction (package) to consider
                iter = modit->iter;
                fUsingModified = true;
            } else {
                // Either no entry in mapModifiedTx, or it's worse than mapTx.
                // Increment mi for the next loop iteration.
                ++mi;
            }
        }

        // We skip mapTx entries that are inBlock, and mapModifiedTx shouldn't
        // contain anything that is inBlock.
        assert(!inBlock.count(iter));

        // Fee ordering note: packageSize is the VIRTUAL size, and selection
        // order comes from the mempool's ancestor_score index (fees over that
        // virtual size), while after SmallBlockHeight the block limit counts
        // SERIALIZED bytes. Ordering by serialized size would need a second
        // mempool index; with blocks far below the cap the difference does
        // not matter, and it affects only fee income, never validity.
        uint64_t packageSize = iter->GetSizeWithAncestors();
        CAmount packageFees = iter->GetModFeesWithAncestors();
        int64_t packageSigOpsCost = iter->GetSigOpCostWithAncestors();
        if (fUsingModified) {
            packageSize = modit->nSizeWithAncestors;
            packageFees = modit->nModFeesWithAncestors;
            packageSigOpsCost = modit->nSigOpCostWithAncestors;
        }

        if (packageFees < blockMinFeeRate.GetFee(packageSize)) {
            // Everything else we might consider has a lower fee rate
            return;
        }

        if (!TestPackage(packageSize, packageSigOpsCost)) {
            if (fUsingModified) {
                // Since we always look at the best entry in mapModifiedTx,
                // we must erase failed entries so that we can consider the
                // next best entry on the next loop iteration
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }

            ++nConsecutiveFailed;

            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES && nBlockWeight >
                    nBlockMaxWeight - 4000) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        CTxMemPool::setEntries ancestors;
        uint64_t nNoLimit = std::numeric_limits<uint64_t>::max();
        std::string dummy;
        mempool.CalculateMemPoolAncestors(*iter, ancestors, nNoLimit, nNoLimit, nNoLimit, nNoLimit, dummy, false);

        onlyUnconfirmed(ancestors);
        ancestors.insert(iter);

        // Don't add deposits to the same block as a Withdrawal for this
        // sidechain. The check above only sees the next mapTx entry, so a
        // deposit can still reach the block from mapModifiedTx or by being
        // pulled in as an ancestor of some other transaction. Both the payout
        // and the deposit spend the sidechain's CTIP, so letting one through
        // here would build a template that double-spends it and is rejected.
        // Test the whole package, which is what actually gets added.
        bool fPackageHasExcludedDeposit = false;
        for (CTxMemPool::txiter ait : ancestors) {
            if (ait->IsSidechainDeposit() &&
                    setSidechainsWithWithdrawal.count(ait->GetSidechainNumber())) {
                fPackageHasExcludedDeposit = true;
                break;
            }
        }
        if (fPackageHasExcludedDeposit) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // Competing BMM requests stay in the
        // memory pool, so the assembler itself must keep the block to one
        // request per sidechain - the one PickBMMRequests picked - or every
        // template fails bad-critical-bmm-nsidechain-multiple. A package that
        // carries any other request, or a second one for a slot already in the
        // block, is skipped like an excluded deposit above.
        bool fPackageHasUnchosenBMM = false;
        if (fDrivechainEnabled) {
            std::set<uint8_t> setPackageSlots;
            for (CTxMemPool::txiter ait : ancestors) {
                const CTransaction& atx = ait->GetTx();
                if (atx.criticalData.IsNull())
                    continue;
                uint8_t nSlot;
                std::string strPrev = "";
                if (!atx.criticalData.IsBMMRequest(nSlot, strPrev))
                    continue;
                if (!setBMMChosen.count(atx.GetHash()) || setBMMSlotTaken.count(nSlot) ||
                        !setPackageSlots.insert(nSlot).second) {
                    fPackageHasUnchosenBMM = true;
                    break;
                }
            }
        }
        if (fPackageHasUnchosenBMM) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        if (!TestPackageTransactions(ancestors)) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            continue;
        }

        // Two costs TestPackage() above does not model, re-tested here against
        // the package that will actually be added:
        //
        //  - the coinbase commitment each critical data transaction obliges us
        //    to append (see AddCriticalDataOverhead). AddToBlock charges it,
        //    so it is accounted for by the time the next package is weighed,
        //    but it is not part of this package's own weight or sigop cost and
        //    a single package can hold enough of them to overshoot.
        //  - under the small-block soft fork, exact bytes in the enforced
        //    measure (witness at par, criticalData excluded, the fixed
        //    nVersion-3 charge), which binds there instead of weight.
        //
        // Both loops run over the package rather than the single entry, since
        // the whole package is what gets added.
        uint64_t nPackageSerializedSize = 0;
        int64_t nPackageCommitmentWeight = 0;
        int64_t nPackageCommitmentSigOpsCost = 0;
        for (CTxMemPool::txiter it : ancestors) {
            AddCriticalDataOverhead(it->GetTx(), nPackageCommitmentWeight, nPackageCommitmentSigOpsCost);
            if (fEnforceSmallBlock) {
                nPackageSerializedSize += GetChargedSerializedSize(it->GetTx());
                nPackageSerializedSize += SmallBlockCriticalTxReserveBytes(it->GetTx());
            }
        }

        // Repeats TestPackage()'s two comparisons with the commitments folded
        // in, so a package carrying none is judged exactly as before.
        const bool fOverBudget =
                nBlockWeight + WITNESS_SCALE_FACTOR * packageSize + nPackageCommitmentWeight >= nBlockMaxWeight ||
                nBlockSigOpsCost + packageSigOpsCost + nPackageCommitmentSigOpsCost >= MAX_BLOCK_SIGOPS_COST;
        const bool fOverSmallBlock = fEnforceSmallBlock &&
                nBlockSerializedSize + nPackageSerializedSize > MAX_SMALL_BLOCK_SERIALIZED_SIZE;

        if (fOverBudget || fOverSmallBlock) {
            if (fUsingModified) {
                mapModifiedTx.get<ancestor_score>().erase(modit);
                failedTx.insert(iter);
            }
            ++nConsecutiveFailed;
            if (nConsecutiveFailed > MAX_CONSECUTIVE_FAILURES &&
                    (nBlockWeight > nBlockMaxWeight - 4000 ||
                     (fEnforceSmallBlock &&
                      nBlockSerializedSize > MAX_SMALL_BLOCK_SERIALIZED_SIZE - 4000))) {
                // Give up if we're close to full and haven't succeeded in a while
                break;
            }
            continue;
        }

        // This transaction will make it in; reset the failed counter.
        nConsecutiveFailed = 0;

        // Package can be added. Sort the entries in a valid order.
        std::vector<CTxMemPool::txiter> sortedEntries;
        SortForBlock(ancestors, iter, sortedEntries);

        for (size_t i=0; i<sortedEntries.size(); ++i) {
            AddToBlock(sortedEntries[i]);
            // Erase from the modified set, if present
            mapModifiedTx.erase(sortedEntries[i]);

            // Set fNeedCriticalFeeTx
            if (fDrivechainEnabled && sortedEntries[i]->HasCriticalData())
                fNeedCriticalFeeTx = true;

            // This slot now has its one BMM request.
            if (fDrivechainEnabled && sortedEntries[i]->HasCriticalData()) {
                uint8_t nSlot;
                std::string strPrev = "";
                if (sortedEntries[i]->GetTx().criticalData.IsBMMRequest(nSlot, strPrev))
                    setBMMSlotTaken.insert(nSlot);
            }
        }

        ++nPackagesSelected;

        // Update transactions that depend on each of these
        nDescendantsUpdated += UpdatePackagesForAdded(ancestors, mapModifiedTx);
    }
}

void IncrementExtraNonce(CBlock* pblock, const CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    CMutableTransaction txCoinbase(*pblock->vtx[0]);
    txCoinbase.vin[0].scriptSig = (CScript() << nHeight << CScriptNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(txCoinbase.vin[0].scriptSig.size() <= 100);

    pblock->vtx[0] = MakeTransactionRef(std::move(txCoinbase));
    pblock->hashMerkleRoot = BlockMerkleRoot(*pblock);
}

//////////////////////////////////////////////////////////////////////////////
//
// Internal miner
//

//
// ScanHash scans nonces looking for a hash with at least some zero bits.
// The nonce is usually preserved between calls, but periodically or if the
// nonce is 0xffff0000 or above, the block is rebuilt and nNonce starts over at
// zero.
//
bool static ScanHash(const CBlockHeader *pblock, uint32_t& nNonce, uint256 *phash)
{
    // Write the first 76 bytes of the block header to a double-SHA256 state.
    SHAndwich256 hasher;
    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
    ss << *pblock;
    assert(ss.size() == 80);
    hasher.Write((unsigned char*)&ss[0], 76);

    while (true) {
        nNonce++;

        if (nNonce > nMiningNonce)
            nMiningNonce = nNonce;

        // Write the last 4 bytes of the block header (the nonce) to a copy of
        // the double-SHA256 state, and compute the result.
        SHAndwich256(hasher).Write((unsigned char*)&nNonce, 4).Finalize((unsigned char*)phash);

        // Return the nonce if the hash has at least some zero bits,
        // caller will check if it has enough to reach the target
        if (((uint16_t*)phash)[15] == 0)
            return true;

        // If nothing found after trying for a while, return -1
        if ((nNonce & 0xfff) == 0)
            return false;
    }
}

static bool ProcessBlockFound(const CBlock* pblock, const CChainParams& chainparams)
{
    LogPrintf("%s\n", pblock->ToString());
    LogPrintf("generated %s\n", FormatMoney(pblock->vtx[0]->vout[0].nValue));

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != chainActive.Tip()->GetBlockHash())
            return error("BitcoinMiner: generated block is stale");
    }

    // Inform about the new block
    GetMainSignals().BlockFound(pblock->GetHash());

    // Process this block the same as if we had received it from another node
    std::shared_ptr<const CBlock> block = std::make_shared<CBlock>(*pblock);
    CValidationState state;
    if (!ProcessNewBlock(Params(), block, true, nullptr))
        return error("BitcoinMiner: ProcessNewBlock, block not accepted");

    return true;
}

void static BitcoinMiner(const CChainParams& chainparams)
{
    LogPrintf("BitcoinMiner started\n");
    //SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("skydoge-miner");

    unsigned int nExtraNonce = 0;

    if (vpwallets.empty())
        return; // TODO error message

    std::shared_ptr<CReserveScript> coinbaseScript;
    vpwallets[0]->GetScriptForMining(coinbaseScript);

    bool fBreakForBMM = gArgs.GetBoolArg("-minerbreakforbmm", false);
    int nBMMBreakAttempts = 0;

    try {
        // Throw an error if no script was provided.  This can happen
        // due to some internal error but also if the keypool is empty.
        // In the latter case, already the pointer is NULL.
        if (!coinbaseScript || coinbaseScript->reserveScript.empty())
            throw std::runtime_error("No coinbase script available (mining requires a wallet)");

        while (true) {
            if (fMiningReqiresPeer) {
                // Busy-wait for the network to come online so we don't waste time mining
                // on an obsolete chain. In regtest mode we expect to fly solo.
                // TODO
                /*
                do {
                    bool fvNodesEmpty;
                    {
                        LOCK(cs_vNodes);
                        fvNodesEmpty = vNodes.empty();
                    }
                    if (!fvNodesEmpty && !IsInitialBlockDownload())
                        break;
                    MilliSleep(1000);
                } while (true);
                */
            }

            //
            // Create new block
            //
            unsigned int nTransactionsUpdatedLast = mempool.GetTransactionsUpdated();
            // Read the tip under cs_main, as every other caller does, and do not
            // proceed on a null one. chainActive.Tip() is null until the chain is
            // loaded, and this thread can reach here first: the resulting null
            // reached UpdateTime() ~100 lines below and crashed the process.
            CBlockIndex* pindexPrev = nullptr;
            {
                LOCK(cs_main);
                pindexPrev = chainActive.Tip();
            }
            if (pindexPrev == nullptr) {
                MilliSleep(1000);
                continue;
            }

            bool fAddedBMM = false;

            int nMinerSleep = gArgs.GetArg("-minersleep", 0);
            if (nMinerSleep)
                MilliSleep(nMinerSleep);

            std::unique_ptr<CBlockTemplate> pblocktemplate;
            try {
                pblocktemplate = BlockAssembler(Params()).CreateNewBlock(coinbaseScript->reserveScript, true /* mine segwit */, fAddedBMM);
            } catch (const std::runtime_error& e) {
                // Don't let a transient template failure permanently kill the
                // mining thread - log, wait, and try again.
                LogPrintf("Error in BitcoinMiner: CreateNewBlock failed: %s - retrying in 10s\n", e.what());
                MilliSleep(10000);
                continue;
            }
            if (!pblocktemplate.get())
            {
                LogPrintf("Error in BitcoinMiner: Keypool ran out, please call keypoolrefill before restarting the mining thread\n");
                return;
            }
            CBlock *pblock = &pblocktemplate->block;
            IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

            LogPrintf("Running BitcoinMiner with %u transactions in block (%u bytes)\n", pblock->vtx.size(),
                ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

            //
            // Search
            //
            int64_t nStart = GetTime();
            arith_uint256 hashArithTarget = arith_uint256().SetCompact(pblock->nBits);
            hashTarget = ArithToUint256(hashArithTarget);
            hashBest = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            nMiningNonce = 0;
            uint256 hash;
            uint32_t nNonce = 0;
            while (true) {
                // Check if something found
                // if (ScanHash(pblock, nNonce, &hash))
                // {
                //     if (UintToArith256(hash) <= UintToArith256(hashBest))
                //     {
                //         hashBest = hash;
                //     }

                //     if (UintToArith256(hash) <= hashArithTarget)
                //     {
                //         // Found a solution
                //         pblock->nNonce = nNonce;
                //         assert(hash == pblock->GetPoWHash());

                //         LogPrintf("BitcoinMiner:\n");
                //         LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex(), hashArithTarget.GetHex());
                //         ProcessBlockFound(pblock, chainparams);
                //         coinbaseScript->KeepScript();
                //         nBMMBreakAttempts = 0;

                //         break;
                //     }
                // }
                while(true){
                    hash = pblock->GetHash();
                    if (UintToArith256(hash) <= UintToArith256(hashBest))
                    {
                        hashBest = hash;
                    }
                    if (UintToArith256(hash) <= hashArithTarget)
                    {
                        // Found a solution
                        //pblock->nNonce = nNonce;
                        //assert(hash == pblock->GetHash());

                        LogPrintf("BitcoinMiner:\n");
                        LogPrintf("proof-of-work found  \n  hash: %s  \ntarget: %s\n", hash.GetHex(), hashArithTarget.GetHex());
                        ProcessBlockFound(pblock, chainparams);
                        coinbaseScript->KeepScript();
                        nBMMBreakAttempts = 0;
                        break;
                    }

                    pblock->nNonce += 1;
                    if ((pblock->nNonce & 0xFF) == 0)
                        break;      
                }
                

                if (nNonce >= 0xffff0000)
                    break;
                if (mempool.GetTransactionsUpdated() != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                    break;
                if (pindexPrev != chainActive.Tip()) {
                    nBMMBreakAttempts = 0;
                    break;
                }

                // Update nTime every few seconds
                if (UpdateTime(pblock, chainparams.GetConsensus(), pindexPrev) < 0)
                    break; // Recreate the block if the clock has run backwards,
                           // so that we can use the correct time.

                // If the user has set --minerbreakforbmm, and BMM txns were not
                // already added to this block but exist in the mempool, break
                // the miner so that it recreates the block.
                if (fBreakForBMM && !fAddedBMM && nBMMBreakAttempts < 10 &&
                        mempool.GetCriticalTxnAddedSinceBlock()) {
                    nBMMBreakAttempts++;
                    break;
                }

                if (chainparams.GetConsensus().fPowAllowMinDifficultyBlocks)
                {
                    // Changing pblock->nTime can change work required on testnet:
                    hashArithTarget.SetCompact(pblock->nBits);
                }
            }
        }
    }
    catch (const boost::thread_interrupted&)
    {
        LogPrintf("BitcoinMiner terminated\n");
        throw;
    }
    catch (const std::runtime_error &e)
    {
        LogPrintf("BitcoinMiner runtime error: %s\n", e.what());
        return;
    }
}

void GenerateBitcoins(bool fGenerate, int nThreads, const CChainParams& chainparams)
{
    static boost::thread_group* minerThreads = NULL;

    if (nThreads < 0)
        nThreads = GetNumCores();

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nThreads == 0 || !fGenerate)
        return;

    minerThreads = new boost::thread_group();
    for (int i = 0; i < nThreads; i++)
        minerThreads->create_thread(boost::bind(&BitcoinMiner, boost::cref(chainparams)));
}
