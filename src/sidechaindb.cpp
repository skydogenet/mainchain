// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechaindb.h>

#include <chainparams.h> // GetCommitmentHash reads SidechainParamsHeight

#include <consensus/consensus.h>
#include <consensus/merkle.h>
#include <clientversion.h>
#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <sidechain.h>
#include <streams.h>
#include <uint256.h>
#include <util.h>
#include <utilstrencodings.h>

#include <algorithm>
#include <atomic>

/** The one sequence every SidechainDB object draws GetTemplateStateSeq values
 *  from, so that a value is never handed out twice in the life of the
 *  process, whichever object asks. */
static std::atomic<uint64_t> nTemplateStateSeqLast(0);

SidechainDB::SidechainDB()
{
    Reset();
}

void SidechainDB::TemplateStateChanged()
{
    nTemplateStateSeq = ++nTemplateStateSeqLast;
}

void SidechainDB::ApplyLDBData(const uint256& hashBlock, const SidechainBlockData& data)
{
    TemplateStateChanged();
    hashBlockLastSeen = hashBlock;
    vWithdrawalStatus = data.vWithdrawalStatus;
    vActivationStatus = data.vActivationStatus;
    vSidechain = data.vSidechain;

    // Install the treasury from the record, when the record carries one.
    //
    // This is the point of the treasury log: the pointer is restored from the
    // block it belongs to, alongside the withdrawal and activation lists, so it
    // no longer depends on the deposit cache having been written out at
    // shutdown. Records written before the log existed leave the treasury
    // alone, and it is recovered from the deposit cache as it always was.
    //
    // The failure records are restored the same way, which also settles the
    // reorg case that the block index behind mapFailedWithdrawalBlock exists to
    // handle: the parent's record states the failures as of the parent, so
    // rolling back to it needs no undo index at all.
    fTreasuryFromRecord = data.HasTreasury();
    if (fTreasuryFromRecord) {
        mapCTIP.clear();
        mapTreasury.clear();
        for (const SidechainTreasuryEntry& e : data.vTreasury) {
            SidechainCTIP ctip;
            ctip.out = e.out;
            ctip.amount = e.amount;

            mapCTIP[e.nSidechain] = ctip;
            mapTreasury[e.nSidechain] = e;
        }

        // A CUMULATIVE record states the whole failed set as of its block, so
        // installing it is a RESET. A DELTA carries only this block's failures
        // and is ACCUMULATED onto what is already here.
        //
        // Accumulate rather than skip, deliberately: the deposit-cache rebuild
        // walks the chain FORWARD calling this for every block, which is a
        // sequential replay and wants the merge.
        //
        // So the default is correct for a forward replay, and the awkward
        // case - restoring an ARBITRARY block, where what is already here is
        // unrelated - belongs to RestoreFailedSpentFromRecords, which clears
        // first and then walks ascending. A caller doing random access without
        // clearing gets a superset, not a subset; still wrong, but it cannot
        // silently re-admit a bundle the chain has failed.
        if (!data.HasFailedSpentDelta())
            mapFailedWithdrawal.clear();
        for (const SidechainFailedWithdrawal& f : data.vFailed)
            mapFailedWithdrawal[f.hash] = f;
    }

    // The spent bundles, restored the same way and for the same reason.
    //
    // This is the section the treasury log missed. HaveSpentWithdrawal gates
    // AddWithdrawal one line above the failed check restored just above, and
    // GetConsensusSections hashes the map as "spentwithdrawals", so it is
    // consensus state by both of the tests applied to the rest of this record -
    // yet until this key its only copy was withdrawal.dat, written once at
    // shutdown with no block stamp and no staleness check. A node that stopped
    // uncleanly came back able to re-admit a bundle it had already paid out.
    //
    // Gated on HasSpent rather than HasTreasury: records under the treasury key
    // serialise vSpent too, but as the empty vector nothing ever wrote, and
    // restoring from those would clear a map withdrawal.dat had just loaded
    // correctly. Only the key promises the field means anything.
    fSpentFromRecord = data.HasSpent();
    if (fSpentFromRecord) {
        // Reset on a cumulative record, accumulate on a delta - see the failed
        // set above for why this accumulates rather than skipping.
        if (!data.HasFailedSpentDelta())
            mapSpentWithdrawal.clear();
        AddSpentWithdrawals(data.vSpent);
    }

    // The blocks/sidechain index stores only the active sidechain slots to avoid
    // persisting 256 blank entries per block (see ConnectBlock). A full 256-entry
    // vector is the legacy/complete form and is used as-is; a shorter vector is
    // the sparse form -- rebuild the canonical 256-slot blank table and overlay
    // the stored active slots by index, so the in-memory table is identical to a
    // full snapshot.
    if (vSidechain.size() < (size_t)SIDECHAIN_ACTIVATION_MAX_ACTIVE) {
        std::vector<Sidechain> vStored;
        vStored.swap(vSidechain);
        vSidechain.assign(SIDECHAIN_ACTIVATION_MAX_ACTIVE, Sidechain());
        for (size_t i = 0; i < vSidechain.size(); i++)
            vSidechain[i].nSidechain = i;
        for (const Sidechain& s : vStored) {
            if (s.nSidechain < vSidechain.size())
                vSidechain[s.nSidechain] = s;
        }
    }
}

// Bounded. Every BMM
// or critical-data request purged from the memory pool is recorded here so the
// wallet can abandon its OWN requests (abandonbmm, the mining dialog); entries
// for other peers' transactions are never removed, and such requests cost a
// peer nothing (they are never mined), so a peer could grow the set - which is
// copied with every SidechainDB copy and persisted in bmm.dat - at will. Keep
// at most MAX_REMOVED_BMM entries, dropping the oldest first. Trade-off: under
// such a flood this node's own oldest entries can fall out before abandonbmm
// runs; abandontransaction still frees them by hand. Node-local only: the set
// is not part of any consensus hash.
static const size_t MAX_REMOVED_BMM = 20000;

void SidechainDB::AddRemovedBMM(const uint256& hashRemoved)
{
    if (!setRemovedBMM.insert(hashRemoved).second)
        return;
    dequeRemovedBMMOrder.push_back(hashRemoved);
    // Entries abandoned through BMMAbandoned leave a stale id in the deque;
    // bound the deque too so those cannot accumulate either.
    while (setRemovedBMM.size() > MAX_REMOVED_BMM ||
            dequeRemovedBMMOrder.size() > 2 * MAX_REMOVED_BMM) {
        setRemovedBMM.erase(dequeRemovedBMMOrder.front());
        dequeRemovedBMMOrder.pop_front();
    }
}

void SidechainDB::AddRemovedDeposit(const uint256& hashRemoved)
{
    vRemovedDeposit.push_back(hashRemoved);
}

bool SidechainDB::AddDeposits(const std::vector<SidechainDeposit>& vDeposit, bool fUpdateCTIP)
{
    if (vDeposit.empty())
        return true;

    // Split the deposits by nSidechain
    std::vector<std::vector<SidechainDeposit>> vDepositSplit;
    vDepositSplit.resize(vDepositCache.size());
    for (const SidechainDeposit& d : vDeposit) {
        if (!IsSidechainActive(d.nSidechain))
            continue;
        if (HaveDepositCached(d.tx.GetHash()))
            continue;

        // Put deposit into vector based on nSidechain
        vDepositSplit[d.nSidechain].push_back(d);
    }

    // Add the deposits to SCDB, remembering which slots actually gained one:
    // those are the only slots whose pointer this call may move.
    std::set<uint8_t> setSlotTouched;
    for (size_t x = 0; x < vDepositSplit.size(); x++) {
        for (size_t y = 0; y < vDepositSplit[x].size(); y++) {
            vDepositCache[x].push_back(vDepositSplit[x][y]);
            setDepositTXID.insert(vDepositSplit[x][y].tx.GetHash());
            setSlotTouched.insert((uint8_t)x);
        }
    }

    // Sort the deposits by CTIP UTXO spend order. A sort failure is a local,
    // content-independent condition (e.g. a sidechain whose on-chain deposit chain
    // has forked into more than one root — "Multiple missing CTIP"). The original
    // code ignored these return values ON PURPOSE: on failure it left the cache in
    // insertion order and STILL ran UpdateCTIP, so mapCTIP is derived from the same
    // back() deposit on every node. Returning early here (skipping UpdateCTIP) would
    // make this node's CTIP diverge from the rest of the network and could split
    // consensus, so we only LOG and always continue. (SortDeposits itself is the
    // O(n log n) rewrite; on failure it leaves vDepositCache untouched, so back()
    // — and therefore the CTIP — is byte-identical to the legacy build.)
    if (!SortSCDBDeposits())
        LogPrintf("SCDB %s: Could not sort deposits for a sidechain (forked deposit history, expected on mainnet - see SortDeposits); continuing with insertion order, CTIP unaffected.\n", __func__);

    // Update the CTIP of each slot that gained a deposit and log it (run
    // regardless of the sort result, exactly as the original code did). Only
    // the touched slots: see UpdateCTIP for why the others' pointers - which
    // may be the record's, with no deposits behind them - must stand.
    if (fUpdateCTIP && !setSlotTouched.empty()) {
        if (!UpdateCTIP(setSlotTouched))
            LogPrintf("SCDB %s: Could not update CTIP for a sidechain; continuing.\n", __func__);
    }

    // Security fix (resource exhaustion): bound the deposit cache. vDepositCache
    // is sorted in CTIP spend (chronological) order and UpdateCTIP() only reads
    // the newest deposit (back()), so removing the oldest entries never changes
    // CTIP selection. Keeping the newest SCDB_DEPOSIT_CACHE_MAX deposits per
    // sidechain also preserves Undo() for any realistic reorg depth. Without
    // this, an attacker flooding a sidechain with deposits grows RAM without
    // bound and makes the per-block deposit sort ever slower.
    for (size_t x = 0; x < vDepositCache.size(); x++) {
        if (vDepositCache[x].size() <= SCDB_DEPOSIT_CACHE_MAX)
            continue;

        const size_t nPrune = vDepositCache[x].size() - SCDB_DEPOSIT_CACHE_MAX;
        for (size_t y = 0; y < nPrune; y++)
            setDepositTXID.erase(vDepositCache[x][y].tx.GetHash());

        vDepositCache[x].erase(vDepositCache[x].begin(),
                               vDepositCache[x].begin() + nPrune);

        LogPrintf("SCDB %s: Pruned %u old deposits for sidechain %u (cache max: %u)\n",
                __func__, nPrune, x, SCDB_DEPOSIT_CACHE_MAX);
    }

    return true;
}

bool SidechainDB::AddWithdrawal(uint8_t nSidechain, const uint256& hash, int nHeight, bool fDebug)
{
    if (!IsSidechainActive(nSidechain)) {
        LogPrintf("SCDB %s: Rejected Withdrawal: %s. Invalid sidechain number: %u\n",
                __func__,
                hash.ToString());
        return false;
    }

    if (HaveWorkScore(hash, nSidechain)) {
        LogPrintf("SCDB %s: Rejected Withdrawal: %s already known\n",
                __func__,
                hash.ToString());
        return false;
    }

    if (HaveSpentWithdrawal(hash, nSidechain)) {
        LogPrintf("%s: Rejecting Withdrawal: %s - Withdrawal has been spent already!\n",
                __func__, hash.ToString());
        return false;
    }

    if (HaveFailedWithdrawal(hash, nSidechain)) {
        LogPrintf("%s: Rejecting Withdrawal: %s - Withdrawal has failed already!\n",
                __func__, hash.ToString());
        return false;
    }

    // The pending cap, from SidechainParamsHeight. Below it
    // nothing here runs and the table is exactly what 0.44.08 kept. See
    // SIDECHAIN_WITHDRAWAL_MAX_PENDING for the number and for why a full slot
    // displaces its weakest bundle rather than refusing the new one.
    //
    // A loop, not an if: the table can only be over the cap if it entered the
    // fork height over it, and the boundary expiry empties every pre-fork
    // bundle first (the production threshold cannot be met by a legacy
    // score), so in practice this runs at most once per block.
    if (nHeight >= Params().GetConsensus().SidechainParamsHeight) {
        while (vWithdrawalStatus[nSidechain].size() >= SIDECHAIN_WITHDRAWAL_MAX_PENDING) {
            const int nDisplace = GetWithdrawalToDisplace(nSidechain, nHeight);
            if (nDisplace < 0) {
                LogPrintf("%s: Rejecting Withdrawal: %s - sidechain %u holds %u pending bundles, all payout-ready\n",
                        __func__, hash.ToString(), nSidechain,
                        (unsigned)vWithdrawalStatus[nSidechain].size());
                return false;
            }
            const SidechainWithdrawalState& displaced = vWithdrawalStatus[nSidechain][nDisplace];
            LogPrintf("SCDB %s: sidechain %u at the pending cap (%u): displacing %s (workscore %u, blocks left %u) for %s\n",
                    __func__, nSidechain, SIDECHAIN_WITHDRAWAL_MAX_PENDING,
                    displaced.hash.ToString(), displaced.nWorkScore,
                    displaced.nBlocksLeft, hash.ToString());
            // Displaced, not failed: no failure record, and the cached bundle
            // transaction (node-local) is kept, so a miner holding it offers
            // it again and it re-enters through this same function.
            TemplateStateChanged();
            // Remembered (node-local) so this node's miner does not offer it
            // straight back into the full slot every block.
            //
            // 0.45.2: only when this node
            // holds the bundle's raw transaction. The miner reads the marker
            // for nothing else - NewWithdrawalsToCommit only ever asks about
            // bundles in the raw cache - and a marker for EVERY displaced hash
            // grew by one entry per displacement on every validating node,
            // with no bound and no expiry: one fresh withdrawal commitment per
            // block into a full slot was enough. Kept this way the set is
            // never larger than the raw cache, and every path that drops a
            // raw bundle (payout, failure, slot change, Reset) drops its
            // marker too. Node-local either way: in no record, commitment or
            // hash, so this changes no block's validity.
            if (HaveWithdrawalTxCachedForSlot(nSidechain, displaced.hash))
                setDisplacedWithdrawal.insert(std::make_pair(nSidechain, displaced.hash));
            vWithdrawalStatus[nSidechain].erase(vWithdrawalStatus[nSidechain].begin() + nDisplace);
        }
    }

    SidechainWithdrawalState state;
    state.nSidechain = nSidechain;
    state.nBlocksLeft = GetSidechainWithdrawalVerificationPeriod(nHeight) - 1;
    state.nWorkScore = 1;
    state.hash = hash;

    TemplateStateChanged();
    vWithdrawalStatus[nSidechain].push_back(state);
    // Pending again: no longer displaced.
    setDisplacedWithdrawal.erase(std::make_pair(nSidechain, hash));

    if (fDebug)
        LogPrintf("SCDB %s: Cached Withdrawal: %s\n", __func__, hash.ToString());

    return true;
}

bool SidechainDB::WithdrawalExpiresAt(const SidechainWithdrawalState& state, int nHeight)
{
    if (state.nBlocksLeft == 0)
        return true;
    // int64_t ON PURPOSE. While the fields were uint16_t they
    // promoted to int and this was signed, so a bundle already
    // past the threshold gave a NEGATIVE left-hand side and
    // correctly survived. At uint32_t the int from
    // GetSidechainMinWorkScore converts to UNSIGNED instead:
    // 131 - 5000 becomes 4294962427, the test fires, and an
    // over-approved bundle is expired into mapFailedWithdrawal -
    // changing the commitment hash and permanently blocking
    // re-adding it. The widening CREATES that bug; this cast is
    // what prevents it. Proved by compiling both forms.
    if ((int64_t)GetSidechainMinWorkScore(nHeight) - (int64_t)state.nWorkScore > (int64_t)state.nBlocksLeft)
        return true;
    return false;
}

int SidechainDB::GetWithdrawalToDisplace(uint8_t nSidechain, int nHeight) const
{

    // A bundle that has reached the threshold may be paid out in this very
    // block (its spend is recorded before the update runs), so it is never a
    // candidate. int64_t for the same reason as the expiry test: nWorkScore is
    // uint32_t and the threshold an int.
    const int64_t nThreshold = GetSidechainMinWorkScore(nHeight);
    const std::vector<SidechainWithdrawalState>& v = vWithdrawalStatus[nSidechain];
    int nBest = -1;
    for (size_t i = 0; i < v.size(); i++) {
        if ((int64_t)v[i].nWorkScore >= nThreshold)
            continue;
        if (nBest < 0 ||
                v[i].nWorkScore < v[nBest].nWorkScore ||
                (v[i].nWorkScore == v[nBest].nWorkScore && v[i].nBlocksLeft < v[nBest].nBlocksLeft)) {
            nBest = (int)i;
        }
    }
    return nBest;
}

bool SidechainDB::WithdrawalSlotHasRoom(uint8_t nSidechain, int nHeight) const
{
    if (nHeight < Params().GetConsensus().SidechainParamsHeight)
        return true;
    if (vWithdrawalStatus[nSidechain].size() < SIDECHAIN_WITHDRAWAL_MAX_PENDING)
        return true;
    return GetWithdrawalToDisplace(nSidechain, nHeight) >= 0;
}

int SidechainDB::PruneFailedWithdrawals(int nHeight)
{
    const Consensus::Params& params = Params().GetConsensus();
    if (nHeight <= params.SidechainParamsHeight)
        return 0;

    // Only failures recorded at or after the fork height carry a height that
    // every node agrees on (the wide records store it); the pre-fork set is
    // fixed and finite and is kept whole. int64_t so a large retention cannot
    // wrap.
    auto fDrop = [&params, nHeight](const SidechainFailedWithdrawal& f) {
        return f.nFailHeight >= params.SidechainParamsHeight &&
               (int64_t)f.nFailHeight + params.WithdrawalFailedRetention <= (int64_t)nHeight;
    };

    int nDropped = 0;
    for (std::map<uint256, SidechainFailedWithdrawal>::iterator it = mapFailedWithdrawal.begin();
            it != mapFailedWithdrawal.end();) {
        if (fDrop(it->second)) {
            LogPrintf("SCDB %s: dropping failed Withdrawal %s (sidechain %u, failed at %d) at height %d\n",
                    __func__, it->first.ToString(), it->second.nSidechain,
                    it->second.nFailHeight, nHeight);
            it = mapFailedWithdrawal.erase(it);
            nDropped++;
        } else {
            ++it;
        }
    }

    // The node-local failure-to-block index holds the same records; keep it
    // bounded with the set it indexes.
    for (std::map<uint256, std::vector<SidechainFailedWithdrawal>>::iterator it = mapFailedWithdrawalBlock.begin();
            it != mapFailedWithdrawalBlock.end();) {
        std::vector<SidechainFailedWithdrawal>& v = it->second;
        v.erase(std::remove_if(v.begin(), v.end(), fDrop), v.end());
        if (v.empty())
            it = mapFailedWithdrawalBlock.erase(it);
        else
            ++it;
    }

    if (nDropped)
        TemplateStateChanged();

    return nDropped;
}

void SidechainDB::ResetSlotDeposits(uint8_t nSidechain)
{
    if (nSidechain >= vDepositCache.size())
        return;

    // Erase from the shared txid filter before the clear, while the hashes are
    // still reachable through the deposits that carry them.
    for (const SidechainDeposit& d : vDepositCache[nSidechain])
        setDepositTXID.erase(d.tx.GetHash());

    vDepositCache[nSidechain].clear();
}

bool SidechainDB::DepositCacheSupportsTreasury(uint8_t& nSlotOut) const
{
    for (const std::pair<const uint8_t, SidechainCTIP>& p : mapCTIP) {
        const uint8_t nSidechain = p.first;
        const SidechainCTIP& ctip = p.second;

        nSlotOut = nSidechain;

        if (nSidechain >= vDepositCache.size())
            return false;

        // A pointer with no deposits behind it at all.
        if (vDepositCache[nSidechain].empty())
            return false;

        // Or with a newest deposit that names some other output. Rebuilt the
        // same way UpdateCTIP builds it, so the two agree by construction.
        const SidechainDeposit& d = vDepositCache[nSidechain].back();

        if (d.nBurnIndex >= d.tx.vout.size())
            return false;

        if (COutPoint(d.tx.GetHash(), d.nBurnIndex) != ctip.out)
            return false;

        if (d.tx.vout[d.nBurnIndex].nValue != ctip.amount)
            return false;
    }

    // The loop above only ever inspects slots that HAVE a pointer, so a slot
    // with deposits in the cache but no mapCTIP entry is invisible to it. That
    // is a corrupt state - UpdateCTIP sets mapCTIP[n] from the newest deposit,
    // so a non-empty vDepositCache[n] with no pointer means the pointer was
    // lost after the deposits were loaded - and it used to fall through to
    // "return true", telling the repair the node was healthy.
    //
    // Scope: this catches the deposits-present / pointer-absent case. It
    // sees only the in-memory caches, not the chain, so an active slot with
    // neither pointer nor deposits looks the same as a fresh sidechain with
    // no deposits yet (which is genuinely fine and must not trip a rebuild).
    // That is why every node runs a full -reindex on this release.
    for (const Sidechain& sc : GetActiveSidechains()) {
        const uint8_t nSidechain = sc.nSidechain;
        if (nSidechain < vDepositCache.size() &&
                !vDepositCache[nSidechain].empty() &&
                !mapCTIP.count(nSidechain)) {
            nSlotOut = nSidechain;
            return false;
        }
    }

    return true;
}

void SidechainDB::AddSpentWithdrawals(const std::vector<SidechainSpentWithdrawal>& vSpent)
{
    TemplateStateChanged();
    std::map<uint256, std::vector<SidechainSpentWithdrawal>>::iterator it;

    for (const SidechainSpentWithdrawal& spent : vSpent) {
        it = mapSpentWithdrawal.find(spent.hashBlock);
        if (it != mapSpentWithdrawal.end()) {
            // Adding the same spend twice is never meaningful - a bundle is
            // spent in one block or not at all - and since this container is
            // hashed into the consensus state, a duplicate is not merely
            // untidy: it makes this node report a state no correctly-built
            // node can report.
            //
            // Two sources now feed it. The per-block record restores the map
            // during ResyncSCDB, and withdrawal.dat installs the same entries
            // again later in startup, because the file is read after the
            // sidechain database has been brought to the tip. Before the
            // record carried them there was only one source and appending was
            // safe; there are two now, and every reload has to be a no-op.
            bool fHave = false;
            for (const SidechainSpentWithdrawal& existing : it->second) {
                if (existing.hash == spent.hash &&
                        existing.nSidechain == spent.nSidechain) {
                    fHave = true;
                    break;
                }
            }
            if (fHave)
                continue;

            it->second.push_back(spent);
        } else {
            mapSpentWithdrawal[spent.hashBlock] = std::vector<SidechainSpentWithdrawal>{ spent };
        }
    }
}

void SidechainDB::AddFailedWithdrawals(const std::vector<SidechainFailedWithdrawal>& vFailed)
{
    TemplateStateChanged();
    for (const SidechainFailedWithdrawal& failed : vFailed)
        mapFailedWithdrawal[failed.hash] = failed;
}

void SidechainDB::AddFailedWithdrawals(const uint256& hashBlock, const std::vector<SidechainFailedWithdrawal>& vFailed)
{
    TemplateStateChanged();
    if (vFailed.empty())
        return;

    AddFailedWithdrawals(vFailed);
    AddFailedWithdrawalBlocks(hashBlock, vFailed);
}

void SidechainDB::AddFailedWithdrawalBlocks(const uint256& hashBlock, const std::vector<SidechainFailedWithdrawal>& vFailed)
{
    TemplateStateChanged();
    // Remember which block did it. Undo needs this to tell a failure that
    // belongs to the chain the node is on from one that belonged to a branch
    // that has since been abandoned.
    //
    // This deliberately does NOT touch mapFailedWithdrawal. The two containers
    // do not hold the same thing: mapFailedWithdrawal is keyed by withdrawal
    // hash alone and keeps one record per hash, while this index keeps every
    // failure each block recorded. HaveFailedWithdrawal matches on nSidechain
    // as well as hash, so if the same hash ever fails on two slots, replaying
    // this index into mapFailedWithdrawal could install the wrong slot and turn
    // an accepted block into a rejected one. Recording the association has to
    // stay separable from deciding what has failed.
    std::vector<SidechainFailedWithdrawal>& vBlock = mapFailedWithdrawalBlock[hashBlock];
    vBlock.insert(vBlock.end(), vFailed.begin(), vFailed.end());
}

void SidechainDB::BMMAbandoned(const uint256& txid)
{
    setRemovedBMM.erase(txid);
}

void SidechainDB::CacheSidechains(const std::vector<Sidechain>& vSidechainIn)
{
    TemplateStateChanged();
    vSidechain = vSidechainIn;
}

bool SidechainDB::CacheCustomVotes(const std::vector<std::string>& vVote)
{
    if (vVote.size() != SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        return false;

    // Verify votes are valid
    for (const std::string& s : vVote) {
        if (s.empty())
            return false;

        if (s.size() != 64 && s.size() != 1)
            return false;

        if (s.size() == 64 && uint256S(s).IsNull())
            return false;

        if (s.size() == 1 && s.front() != SCDB_DOWNVOTE && s.front() != SCDB_ABSTAIN)
            return false;
    }

    TemplateStateChanged();
    vVoteCache = vVote;

    return true;
}

void SidechainDB::CacheSidechainActivationStatus(const std::vector<SidechainActivationStatus>& vActivationStatusIn)
{
    TemplateStateChanged();
    vActivationStatus = vActivationStatusIn;
}

void SidechainDB::CacheSidechainProposals(const std::vector<Sidechain>& vSidechainProposalIn)
{
    // TODO change container improve performance
    for (const Sidechain& s : vSidechainProposalIn) {
        // Make sure this proposal isn't already cached in our proposals
        bool fFound = false;
        for (const Sidechain& p : vSidechainProposal) {
            if (p == s)
            {
                fFound = true;
                break;
            }
        }
        if (!fFound) {
            TemplateStateChanged();
            vSidechainProposal.push_back(s);
        }
    }
}

void SidechainDB::CacheSidechainHashToAck(const uint256& u)
{
    TemplateStateChanged();
    vSidechainHashAck.push_back(u);
}

bool SidechainDB::CacheWithdrawalTx(const CTransaction& tx, uint8_t nSidechain)
{
    if (HaveWithdrawalTxCached(tx.GetHash())) {
        LogPrintf("%s: Rejecting Withdrawal: %s - Already cached!\n",
                __func__, tx.GetHash().ToString());
        return false;
    }

    TemplateStateChanged();
    vWithdrawalTxCache.push_back(std::make_pair(nSidechain, tx));

    return true;
}

bool SidechainDB::CheckWorkScore(uint8_t nSidechain, const uint256& hash, int nHeight, bool fDebug) const
{
    if (!IsSidechainActive(nSidechain))
        return false;

    std::vector<SidechainWithdrawalState> vState = GetState(nSidechain);
    for (const SidechainWithdrawalState& state : vState) {
        if (state.hash == hash) {
            if (state.nWorkScore >= GetSidechainMinWorkScore(nHeight)) {
                if (fDebug)
                    LogPrintf("SCDB %s: Approved: %s\n",
                            __func__,
                            hash.ToString());
                return true;
            } else {
                if (fDebug)
                    LogPrintf("SCDB %s: Rejected: %s (insufficient work score)\n",
                            __func__,
                            hash.ToString());
                return false;
            }
        }
    }
    if (fDebug)
        LogPrintf("SCDB %s: Rejected (Withdrawal state not found): %s\n",
                __func__,
                hash.ToString());
    return false;
}

void SidechainDB::ClearRemovedDeposits()
{
    vRemovedDeposit.clear();
}

unsigned int SidechainDB::GetActiveSidechainCount() const
{
    unsigned int i = 0;
    for (const Sidechain& s : vSidechain)  {
        if (s.fActive)
            i++;
    }
    return i;
}

bool SidechainDB::GetAckSidechain(const uint256& u) const
{
    for (const uint256& hash : vSidechainHashAck) {
        if (u == hash) {
            return true;
        }
    }
    return false;
}

std::vector<Sidechain> SidechainDB::GetActiveSidechains() const
{
    std::vector<Sidechain> vActive;
    for (const Sidechain& s : vSidechain)  {
        if (s.fActive)
            vActive.push_back(s);
    }

    return vActive;
}

std::vector<Sidechain> SidechainDB::GetSidechains() const
{
    return vSidechain;
}

std::set<uint256> SidechainDB::GetRemovedBMM() const
{
    return setRemovedBMM;
}

std::vector<uint256> SidechainDB::GetRemovedDeposits() const
{
    return vRemovedDeposit;
}

bool SidechainDB::GetCTIP(uint8_t nSidechain, SidechainCTIP& out) const
{
    if (!IsSidechainActive(nSidechain))
        return false;

    std::map<uint8_t, SidechainCTIP>::const_iterator it = mapCTIP.find(nSidechain);
    if (it != mapCTIP.end()) {
        out = it->second;
        return true;
    }

    return false;
}

bool SidechainDB::GetCachedWithdrawalTx(const uint256& hash, CMutableTransaction& mtx) const
{
    // Find the Withdrawal
    for (const std::pair<uint8_t, CMutableTransaction>& pair : vWithdrawalTxCache) {
        if (pair.second.GetHash() == hash) {
            mtx = pair.second;
            return true;
        }
    }
    return false;
}

std::map<uint8_t, SidechainCTIP> SidechainDB::GetCTIP() const
{
    return mapCTIP;
}

std::vector<SidechainTreasuryEntry> SidechainDB::GetTreasuryLog(TreasuryLogAudit* pAudit) const
{
    if (pAudit)
        *pAudit = TreasuryLogAudit();

    // Built from mapCTIP, which is the consensus state, and NOT from
    // mapTreasury, which is a log kept beside it. The two are supposed to move
    // together and nothing enforces that they do, so the record is constructed
    // so that a disagreement CANNOT be written out in any of its three shapes:
    //
    //   - a pointer with no log entry would have made the record OMIT that
    //     slot, and ApplyLDBData clears mapCTIP and installs exactly what the
    //     record lists, so the omission erases the pointer on every replay;
    //   - a log entry with no pointer would have been emitted and then
    //     INSTALLED as a pointer this node's chain does not support;
    //   - a log entry whose outpoint or amount had drifted would have installed
    //     the WRONG pointer, which is worse than either.
    //
    // Only nSeq and amountPrev come from the log, and only as metadata: both are
    // node-local by construction (see SidechainTreasuryEntry) and hashed by
    // nothing, so taking them from a stale entry - or defaulting them - cannot
    // make two honest nodes report different consensus state.
    //
    // Nothing here reads vDepositCache: a pointer answer that depended on how
    // much deposit history a node happened to hold would make the SCDB
    // commitment node-local. This function must never acquire that dependency.
    //
    // The TreasuryLogAudit is the only channel that can report a
    // disagreement, because the return value is built to be correct: anything
    // reading the vector sees a clean log whether or not the maps agreed.
    std::vector<SidechainTreasuryEntry> vTreasury;
    vTreasury.reserve(mapCTIP.size());

    for (const std::pair<const uint8_t, SidechainCTIP>& p : mapCTIP) {
        SidechainTreasuryEntry entry;
        entry.nSidechain = p.first;
        entry.out = p.second.out;
        entry.amount = p.second.amount;
        entry.nSeq = 0;
        entry.amountPrev = 0;

        std::map<uint8_t, SidechainTreasuryEntry>::const_iterator it = mapTreasury.find(p.first);
        if (it == mapTreasury.end()) {
            if (pAudit)
                pAudit->vMissing.push_back(p.first);
        } else {
            entry.nSeq = it->second.nSeq;
            entry.amountPrev = it->second.amountPrev;

            if (pAudit &&
                    (it->second.out != p.second.out || it->second.amount != p.second.amount)) {
                pAudit->vMismatched.push_back(p.first);
            }
        }

        vTreasury.push_back(entry);
    }

    // Log entries for slots that hold no pointer are dropped rather than
    // emitted, and reported.
    if (pAudit) {
        for (const std::pair<const uint8_t, SidechainTreasuryEntry>& p : mapTreasury) {
            if (!mapCTIP.count(p.first))
                pAudit->vStale.push_back(p.first);
        }
    }

    return vTreasury;
}

std::vector<std::string> SidechainDB::GetVotes() const
{
    return vVoteCache;
}

std::vector<SidechainDeposit> SidechainDB::GetDeposits(uint8_t nSidechain) const
{
    std::vector<SidechainDeposit> vDeposit;
    if (!IsSidechainActive(nSidechain))
        return vDeposit;

    return vDepositCache[nSidechain];
}

uint256 SidechainDB::GetHashBlockLastSeen()
{
    return hashBlockLastSeen;
}

void SidechainDB::GetConsensusSections(std::vector<SidechainDB::ConsensusSection>& vSection, int nHeight) const
{
    // Only state that block validity reads. Deliberately excludes the deposit
    // cache, the raw withdrawal transactions, votes, proposals, ack hashes and
    // the removed-BMM set: those are node-local, differ between honest nodes,
    // and including them is why GetTestHash() cannot answer "do we agree?".
    //
    // The deposit cache is excluded even though it feeds mapCTIP, because only
    // the resulting treasury pointer is consensus - two nodes can hold
    // different pruned deposit histories and still be in complete agreement
    // about every block.
    //
    // Every container below is either a fixed-size vector indexed by slot or a
    // std::map, so iteration order is deterministic without sorting.
    //
    // The section boundaries carry no weight in the hash - the leaves are
    // concatenated before hashing - so they can be renamed or resplit freely.
    // What must not change without deliberate intent is the order of the
    // leaves within the concatenation, because that is the hash.
    vSection.clear();

    // Which block this state describes. Included so a hash cannot be compared
    // across two different heights by accident.
    ConsensusSection block;
    block.name = "block";
    block.vLeaf.push_back(hashBlockLastSeen);
    vSection.push_back(block);

    // The sidechain table. All 256 slots, so a sidechain in a different slot
    // changes the hash.
    ConsensusSection sidechains;
    sidechains.name = "sidechains";
    for (const Sidechain& s : vSidechain)
        sidechains.vLeaf.push_back(s.GetSerHash());
    vSection.push_back(sidechains);

    // Withdrawal work scores - read by CheckWorkScore, which decides whether a
    // payout may be spent.
    ConsensusSection withdrawals;
    withdrawals.name = "withdrawalstatus";
    // Same width rule as GetCommitmentHash, and for the same reason: below
    // SidechainParamsHeight the legacy 37-byte form, at or after it the widened
    // 41-byte one. Without this the census hash would change form for every
    // historical block and every node still on 0.44.08 would look divergent.
    const bool fWide = nHeight >= Params().GetConsensus().SidechainParamsHeight;
    for (size_t i = 0; i < vWithdrawalStatus.size(); i++) {
        for (const SidechainWithdrawalState& state : vWithdrawalStatus[i]) {
            withdrawals.vLeaf.push_back(fWide ? state.GetSerHash()
                                              : NarrowWithdrawalState(state).GetSerHash());
        }
    }
    vSection.push_back(withdrawals);

    // Pending activation proposals - an activation commit naming a proposal
    // this node does not know rejects the block.
    ConsensusSection activation;
    activation.name = "activationstatus";
    for (const SidechainActivationStatus& a : vActivationStatus)
        activation.vLeaf.push_back(a.GetSerHash());
    vSection.push_back(activation);

    // The treasury pointers. Restored from the per-block record where the
    // record carries a treasury log, and rebuilt from the deposit cache for
    // blocks recorded before it did - so on an older record this is still the
    // field most likely to differ.
    //
    // Only the pointer is hashed. The movement counter that travels with it in
    // the log is node-local (see SidechainTreasuryEntry) and hashing it would
    // make honest nodes report divergence.
    ConsensusSection ctip;
    ctip.name = "ctip";
    for (const std::pair<const uint8_t, SidechainCTIP>& p : mapCTIP) {
        // Slot number and pointer hashed together, so the same treasury filed
        // under a different slot does not collide.
        ctip.vLeaf.push_back(SerializeHash(std::make_pair(p.first, p.second)));
    }
    vSection.push_back(ctip);

    // Bundle outcomes. Both are consulted before a bundle may be re-added.
    ConsensusSection failed;
    failed.name = "failedwithdrawals";
    for (const std::pair<const uint256, SidechainFailedWithdrawal>& p : mapFailedWithdrawal)
        failed.vLeaf.push_back(p.first);
    vSection.push_back(failed);

    ConsensusSection spent;
    spent.name = "spentwithdrawals";
    for (const std::pair<const uint256, std::vector<SidechainSpentWithdrawal>>& p : mapSpentWithdrawal) {
        spent.vLeaf.push_back(p.first);
        // SidechainSpentWithdrawal has no GetSerHash of its own; it is
        // serialisable, so hash the serialised form directly.
        for (const SidechainSpentWithdrawal& sw : p.second)
            spent.vLeaf.push_back(SerializeHash(sw));
    }
    vSection.push_back(spent);
}

uint256 SidechainDB::GetConsensusHash(int nHeight) const
{
    std::vector<ConsensusSection> vSection;
    GetConsensusSections(vSection, nHeight);

    std::vector<uint256> vLeaf;
    for (const ConsensusSection& section : vSection)
        vLeaf.insert(vLeaf.end(), section.vLeaf.begin(), section.vLeaf.end());

    return ComputeMerkleRoot(vLeaf);
}

uint256 SidechainDB::GetCommitmentHash(int nHeight) const
{
    // The committed form. See the header comment: this is the consensus
    // sections with everything that depends on the committing block's own
    // hash removed, because the miner must compute it before that hash
    // exists. Deliberately restated here rather than derived from
    // GetConsensusSections() - the sections may change shape, this may not.
    //
    // One self-delimiting byte stream. Every variable-length field below is
    // CompactSize length-prefixed, recursively, by the same SerializationOp
    // methods the per-block LDB record (SidechainBlockData) already writes
    // 1.87M times per reindex - so the encoding is injective for the same
    // reason the record is parseable, and it is not a second, less-exercised
    // serialisation of the same structs. A reader walking the stream
    // front-to-back has exactly one valid parse, so two distinct states cannot
    // share a pre-image, and an empty section is CompactSize(0) rather than
    // nothing at all: "missing" is not a byte sequence this straight-line code
    // can emit.
    //
    // There is deliberately NO merkle tree here. A length-prefixed stream has
    // no odd level and no self-paired last node, so the CVE-2012-2459 shape
    // cannot arise and there is nothing for a mutation flag to report. If
    // anyone ever reintroduces a tree in this function, ComputeMerkleRoot's
    // fMutated out-param must be passed AND checked at both consumers -
    // ConnectBlock and ComputeSCDBCommitment, in validation.cpp - or a
    // duplicated trailing leaf silently collides two different states.
    //
    // nVersion is pinned to a frozen constant rather than PROTOCOL_VERSION
    // (hash.h's default): none of the hashed types branches on version today,
    // so this is byte-identical, and it removes the hazard of a future version
    // bump silently moving a consensus hash.
    CHashWriter ss(SER_GETHASH, SCDB_COMMITMENT_SER_VERSION);

    ss << std::string(SCDB_COMMITMENT_DOMAIN);

    // 1. The sidechain table. All 256 slots, so a sidechain in a different slot
    //    changes the hash.
    ss << std::string(SCDB_COMMITMENT_TAG_SIDECHAINS) << vSidechain;

    // 2. Withdrawal work scores. The nested vector writes CompactSize(256) then
    //    a CompactSize count per slot, so the slot PARTITION is committed -
    //    which the old flat leaf list could not see.
    // WIDTH IS CHOSEN BY HEIGHT, NOT BY A STREAM FLAG. Below
    // SidechainParamsHeight the production windows are not in force, the values
    // are the legacy 263/131, and they always fit the narrow form - so the
    // pre-image here is byte-identical to every build back to 0.44.08 and a
    // mixed network still agrees. At and after that height the wide form is used,
    // because a 129,600-block window cannot be expressed in the narrow one.
    if (nHeight >= Params().GetConsensus().SidechainParamsHeight) {
        ss << std::string(SCDB_COMMITMENT_TAG_WITHDRAWALSTATUS) << vWithdrawalStatus;
    } else {
        ss << std::string(SCDB_COMMITMENT_TAG_WITHDRAWALSTATUS)
           << NarrowWithdrawalTable(vWithdrawalStatus);
    }

    // 3. Pending activation proposals.
    ss << std::string(SCDB_COMMITMENT_TAG_ACTIVATIONSTATUS) << vActivationStatus;

    // 4. The treasury pointers. std::map writes CompactSize(size) then each
    //    (slot, ctip) pair in ascending slot order, so the same treasury filed
    //    under a different slot does not collide. The node-local movement
    //    counter (SidechainTreasuryEntry::nSeq) is not in this container and
    //    stays out, for the reason sidechain.h gives.
    ss << std::string(SCDB_COMMITMENT_TAG_CTIP) << mapCTIP;

    // 5. Failed bundles, as (nSidechain, blind hash) - the pair that
    //    HaveFailedWithdrawal actually matches on. The old form pushed the raw
    //    map key and committed no slot at all; the key is redundant with
    //    failed.hash by construction (AddFailedWithdrawals does
    //    mapFailedWithdrawal[failed.hash] = failed), so hashing the value
    //    loses nothing and closes the gap. Map order is memcmp over the key.
    std::vector<SidechainFailedWithdrawal> vFailed;
    vFailed.reserve(mapFailedWithdrawal.size());
    for (const std::pair<const uint256, SidechainFailedWithdrawal>& p : mapFailedWithdrawal)
        vFailed.push_back(p.second);
    ss << std::string(SCDB_COMMITMENT_TAG_FAILED) << vFailed;

    // 6. Spent bundles, reduced to what validity reads. The map key and each
    //    entry's hashBlock are the block the spend landed in - for a spend in
    //    the committing block that is the committing block's own hash, which
    //    does not exist yet. Both are dropped and the pairs are sorted, because
    //    the map ordered them by that same absent hash.
    //
    //    Then DEDUPLICATED: HaveSpentWithdrawal is a set-membership test, so
    //    multiplicity is not state any validity decision reads. Committing a
    //    multiset would fork a node off for holding a duplicate that changes no
    //    decision - and a duplicate cannot self-heal, because ConnectBlock
    //    writes the whole map into the record and ApplyLDBData re-adds it.
    //    Multiplicity stays visible in GetConsensusHash, which is the right
    //    place for it: detection there, no false-positive fork here.
    std::vector<std::pair<uint8_t, uint256>> vSpentPair;
    for (const std::pair<const uint256, std::vector<SidechainSpentWithdrawal>>& p : mapSpentWithdrawal) {
        for (const SidechainSpentWithdrawal& sw : p.second)
            vSpentPair.push_back(std::make_pair(sw.nSidechain, sw.hash));
    }
    std::sort(vSpentPair.begin(), vSpentPair.end());
    vSpentPair.erase(std::unique(vSpentPair.begin(), vSpentPair.end()), vSpentPair.end());
    ss << std::string(SCDB_COMMITMENT_TAG_SPENT) << vSpentPair;

    return ss.GetHash();
}

uint256 SidechainDB::GetTestHash(int nHeight) const
{
    std::vector<uint256> vLeaf;

    // Add mapCTIP
    std::map<uint8_t, SidechainCTIP>::const_iterator it;
    for (it = mapCTIP.begin(); it != mapCTIP.end(); it++) {
        vLeaf.push_back(it->second.GetSerHash());
    }

    uint256 hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with CTIP data: %s\n", __func__, hash.ToString());

    // Add hashBlockLastSeen
    vLeaf.push_back(hashBlockLastSeen);

    hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with hashBlockLastSeen data: %s\n", __func__, hash.ToString());

    // Add vSidechain
    for (const Sidechain& s : vSidechain) {
        vLeaf.push_back(s.GetSerHash());
    }

    hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with vSidechain data: %s\n", __func__, hash.ToString());

    // Add vActivationStatus
    for (const SidechainActivationStatus& s : vActivationStatus) {
        vLeaf.push_back(s.GetSerHash());
    }

    hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with vActivationStatus data: %s\n", __func__, hash.ToString());

    // Add vDepositCache
    for (const std::vector<SidechainDeposit>& v : vDepositCache) {
        for (const SidechainDeposit& d : v) {
            vLeaf.push_back(d.GetSerHash());
        }
    }

    hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with vDepositCache data: %s\n", __func__, hash.ToString());

    // Add vWithdrawalTxCache
    for (const std::pair<uint8_t, CMutableTransaction>& pair : vWithdrawalTxCache) {
        vLeaf.push_back(pair.second.GetHash());
    }

    hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with vWithdrawalTxCache data: %s\n", __func__, hash.ToString());

    // Add vWithdrawalStatus.
    //
    // SAME WIDTH GATE AS GetConsensusSections AND GetCommitmentHash, for
    // consistency only. This hash is not comparable between honest
    // same-version nodes anyway: it mixes in vDepositCache and
    // vWithdrawalTxCache above, which are node-local and legitimately differ
    // (the withdrawal-tx cache is filled by operator RPC, in arrival order).
    // See the header comment on GetConsensusHash, which says so directly.
    // GetConsensusHash is the census instrument; it is gated, and it is what
    // an operator comparing nodes must use.
    //
    // Gate it anyway: three accessors hash withdrawal state and two selected
    // the width, so leaving the third alone reads to the next reader as a
    // deliberate exception, and the reason it was skipped is simply that no
    // test called GetTestHash at all.
    const bool fWide = nHeight >= Params().GetConsensus().SidechainParamsHeight;
    for (size_t i = 0; i < SIDECHAIN_ACTIVATION_MAX_ACTIVE; i++) {
        std::vector<SidechainWithdrawalState> vState = GetState(i);
        for (const SidechainWithdrawalState& state : vState) {
            vLeaf.push_back(fWide ? state.GetSerHash()
                                  : NarrowWithdrawalState(state).GetSerHash());
        }
    }

    hash = ComputeMerkleRoot(vLeaf);
    LogPrintf("%s: Hash with vWithdrawalStatus data (total hash): %s\n", __func__, hash.ToString());

    return ComputeMerkleRoot(vLeaf);
}

bool SidechainDB::GetSidechain(const uint8_t nSidechain, Sidechain& sidechain) const
{
    if (!IsSidechainActive(nSidechain))
        return false;

    sidechain = vSidechain[nSidechain];

    return true;
}

std::vector<SidechainActivationStatus> SidechainDB::GetSidechainActivationStatus() const
{
    return vActivationStatus;
}

std::set<uint8_t> SidechainDB::GetSlotsClearedByActivation(const std::vector<uint256>& vActivationHash, int nHeight) const
{
    // Only a proposal that replaces
    // an active sidechain and reaches its period in this block clears a slot
    // that has bundles (a new slot has none). UpdateActivationStatus ages
    // every proposal by one before it compares, hence nAge + 1. Checked first
    // so the full copy below is made in that one block, not in every template.
    std::set<uint8_t> setCleared;
    if (GetSlotsWithReplacementDue(nHeight).empty())
        return setCleared;

    // The real step on a copy, with the commitments the block will carry, so
    // failures, expiry and the escrow refusal decide exactly as ApplyUpdate will.
    SidechainDB scdbSim = (*this);
    scdbSim.UpdateActivationStatus(vActivationHash, nHeight);
    for (size_t n = 0; n < vWithdrawalStatus.size() && n < scdbSim.vWithdrawalStatus.size(); n++) {
        if (!vWithdrawalStatus[n].empty() && scdbSim.vWithdrawalStatus[n].empty())
            setCleared.insert((uint8_t)n);
    }
    return setCleared;
}

std::set<uint8_t> SidechainDB::GetSlotsWithReplacementDue(int nHeight) const
{
    std::set<uint8_t> setDue;
    for (const SidechainActivationStatus& s : vActivationStatus) {
        if (IsSidechainActive(s.proposal.nSidechain) &&
                s.nAge + 1 == GetSidechainReplacementPeriod(nHeight))
            setDue.insert(s.proposal.nSidechain);
    }
    return setDue;
}

std::string SidechainDB::GetSidechainName(uint8_t nSidechain) const
{
    std::string str = "UnknownSidechain";

    Sidechain sidechain;
    if (GetSidechain(nSidechain, sidechain))
        return sidechain.title;

    return str;
}

std::vector<Sidechain> SidechainDB::GetSidechainProposals() const
{
    return vSidechainProposal;
}

bool SidechainDB::GetSidechainScript(const uint8_t nSidechain, CScript& scriptPubKey) const
{
    Sidechain sidechain;
    if (!GetSidechain(nSidechain, sidechain))
        return false;

    scriptPubKey.resize(2);
    scriptPubKey[0] = OP_DRIVECHAIN;
    scriptPubKey[1] = nSidechain;

    return true;
}

std::vector<uint256> SidechainDB::GetSidechainsToActivate() const
{
    return vSidechainHashAck;
}

std::vector<SidechainSpentWithdrawal> SidechainDB::GetSpentWithdrawalsForBlock(const uint256& hashBlock) const
{
    std::map<uint256, std::vector<SidechainSpentWithdrawal>>::const_iterator it;
    it = mapSpentWithdrawal.find(hashBlock);

    if (it != mapSpentWithdrawal.end())
        return it->second;

    return std::vector<SidechainSpentWithdrawal>{};
}

bool SidechainDB::WasWithdrawalDisplaced(uint8_t nSidechain, const uint256& hash) const
{
    return setDisplacedWithdrawal.count(std::make_pair(nSidechain, hash)) > 0;
}

bool SidechainDB::IsWithdrawalUpvotedHere(uint8_t nSidechain, const uint256& hash) const
{
    if (nSidechain >= vVoteCache.size())
        return false;
    const std::string& strVote = vVoteCache[nSidechain];
    return strVote.size() == 64 && uint256S(strVote) == hash;
}

std::vector<SidechainWithdrawalState> SidechainDB::GetState(uint8_t nSidechain) const
{
    if (!HasState() || !IsSidechainActive(nSidechain))
        return std::vector<SidechainWithdrawalState>();

    return vWithdrawalStatus[nSidechain];
}

std::vector<std::vector<SidechainWithdrawalState>> SidechainDB::GetState() const
{
    return vWithdrawalStatus;
}

std::vector<uint256> SidechainDB::GetUncommittedWithdrawalCache(uint8_t nSidechain) const
{
    std::vector<uint256> vHash;
    // Declared as the cache's own element type: naming a different transaction
    // type here binds the reference to a temporary, copying every entry.
    for (const std::pair<uint8_t, CMutableTransaction>& pair : vWithdrawalTxCache) {
        if (nSidechain != pair.first)
            continue;

        uint256 txid = pair.second.GetHash();
        if (!HaveWorkScore(txid, nSidechain)) {
            vHash.push_back(pair.second.GetHash());
        }
    }
    return vHash;
}

std::vector<std::pair<uint8_t, CMutableTransaction>> SidechainDB::GetWithdrawalTxCache() const
{
    return vWithdrawalTxCache;
}

std::vector<SidechainSpentWithdrawal> SidechainDB::GetSpentWithdrawalCache() const
{
    std::vector<SidechainSpentWithdrawal> vSpent;
    for (auto const& it : mapSpentWithdrawal) {
        for (const SidechainSpentWithdrawal& s : it.second)
            vSpent.push_back(s);
    }
    return vSpent;
}

//! This block's failures only - the DELTA the record under a delta key
//! carries. mapFailedWithdrawalBlock is already keyed by block and already
//! holds exactly this, recorded by RemoveExpiredWithdrawals as the block was
//! connected, so nothing new has to be tracked to write a delta record.
std::vector<SidechainFailedWithdrawal> SidechainDB::GetBlockFailedWithdrawals(const uint256& hashBlock) const
{
    std::map<uint256, std::vector<SidechainFailedWithdrawal>>::const_iterator it =
            mapFailedWithdrawalBlock.find(hashBlock);
    if (it == mapFailedWithdrawalBlock.end())
        return std::vector<SidechainFailedWithdrawal>();
    return it->second;
}

//! This block's spends only. mapSpentWithdrawal is keyed by block hash, so the
//! delta is one lookup - unlike the failed map, which is keyed by withdrawal
//! hash and needs the separate per-block index above.
std::vector<SidechainSpentWithdrawal> SidechainDB::GetBlockSpentWithdrawals(const uint256& hashBlock) const
{
    std::map<uint256, std::vector<SidechainSpentWithdrawal>>::const_iterator it =
            mapSpentWithdrawal.find(hashBlock);
    if (it == mapSpentWithdrawal.end())
        return std::vector<SidechainSpentWithdrawal>();
    return it->second;
}

//! Empty both sets so a reconstruction walk can install them from scratch.
//! Deliberately NOT touching mapFailedWithdrawalBlock: that index is the source
//! of the deltas being replayed, and its own comment explains why it must stay
//! separable from the decision of what has failed.
void SidechainDB::ClearFailedAndSpentWithdrawals()
{
    TemplateStateChanged();
    mapFailedWithdrawal.clear();
    mapSpentWithdrawal.clear();
}

//! Apply one record's failed/spent sections on top of what is already there.
//! ORDER MATTERS AND THE CALLER MUST DRIVE IT ASCENDING BY HEIGHT. This looks
//! like a set union and is not one: mapFailedWithdrawal is keyed by hash ALONE
//! and assignment is last-write-wins, while HaveFailedWithdrawal matches on
//! (hash, nSidechain). If one blind hash ever fails on two slots, applying the
//! deltas newest-first installs the wrong slot and AddWithdrawal - which is
//! consensus and behind no flag day - then accepts or rejects differently from
//! a node that connected the blocks normally.
void SidechainDB::MergeFailedAndSpentWithdrawals(const SidechainBlockData& data)
{
    TemplateStateChanged();
    for (const SidechainFailedWithdrawal& f : data.vFailed)
        mapFailedWithdrawal[f.hash] = f;
    AddSpentWithdrawals(data.vSpent);
}

std::vector<SidechainFailedWithdrawal> SidechainDB::GetFailedWithdrawalCache() const
{
    std::vector<SidechainFailedWithdrawal> vFailed;
    for (auto const& it : mapFailedWithdrawal) {
        vFailed.push_back(it.second);
    }
    return vFailed;
}

std::vector<std::pair<uint256, SidechainFailedWithdrawal>> SidechainDB::GetFailedWithdrawalBlocks() const
{
    std::vector<std::pair<uint256, SidechainFailedWithdrawal>> vBlock;
    for (auto const& it : mapFailedWithdrawalBlock) {
        for (const SidechainFailedWithdrawal& f : it.second)
            vBlock.push_back(std::make_pair(it.first, f));
    }
    return vBlock;
}

bool SidechainDB::HasState() const
{
    // Make sure that SCDB is actually initialized
    if (vWithdrawalStatus.empty() || !GetActiveSidechainCount())
        return false;

    // Check if we have Withdrawal state
    for (auto i : vWithdrawalStatus) {
        if (!i.empty())
            return true;
    }

    return false;
}

bool SidechainDB::HaveDepositCached(const uint256& txid) const
{
    return (setDepositTXID.find(txid) != setDepositTXID.end());
}

bool SidechainDB::HaveSpentWithdrawal(const uint256& hash, const uint8_t nSidechain) const
{
    // TODO change / update container mapSpentWithdrawals so that we can look up
    // Withdrawal(s) by Withdrawal hash instead of looping.
    for (auto const& it : mapSpentWithdrawal) {
        for (const SidechainSpentWithdrawal& s : it.second) {
            if (s.hash == hash && s.nSidechain == nSidechain)
                return true;
        }
    }

    return false;
}

bool SidechainDB::HaveFailedWithdrawal(const uint256& hash, const uint8_t nSidechain) const
{
    std::map<uint256, SidechainFailedWithdrawal>::const_iterator it;
    it = mapFailedWithdrawal.find(hash);
    if (it != mapFailedWithdrawal.end() && it->second.nSidechain == nSidechain)
        return true;

    return false;
}

bool SidechainDB::HaveWithdrawalTxCachedForSlot(uint8_t nSidechain, const uint256& hash) const
{
    for (const std::pair<uint8_t, CMutableTransaction>& pair : vWithdrawalTxCache) {
        if (pair.first == nSidechain && pair.second.GetHash() == hash)
            return true;
    }
    return false;
}

bool SidechainDB::HaveWithdrawalTxCached(const uint256& hash) const
{
    for (const std::pair<uint8_t, CMutableTransaction>& pair : vWithdrawalTxCache) {
        if (pair.second.GetHash() == hash)
            return true;
    }
    return false;
}

// The fork height of the treasury-pointer rules: validation.cpp's
// nCTIPRulesHeight, max(EscrowRulesHeight, SCDBCommitmentHeight). Read from the
// live parameters, so the test-network startup overrides of either height move
// it (both at 1,976,112 on mainnet, inactive on testnet, 300 on regtest).
static int GetCTIPRulesHeight()
{
    const Consensus::Params& params = Params().GetConsensus();
    return std::max(params.EscrowRulesHeight, params.SCDBCommitmentHeight);
}

bool SidechainDB::IsSidechainProposalKnown(const Sidechain& proposal) const
{
    // Pending: the same proposal hash an ACK commitment names.
    const uint256 hash = proposal.GetSerHash();
    for (const SidechainActivationStatus& s : vActivationStatus) {
        if (s.proposal.GetSerHash() == hash)
            return true;
    }
    // Active: the slot's occupant has the same parameters. Sidechain's
    // operator== compares every proposal field and not fActive, which is the
    // only field activation changes.
    if (IsSidechainActive(proposal.nSidechain) && vSidechain[proposal.nSidechain] == proposal)
        return true;
    return false;
}

bool SidechainDB::HaveWorkScore(const uint256& hash, uint8_t nSidechain) const
{
    if (!IsSidechainActive(nSidechain))
        return false;

    std::vector<SidechainWithdrawalState> vState = GetState(nSidechain);
    for (const SidechainWithdrawalState& state : vState) {
        if (state.hash == hash)
            return true;
    }
    return false;
}

bool SidechainDB::IsSidechainActive(uint8_t nSidechain) const
{
    if (nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        return false;
    if (nSidechain >= vWithdrawalStatus.size())
        return false;
    if (nSidechain >= vDepositCache.size())
        return false;
    if (nSidechain >= vSidechain.size())
        return false;

    return vSidechain[nSidechain].fActive;
}

void SidechainDB::RemoveExpiredWithdrawals(int nHeight, const uint256& hashBlock)
{
    TemplateStateChanged();

    // THE BOUNDARY SWEEP. At the fork
    // height exactly (==, never >=) the threshold jumps from the legacy 131 to
    // the production value, so every bundle proposed under the legacy window
    // expires here at once. Those bundles did not fail a vote; the rules
    // changed under them. So at this one height they leave WITHOUT a failure
    // record and the same hash may be proposed again under the new rules. At
    // every other height blacklisting on expiry is unchanged.
    const Consensus::Params& params = Params().GetConsensus();
    const bool fBoundarySweep = params.fWithdrawalBoundarySweep &&
            nHeight == params.SidechainParamsHeight;
    if (fBoundarySweep) {
        // Node-local companion: a vote cached under the old rules must not
        // auto-approve a bundle once it is re-proposed under the new ones.
        ResetWithdrawalVotes();
    }

    for (size_t x = 0; x < vWithdrawalStatus.size(); x++) {
        vWithdrawalStatus[x].erase(std::remove_if(
                    vWithdrawalStatus[x].begin(), vWithdrawalStatus[x].end(),
                    [this, nHeight, &hashBlock, fBoundarySweep](const SidechainWithdrawalState& state)
                    {
                        // If the Withdrawal has 0 blocks remaining, or does not have
                        // enough blocks remaining to gather required work score
                        // then expire it (which will mark it failed) & remove.
                        // (the test moved, unchanged, into
                        // WithdrawalExpiresAt so the miner can ask it too.)
                        const bool fExpire = WithdrawalExpiresAt(state, nHeight);

                        if (fExpire && fBoundarySweep) {
                            // No failure record, and the cached bundle
                            // transaction is kept (node-local) so the miner
                            // offers it again with no operator action.
                            LogPrintf("SCDB RemoveExpiredWithdrawals: boundary sweep at the fork height %d, NOT recording failed: %s\n",
                                    nHeight, state.ToString());
                            return true;
                        }

                        if (fExpire) {
                            LogPrintf("SCDB RemoveExpiredWithdrawals: Erasing expired Withdrawal: %s\n",
                                    state.ToString());

                            // Add to mapFailedWithdrawals, against the block
                            // that expired it. The block matters because
                            // AddWithdrawal refuses a bundle already recorded
                            // failed: if this block is later disconnected the
                            // record has to go with it, or this node rejects
                            // the block that re-proposes the bundle on the
                            // chain everyone else is following.
                            SidechainFailedWithdrawal failed;
                            failed.nSidechain = state.nSidechain;
                            failed.hash = state.hash;
                            failed.nFailHeight = nHeight;
                            AddFailedWithdrawals(hashBlock,
                                    std::vector<SidechainFailedWithdrawal>{ failed });

                            // Remove the cached transaction for the failed
                            // Withdrawal. The cache is shared by all sidechains,
                            // so match the slot as well as the hash.
                            //
                            // The bundle bytes are deliberately not kept for a
                            // possible disconnect. Nothing reads this cache to
                            // decide whether a block is valid - SpendWithdrawal
                            // only ever removes from it, and a payout is checked
                            // against the work score in vWithdrawalStatus, which
                            // the per-block record restores - so a miner that
                            // loses it re-requests the bundle from the sidechain,
                            // as the note in SpendWithdrawal describes. Holding
                            // the bytes instead would put them in the full copy
                            // of SCDB that Update() takes for every block.
                            setDisplacedWithdrawal.erase(std::make_pair(state.nSidechain, state.hash));
                            for (size_t i = 0; i < vWithdrawalTxCache.size(); i++) {
                                if (vWithdrawalTxCache[i].first == state.nSidechain &&
                                        vWithdrawalTxCache[i].second.GetHash() == state.hash) {
                                    vWithdrawalTxCache[i] = vWithdrawalTxCache.back();
                                    vWithdrawalTxCache.pop_back();
                                    break;
                                }
                            }
                            return true;
                        } else {
                            return false;
                        }
                    }),
                    vWithdrawalStatus[x].end());
    }
}

void SidechainDB::RemoveSidechainHashToAck(const uint256& u)
{
    // TODO change container to make this efficient
    for (size_t i = 0; i < vSidechainHashAck.size(); i++) {
        if (vSidechainHashAck[i] == u) {
            TemplateStateChanged();
            vSidechainHashAck[i] = vSidechainHashAck.back();
            vSidechainHashAck.pop_back();
            break;
        }
    }
}

void SidechainDB::ResetWithdrawalState()
{
    TemplateStateChanged();
    // Clear out Withdrawal state
    vWithdrawalStatus.clear();
    vWithdrawalStatus.resize(SIDECHAIN_ACTIVATION_MAX_ACTIVE);
}

void SidechainDB::ResetWithdrawalVotes()
{
    TemplateStateChanged();
    vVoteCache.clear();
    vVoteCache = std::vector<std::string>(SIDECHAIN_ACTIVATION_MAX_ACTIVE, std::string(1, SCDB_ABSTAIN));
}

void SidechainDB::Reset()
{
    TemplateStateChanged();
    // Clear out CTIP data and the treasury log that shadows it
    mapCTIP.clear();
    mapTreasury.clear();
    fTreasuryFromRecord = false;
    fSpentFromRecord = false;

    // Reset hashBlockLastSeen
    hashBlockLastSeen.SetNull();

    // Clear out sidechains
    vSidechain.clear();

    // Clear out sidechain activation status
    vActivationStatus.clear();

    // Clear out our cache of sidechain deposits
    vDepositCache.clear();

    // Clear out list of sidechain (hashes) we want to ACK
    vSidechainHashAck.clear();

    // Clear out our cache of proposed sidechains
    vSidechainProposal.clear();

    // Clear out cached Withdrawal serializations
    vWithdrawalTxCache.clear();
    // and the displacement markers, which exist only for cached bundles
    setDisplacedWithdrawal.clear();

    // Clear out Withdrawal state
    ResetWithdrawalState();

    // Clear out custom vote cache
    ResetWithdrawalVotes();

    // Clear out spent Withdrawal cache
    mapSpentWithdrawal.clear();

    // Clear out failed Withdrawal cache
    mapFailedWithdrawal.clear();
    mapFailedWithdrawalBlock.clear();

    vRemovedDeposit.clear();
    setRemovedBMM.clear();
    dequeRemovedBMMOrder.clear();

    // The deposit cache and the filter that decides what may enter it have to
    // go together. AddDeposits silently skips any deposit whose txid is still
    // in this set and reports success, so a set left behind here makes every
    // deposit already in memory unaddable for the rest of the process -
    // including during the replay this reset is preparing for, and including
    // by any later repair that re-scans blocks. The node comes back with no
    // treasury tip and writes that emptiness over the deposit file.
    setDepositTXID.clear();

    // Resize vWithdrawalStatus to keep track of Withdrawal(s)
    vWithdrawalStatus.resize(SIDECHAIN_ACTIVATION_MAX_ACTIVE);

    // Resize vDepositCache to keep track of deposit(s)
    vDepositCache.resize(SIDECHAIN_ACTIVATION_MAX_ACTIVE);

    // Initialize with blank inactive sidechains
    vSidechain.resize(SIDECHAIN_ACTIVATION_MAX_ACTIVE);
    for (size_t i = 0; i < vSidechain.size(); i++)
        vSidechain[i].nSidechain = i;
}

bool SidechainDB::SpendWithdrawal(uint8_t nSidechain, const uint256& hashBlock, const CTransaction& tx, const int nTx, int nHeight, bool fJustCheck, bool fDebug)
{
    fDebug = true;
    if (!IsSidechainActive(nSidechain)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal (txid): %s for sidechain number: %u.\n Invalid sidechain number.\n",
                __func__,
                tx.GetHash().ToString(),
                nSidechain);
        }
        return false;
    }

    if (tx.vout.size() < 3) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal (txid): %s for sidechain number: %u. Missing outputs!.\n",
                __func__,
                tx.GetHash().ToString(),
                nSidechain);
        }
        return false;
    }

    uint256 hashBlind;
    if (!tx.GetBlindHash(hashBlind)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal (txid): %s for sidechain number: %u.\n Cannot get blind hash.\n",
                __func__,
                tx.GetHash().ToString(),
                nSidechain);
        }
        return false;
    }

    if (!CheckWorkScore(nSidechain, hashBlind, nHeight, fDebug)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal (blind hash): %s for sidechain number: %u. CheckWorkScore() failed.\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
        return false;
    }

    // Find the required change output returning to the sidechain script as well
    // as the required SIDECHAIN_WITHDRAWAL_RETURN_DEST OP_RETURN output.
    bool fChangeOutputFound = false;
    bool fReturnDestFound = false;
    uint8_t nSidechainScript;
    CAmount amountChange = 0;
    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CScript &scriptPubKey = tx.vout[i].scriptPubKey;

        // This would be non-standard but still checking
        if (!scriptPubKey.size())
            continue;

        // The first OP_RETURN output we find must be an encoding of the
        // SIDECHAIN_WITHDRAWAL_RETURN_DEST char. So once we find an OP_RETURN in
        // this loop it must have the correct data encoded. We will return false
        // if it does not and skip this code if we've already found it.
        // Is this the SIDECHAIN_WITHDRAWAL_RETURN_DEST OP_RETURN output?
        if (!fReturnDestFound && scriptPubKey.front() == OP_RETURN) {
            if (scriptPubKey.size() < 3) {
                if (fDebug) {
                    LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. First OP_RETURN output is invalid size for destination. (too small)\n",
                        __func__,
                        hashBlind.ToString(),
                        nSidechain);
                }
                return false;
            }

            CScript::const_iterator pDest = scriptPubKey.begin() + 1;
            opcodetype opcode;
            std::vector<unsigned char> vch;
            if (!scriptPubKey.GetOp(pDest, opcode, vch) || vch.empty()) {
                if (fDebug) {
                    LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. First OP_RETURN output is invalid. (GetOp failed)\n",
                        __func__,
                        hashBlind.ToString(),
                        nSidechain);
                }
                return false;
            }

            std::string strDest((const char*)vch.data(), vch.size());

            if (strDest != SIDECHAIN_WITHDRAWAL_RETURN_DEST) {
                if (fDebug) {
                    LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Missing SIDECHAIN_WITHDRAWAL_RETURN_DEST output.\n",
                        __func__,
                        hashBlind.ToString(),
                        nSidechain);
                }
                return false;
            }
            fReturnDestFound = true;
        }

        if (scriptPubKey.IsDrivechain(nSidechainScript)) {
            if (fChangeOutputFound) {
                // We already found a sidechain script output. This second
                // sidechain output makes the Withdrawal invalid.
                if (fDebug) {
                    LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Multiple sidechain return outputs in Withdrawal.\n",
                        __func__,
                        hashBlind.ToString(),
                        nSidechain);
                }
                return false;
            }

            // The output index itself is re-found by GetWithdrawalChangeDeposit
            // below, which is what actually builds the deposit.
            fChangeOutputFound = true;

            // Copy amount of sidechain change
            amountChange = tx.vout[i].nValue;

            continue;
        }
    }

    // Make sure that the sidechain output was found
    if (!fChangeOutputFound) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. No sidechain return output in Withdrawal.\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
        return false;
    }

    // Make sure that the sidechain output is to the correct sidechain
    if (nSidechainScript != nSidechain) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Return output to incorrect nSidechain: %u in Withdrawal.\n",
                __func__,
                hashBlind.ToString(),
                nSidechain,
                nSidechainScript);
        }
        return false;
    }

    if (nSidechain >= vWithdrawalStatus.size()) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Withdrawal status for sidechain not found.\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
        return false;
    }

    // Get CTIP
    SidechainCTIP ctip;
    if (!GetCTIP(nSidechain, ctip)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. CTIP not found!\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
       return false;
    }

    // Check that Withdrawal input matches CTIP
    if (ctip.out != tx.vin[0].prevout) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. CTIP does not match!\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
       return false;
    }

    // Escrow rules (BIP300 796c80eb): from EscrowRulesHeight the fee output
    // must be zero-value. Checked here as well as in ConnectBlock so that the
    // miner and the template simulation, which call this and not ConnectBlock,
    // never build a payout the validator refuses.
    if (nHeight >= Params().GetConsensus().EscrowRulesHeight && tx.vout[1].nValue != 0) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. The fee output carries value (bad-withdrawal-fee-value).\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
        return false;
    }

    // Decode sum of withdrawal fees
    CAmount amountFees = 0;
    if (!DecodeWithdrawalFees(tx.vout[1].scriptPubKey, amountFees)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. failed to decode withdrawal fees!\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
       return false;
    }

    // Get the total value out of the blind Withdrawal
    // Cannot fail here: vout.size() >= 3 was checked above and vin[0] was
    // matched against the CTIP, so both are non-empty. Checked anyway so that
    // the "no outputs" case can never arrive as a silent zero.
    CAmount amountBlind = 0;
    if (!tx.GetBlindValueOut(amountBlind)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Could not read the blind value out!\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
       return false;
    }

    CAmount amountInput = ctip.amount;
    CAmount amountOutput = tx.GetValueOut();

    // Check output amount
    if (amountBlind != amountOutput - amountChange) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Invalid output amount!\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
       return false;
    }

    // Check change amount
    if (amountChange != amountInput - (amountBlind + amountFees)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Invalid change amount!\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
       return false;
    }

    if (fJustCheck)
        return true;

    TemplateStateChanged();

    // Create a sidechain deposit object for the return amount.
    //
    // Built by the shared helper rather than here, so that a rebuild replaying
    // this block from disk produces a byte-identical deposit. It re-finds the
    // change output that the loop above already located; the checks it repeats
    // have all passed by this point, so it cannot fail here.
    SidechainDeposit deposit;
    if (!GetWithdrawalChangeDeposit(tx, nTx, hashBlock, nSidechain, deposit)) {
        if (fDebug) {
            LogPrintf("SCDB %s: Cannot spend Withdrawal: %s for sidechain number: %u. Could not build the change return deposit.\n",
                __func__,
                hashBlind.ToString(),
                nSidechain);
        }
        return false;
    }

    // Add deposit to cache, update CTIP
    AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // If the block which spent this Withdrawal is disconnected, the miner
    // needs the raw bundle again to pay it on the replacing branch. It is not
    // kept here: Undo rebuilds it from the payout transaction in the
    // disconnected block (RestorePaidWithdrawalTx), which carries every byte
    // the cache held, so nothing extra rides in the per-block copies of SCDB.
    //
    setDisplacedWithdrawal.erase(std::make_pair(nSidechain, hashBlind));
    // Find the cached transaction for the Withdrawal we spent and remove it
    for (size_t i = 0; i < vWithdrawalTxCache.size(); i++) {
        // The cache is shared by all sidechains, so match the slot as well as
        // the hash.
        if (vWithdrawalTxCache[i].first == nSidechain &&
                vWithdrawalTxCache[i].second.GetHash() == hashBlind) {
            vWithdrawalTxCache[i] = vWithdrawalTxCache.back();
            vWithdrawalTxCache.pop_back();
            break;
        }
    }

    SidechainSpentWithdrawal spent;
    spent.nSidechain = nSidechain;
    spent.hash = hashBlind;
    spent.hashBlock = hashBlock;

    // Track the spent Withdrawal
    AddSpentWithdrawals(std::vector<SidechainSpentWithdrawal>{ spent });

    // The Withdrawal will be removed from SCDB when SCDB::Update() is called now that
    // it has been marked as spent.

    LogPrintf("%s Withdrawal spent: %s for sidechain number: %u.\n", __func__, hashBlind.ToString(), nSidechain);

    return true;
}

bool SidechainDB::TxnToDeposit(const CTransaction& tx, const int nTx, const uint256& hashBlock, SidechainDeposit& deposit)
{
    // Note that the first OP_RETURN output found in a deposit transaction will
    // be used as the destination. Others are ignored.
    bool fBurnFound = false;
    bool fDestFound = false;
    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CScript &scriptPubKey = tx.vout[i].scriptPubKey;

        if (!scriptPubKey.size())
            continue;

        uint8_t nSidechain;
        if (scriptPubKey.IsDrivechain(nSidechain)) {
            // If we already found a burn output, more make the deposit invalid
            if (fBurnFound) {
                LogPrintf("%s: Invalid - multiple burn outputs.\ntxid: %s\n", __func__, tx.GetHash().ToString());
                return false;
            }

            // We found the burn output, copy the output index & nSidechain
            deposit.nSidechain = nSidechain;
            deposit.nBurnIndex = i;
            fBurnFound = true;
            continue;
        }

        // Move on to looking for the encoded destination string

        if (fDestFound)
            continue;
        if (scriptPubKey.front() != OP_RETURN)
            continue;
        if (scriptPubKey.size() < 3) {
            LogPrintf("%s: Invalid - First OP_RETURN is invalid (too small).\ntxid: %s\n", __func__, tx.GetHash().ToString());
            return false;
        }
        if (scriptPubKey.size() > MAX_DEPOSIT_DESTINATION_BYTES) {
            LogPrintf("%s: Invalid - First OP_RETURN is invalid (too large).\ntxid: %s\n", __func__, tx.GetHash().ToString());
            return false;
        }

        CScript::const_iterator pDest = scriptPubKey.begin() + 1;
        opcodetype opcode;
        std::vector<unsigned char> vch;
        if (!scriptPubKey.GetOp(pDest, opcode, vch) || vch.empty()) {
            LogPrintf("%s: Invalid - First OP_RETURN is invalid (failed GetOp).\ntxid: %s\n", __func__, tx.GetHash().ToString());
            return false;
        }

        std::string strDest((const char*)vch.data(), vch.size());
        if (strDest.empty()) {
            LogPrintf("%s: Invalid - empty dest.\ntxid: %s\n", __func__, tx.GetHash().ToString());
            return false;
        }

        deposit.strDest = strDest;

        fDestFound = true;
    }

    deposit.tx = tx;
    deposit.hashBlock = hashBlock;
    deposit.nTx = nTx;

    return (fBurnFound && fDestFound && CTransaction(deposit.tx) == tx);
}

std::string SidechainDB::ToString() const
{
    std::string str;
    str += "SidechainDB:\n";

    str += "Hash of block last seen: " + hashBlockLastSeen.ToString() + "\n";

    std::vector<Sidechain> vActiveSidechain = GetActiveSidechains();

    str += "Sidechains: ";
    str += std::to_string(vSidechain.size());
    str += "\n";
    for (const Sidechain& s : vActiveSidechain) {
        // Print sidechain name
        str += "Sidechain: " + s.GetSidechainName() + "\n";

        // Print sidechain Withdrawal workscore(s)
        std::vector<SidechainWithdrawalState> vState = GetState(s.nSidechain);
        str += "Withdrawal(s): ";
        str += std::to_string(vState.size());
        str += "\n";
        for (const SidechainWithdrawalState& state : vState) {
            str += "Withdrawal:\n";
            str += state.ToString();
        }
        str += "\n";

        // Print CTIP
        SidechainCTIP ctip;
        str += "CTIP:\n";
        if (GetCTIP(s.nSidechain, ctip)) {
            str += "txid: " + ctip.out.hash.ToString() + "\n";
            str += "n: " + std::to_string(ctip.out.n) + "\n";
            str += "amount: " + std::to_string(ctip.amount) + "\n";
        } else {
            str += "No CTIP found for sidechain.\n";
        }
        str += "\n";
    }

    str += "Sidechain proposal activation status:\n";

    if (!vActivationStatus.size())
        str += "No sidechain proposal status.\n";
    for (const SidechainActivationStatus& s : vActivationStatus) {
        str += s.proposal.ToString();
        str += "age: " + std::to_string(s.nAge) += "\n";
        str += "fails: " + std::to_string(s.nFail) += "\n";
    }
    str += "\n";

    return str;
}

bool SidechainDB::Update(int nHeight, const uint256& hashBlock, const uint256& hashPrevBlock, const std::vector<CTxOut>& vout, bool fJustCheck, bool fDebug)
{
    // NOTE: this makes a full copy of SCDB (including the deposit cache) to
    // test-apply the update before committing. The copy is deliberately
    // COMPLETE: ApplyUpdate's accept/reject result depends on the deposit cache
    // - IsSidechainActive() is defined as (nSidechain < vDepositCache.size())
    // and is checked on a return-false path, and UpdateActivationStatus indexes
    // vDepositCache[nSidechain] - so the copy must keep the cache intact and
    // correctly sized. (The deposit-sort CPU cost is bounded by the O(n)
    // SortDeposits instead.)
    SidechainDB scdbCopy = (*this);
    if (scdbCopy.ApplyUpdate(nHeight, hashBlock, hashPrevBlock, vout, fJustCheck, fDebug)) {
        return ApplyUpdate(nHeight, hashBlock, hashPrevBlock, vout, fJustCheck, fDebug);
    } else {
        return false;
    }
}

bool SidechainDB::ApplyUpdate(int nHeight, const uint256& hashBlock, const uint256& hashPrevBlock, const std::vector<CTxOut>& vout, bool fJustCheck, bool fDebug)
{
    if (!fJustCheck)
        TemplateStateChanged();
    if (hashBlock.IsNull()) {
        if (fDebug)
            LogPrintf("SCDB %s: Failed: block hash is null at height: %u\n",
                    __func__,
                    nHeight);
        return false;
    }

    if (!hashBlockLastSeen.IsNull() && hashPrevBlock.IsNull())
    {
        if (fDebug)
            LogPrintf("SCDB %s: Failed: previous block hash null at height: %u\n",
                    __func__,
                    nHeight);
        return false;
    }

    if (!vout.size())
    {
        if (fDebug)
            LogPrintf("SCDB %s: Failed: empty coinbase transaction at height: %u\n",
                    __func__,
                    nHeight);
        return false;
    }


    if (!hashBlockLastSeen.IsNull() && hashPrevBlock != hashBlockLastSeen) {
        if (fDebug)
            LogPrintf("SCDB %s: Failed: previous block hash: %s does not match hashBlockLastSeen: %s at height: %u\n",
                    __func__,
                    hashPrevBlock.ToString(),
                    hashBlockLastSeen.ToString(),
                    nHeight);
        return false;
    }

    /*
     * Look for data relevant to SCDB in this block's coinbase.
     *
     * Scan for new Withdrawal(s) and start tracking them.
     *
     * Scan for SCDB vote bytes, and update withdrawal scores
     *
     * Scan for sidechain proposals & sidechain activation commitments.
     *
     * Update hashBlockLastSeen.
     */

    // Scan for sidechain proposal commitments
    std::vector<Sidechain> vProposal;
    for (const CTxOut& out : vout) {
        const CScript& scriptPubKey = out.scriptPubKey;

        if (!scriptPubKey.IsSidechainProposalCommit())
            continue;

        Sidechain proposal;
        if (!proposal.DeserializeFromProposalScript(scriptPubKey))
            continue;

        vProposal.push_back(proposal);
    }

    // Maximum of 1 sidechain proposal per block
    if (vProposal.size() > 1) {
        if (fDebug)
            LogPrintf("SCDB %s: Invalid: block with multiple sidechain proposals at height: %u\n",
                    __func__,
                    nHeight);
        return false;
    }

    // Track sidechain proposal - from the fork (GetCTIPRulesHeight), once. A
    // proposal already pending, or identical to the sidechain active in its
    // slot, is NOT tracked again, and the block that repeats it stays VALID:
    // an honest proposer may re-include its own proposal in every block it
    // mines, so refusing the block would make honest blocks invalid. Tracking
    // it again adds a second entry that one ACK credits as well (each ACK
    // lookup matches every copy), and a copy left pending after the slot
    // activated can later "replace" the slot with itself on the same ACKs,
    // wiping its withdrawals, deposits and treasury pointer. The single
    // tracked entry keeps its own nAge and nFail exactly as if the repeat had
    // not been there (the repeat is not an ACK). Checked against the state
    // before this block's aging/activation pass, so a proposal expiring or
    // activating in this block is not re-tracked by a repeat in the same
    // block. Below the fork every proposal is tracked as before (0.45.1
    // behaviour, byte-identical SCDB state). Undo needs nothing: the
    // activation status is part of the state a disconnect restores.
    // Consensus rule from the fork height.
    if (!fJustCheck && vProposal.size() == 1) {
        const Sidechain& proposal = vProposal.front();
        if (nHeight >= GetCTIPRulesHeight() && IsSidechainProposalKnown(proposal)) {
            LogPrintf("SCDB %s: Sidechain proposal already tracked or active - not tracked again (block stays valid):\n%s\n",
                    __func__,
                    proposal.ToString());
        } else {
            SidechainActivationStatus status;
            status.nFail = 0;
            status.nAge = 0;
            status.proposal = proposal;

            // Start tracking the new sidechain proposal
            vActivationStatus.push_back(status);

            LogPrintf("SCDB %s: Tracking new sidechain proposal:\n%s\n",
                    __func__,
                    status.proposal.ToString());
        }
    }

    // Scan for sidechain activation commitments
    std::map<uint8_t, uint256> mapActivation;
    std::vector<uint256> vActivationHash;
    for (const CTxOut& out : vout) {
        const CScript& scriptPubKey = out.scriptPubKey;
        uint256 hashSidechain;
        if (!scriptPubKey.IsSidechainActivationCommit(hashSidechain))
            continue;
        if (hashSidechain.IsNull())
            continue;

        // Look up the sidechain number for this activation commitment
        bool fFound = false;
        uint8_t nSidechain = 0;
        for (const SidechainActivationStatus& s : vActivationStatus) {
            if (s.proposal.GetSerHash() == hashSidechain) {
                fFound = true;
                nSidechain = s.proposal.nSidechain;
                break;
            }
        }
        if (!fFound) {
            if (fDebug)
                LogPrintf("SCDB %s: Invalid: Sidechain activation commit for unknown proposal.\nProposal hash: %s\n",
                        __func__,
                        hashSidechain.ToString());
            return false;
        }

        // Small-block soft fork: from SmallBlockHeight a block may not commit
        // to activating an INACTIVE slot when the active sidechains plus the
        // inactive slots this block already commits to have reached
        // SIDECHAIN_SMALL_BLOCK_MAX_ACTIVE. A proposal needs a commitment in
        // nearly every block of its period, so refusing the commitment is
        // what stops the activation - and it stops it as a rejected block,
        // which old and new nodes both notice, rather than as a state they
        // silently disagree on. Replacements of an active slot are not
        // activations and pass. See sidechain.h for the number.
        if (nHeight >= Params().GetConsensus().SmallBlockHeight && !IsSidechainActive(nSidechain)) {
            unsigned int nNewInBlock = 0;
            for (const std::pair<const uint8_t, uint256>& kv : mapActivation) {
                if (!IsSidechainActive(kv.first))
                    nNewInBlock++;
            }
            if (GetActiveSidechainCount() + nNewInBlock + 1 > SIDECHAIN_SMALL_BLOCK_MAX_ACTIVE) {
                if (fDebug)
                    LogPrintf("SCDB %s: Invalid: activation commit for inactive sidechain %u at height %u would take the active count past the limit of %u (active %u, committed in this block %u).\n",
                            __func__, nSidechain, nHeight, SIDECHAIN_SMALL_BLOCK_MAX_ACTIVE,
                            GetActiveSidechainCount(), nNewInBlock);
                return false;
            }
        }

        // Check that there is only 1 sidechain activation commit per
        // sidechain slot number per block
        std::map<uint8_t, uint256>::const_iterator it = mapActivation.find(nSidechain);
        if (it == mapActivation.end()) {
            mapActivation[nSidechain] = hashSidechain;
        } else {
            if (fDebug) {
                LogPrintf("SCDB %s: Multiple activation commitments for sidechain number: %u at height: %u\n",
                        __func__,
                        nSidechain,
                        nHeight);
            }
            return false;
        }
        vActivationHash.push_back(hashSidechain);
    }
    if (!fJustCheck)
        UpdateActivationStatus(vActivationHash, nHeight);

    // Scan for new sidechain withdrawals. Check that there are no more than 1
    // new withdrawal per sidechain per block. Keep track of new withdrawals and
    // add them to SCDB later.
    std::map<uint8_t, uint256> mapNewWithdrawal;
    for (const CTxOut& out : vout) {
        const CScript& scriptPubKey = out.scriptPubKey;
        uint8_t nSidechain;
        uint256 hash;
        if (scriptPubKey.IsWithdrawalHashCommit(hash, nSidechain)) {
            if (!IsSidechainActive(nSidechain)) {
                if (fDebug)
                    LogPrintf("SCDB %s: Skipping new Withdrawal: %s, invalid sidechain number: %u\n",
                            __func__,
                            hash.ToString(),
                            nSidechain);
                continue;
            }

            // Check that there is only 1 new Withdrawal per sidechain per block
            std::map<uint8_t, uint256>::const_iterator it = mapNewWithdrawal.find(nSidechain);
            if (it == mapNewWithdrawal.end()) {
                mapNewWithdrawal[nSidechain] = hash;
            } else {
                if (fDebug) {
                    LogPrintf("SCDB %s: Multiple new withdrawals for sidechain number: %u at height: %u\n",
                            __func__,
                            nSidechain,
                            nHeight);
                }
                return false;
            }
        }
    }

    // age the failed set before anything below can consult
    // it, so a hash dropped at this height may be re-proposed in this block.
    // A no-op below SidechainParamsHeight.
    if (!fJustCheck)
        nFailedPrunedLastUpdate = PruneFailedWithdrawals(nHeight);

    // Update SCDB withdrawl vote scores and add new withdrawals
    if (!fJustCheck && (HasState() || mapNewWithdrawal.size())) {
        // Check if there are update bytes
        std::vector<CScript> vUpdateBytes;
        for (const CTxOut& out : vout) {
            const CScript scriptPubKey = out.scriptPubKey;
            if (scriptPubKey.IsSCDBBytes())
                vUpdateBytes.push_back(scriptPubKey);
        }
        // There is a maximum of 1 update bytes script
        if (vUpdateBytes.size() > 1) {
            if (fDebug)
                LogPrintf("SCDB %s: Error: multiple update byte scripts at height: %u\n",
                       __func__,
                       nHeight);
            return false;
        }

        // Read SCDB m4 update bytes, or create default abstain votes
        std::vector<std::string> vVote;
        if (vUpdateBytes.size()) {
            // Get old (current) state
            std::vector<std::vector<SidechainWithdrawalState>> vOldState;
            for (const Sidechain& s : vSidechain) {
                std::vector<SidechainWithdrawalState> vWithdrawal = GetState(s.nSidechain);
                if (vWithdrawal.size())
                    vOldState.push_back(vWithdrawal);
            }

            // Parse SCDB update bytes for new withdrawal scores
            if (!ParseSCDBBytes(vUpdateBytes.front(), vOldState, vVote)) {
                if (fDebug)
                    LogPrintf("SCDB %s: Error: Failed to parse update bytes at height: %u\n",
                            __func__,
                            nHeight);
                return false;
            }
            if (fDebug)
                LogPrintf("SCDB %s: Parsed update bytes at height: %u\n",
                        __func__,
                        nHeight);
        } else {
            vVote = std::vector<std::string>(SIDECHAIN_ACTIVATION_MAX_ACTIVE, std::string(1, SCDB_ABSTAIN));
        }

        bool fUpdated = UpdateSCDBIndex(vVote, nHeight, hashBlock, true /* fDebug */, mapNewWithdrawal);
        if (!fUpdated) {
            if (fDebug)
                LogPrintf("SCDB %s: Failed to update SCDB at height: %u\n",
                        __func__,
                        nHeight);
            return false;
        }
    }

    // Remove any Withdrawal(s) that were spent in this block. This can happen when a
    // new block is connected, re-connected, or during SCDB resync.
    std::vector<SidechainSpentWithdrawal> vSpent;
    vSpent = GetSpentWithdrawalsForBlock(hashBlock);
    for (const SidechainSpentWithdrawal& s : vSpent) {
        if (!IsSidechainActive(s.nSidechain)) {
            if (fDebug) {
                LogPrintf("SCDB %s: Spent Withdrawal has invalid sidechain number: %u at height: %u\n",
                        __func__,
                        s.nSidechain,
                        nHeight);
            }
            return false;
        }
        bool fRemoved = false;
        for (size_t i = 0; i < vWithdrawalStatus[s.nSidechain].size(); i++) {
            const SidechainWithdrawalState state = vWithdrawalStatus[s.nSidechain][i];
            if (state.nSidechain == s.nSidechain && state.hash == s.hash) {
                if (fDebug && !fJustCheck) {
                    LogPrintf("SCDB %s: Removing spent Withdrawal: %s for nSidechain: %u in block %s.\n",
                            __func__,
                            state.hash.ToString(),
                            state.nSidechain,
                            hashBlock.ToString());
                }

                fRemoved = true;
                if (fJustCheck)
                    break;

                // Remove the spent Withdrawal
                vWithdrawalStatus[s.nSidechain][i] = vWithdrawalStatus[s.nSidechain].back();
                vWithdrawalStatus[s.nSidechain].pop_back();
                break;
            }
        }
        if (!fRemoved) {
            if (fDebug) {
                LogPrintf("SCDB %s: Failed to remove spent Withdrawal: %s for sidechain: %u at height: %u\n",
                        __func__,
                        s.hash.ToString(),
                        s.nSidechain,
                        nHeight);
            }
            return false;
        }
    }
 /*
    if (fDebug && !fJustCheck) {
        LogPrintf("SCDB %s: Updated from block %s to block %s.\n",
                __func__,
                hashBlockLastSeen.ToString(),
                hashBlock.ToString());
    }
  */
    // Update hashBLockLastSeen
    if (!fJustCheck)
        hashBlockLastSeen = hashBlock;

    return true;
}

bool SidechainDB::Undo(int nHeight, const uint256& hashBlock, const uint256& hashPrevBlock, const std::vector<CTransactionRef>& vtx, bool fDebug)
{
    TemplateStateChanged();
    // Withdrawal workscore is recalculated by ResyncSCDB in validation - not here
    // Sidechain activation is also recalculated by ResyncSCDB not here.

    if (!vtx.size()) {
        LogPrintf("%s: SCDB undo failed for block: %s - vtx is empty!\n", __func__, hashBlock.ToString());
        return false;
    }

    // Remove cached Withdrawal spends from the block that was disconnected
    //
    // Unlike the failures below and the pointer further down, this one needs no
    // guard for the case where the parent's record supplied the map. Undo runs
    // on a copy just resynced to the parent, and this container is keyed by the
    // block that did the spending, so a map restored from the parent cannot
    // hold an entry under the hash of a block connected after it. The lookup
    // simply misses and the erase does nothing. It is the key that makes this
    // safe: the failure map is keyed by withdrawal hash, which is why an erase
    // there could take out a failure the parent still holds.
    std::map<uint256, std::vector<SidechainSpentWithdrawal>>::const_iterator it;
    it = mapSpentWithdrawal.find(hashBlock);
    if (it != mapSpentWithdrawal.end())
        mapSpentWithdrawal.erase(it);

    // Remove the withdrawal failures the disconnected block recorded.
    //
    // A failure is a fact about one chain, not about the bundle: it means the
    // bundle ran out of blocks to gather work score on the branch that was
    // being followed. On a different branch it may never have been proposed at
    // all. Keeping the record would leave this node refusing - via the
    // HaveFailedWithdrawal check in AddWithdrawal - the very block that
    // proposes that bundle on the chain the network settled on, which shows up
    // as a bad-scdb-update rejection and stops this node following the chain.
    //
    // Where the failures came from the parent's record they are already exactly
    // the parent's, so there is nothing to undo and the index is not consulted.
    // Consulting it anyway would be a small risk for no gain: this block's
    // entries name failures the restored set does not contain, and the only way
    // an erase could match is if the same bundle were also recorded failed
    // earlier - in which case it would remove a failure the parent still holds.
    // The index entry for this block is still dropped, so it does not
    // accumulate.
    std::map<uint256, std::vector<SidechainFailedWithdrawal>>::const_iterator itFailed;
    itFailed = mapFailedWithdrawalBlock.find(hashBlock);
    if (itFailed != mapFailedWithdrawalBlock.end()) {
        if (!fTreasuryFromRecord) {
            for (const SidechainFailedWithdrawal& f : itFailed->second) {
                // Only drop the record if it is still the one this block wrote.
                std::map<uint256, SidechainFailedWithdrawal>::const_iterator itMap;
                itMap = mapFailedWithdrawal.find(f.hash);
                if (itMap != mapFailedWithdrawal.end() &&
                        itMap->second.nSidechain == f.nSidechain) {
                    mapFailedWithdrawal.erase(itMap);

                    if (fDebug) {
                        LogPrintf("SCDB %s: Undid failure of Withdrawal: %s for sidechain: %u from block: %s\n",
                                __func__, f.hash.ToString(), f.nSidechain,
                                hashBlock.ToString());
                    }
                }
            }
        }
        mapFailedWithdrawalBlock.erase(itFailed);
    }

    // TODO lookup deposits in cache with setDepositTXID, then std::remove_if
    //
    // Undo deposits
    // Loop through the transactions in the block being disconnected, and if
    // they match a transaction in our deposit cache remove it.
    bool fDepositRemoved = false;
    std::set<uint8_t> setSlotRemoved;
    for (const CTransactionRef& tx : vtx) {
        for (size_t x = 0; x < vDepositCache.size(); x++) {
            std::vector<SidechainDeposit>::iterator it;
            for (it = vDepositCache[x].begin(); it != vDepositCache[x].end();) {
                if (*tx == CTransaction(it->tx)) {
                    setDepositTXID.erase(tx->GetHash());
                    fDepositRemoved = true;
                    setSlotRemoved.insert((uint8_t)x);
                    it = vDepositCache[x].erase(it);
                } else {
                    it++;
                }
            }
        }
    }

    // If any deposits were removed re-sort deposits and update CTIP
    if (fDepositRemoved) {
        // TODO check return value
        if (!SortSCDBDeposits()) {
            LogPrintf("SCDB %s: Failed to sort SCDB deposits!", __func__);
        }

        // Recompute the pointer from the deposit cache only when it did not
        // come from the parent's record.
        //
        // Undo is always called on a copy that was just resynced to the parent,
        // so when that record carried a treasury log the pointer is already
        // exactly the parent's. Recomputing it here would derive it from the
        // deposit cache instead, and the cache is the thing that is not
        // trustworthy: it is pruned to a bounded number of deposits per
        // sidechain, and after an unclean shutdown it can be short. Deriving a
        // pointer from it in that state would replace a correct value with a
        // wrong one - which is the divergence this record exists to prevent.
        //
        // The deposits are still removed above either way; only the pointer is
        // left to the record.
        if (fTreasuryFromRecord) {
            LogPrintf("SCDB %s: Treasury restored from the block record; leaving the pointer as recorded.\n",
                    __func__);
        } else {
            if (!UpdateCTIP(setSlotRemoved)) {
                LogPrintf("SCDB %s: Failed to update CTIP!", __func__);
            }
        }
    }

    // Undo hashBlockLastSeen
    hashBlockLastSeen = hashPrevBlock;

    // The parent state may hold a bundle this block paid out again as pending;
    // give the miner its bytes back so the replacing branch can pay it.
    RestorePaidWithdrawalTx(vtx);

    LogPrintf("%s: SCDB undo for block: %s complete!\n", __func__, hashBlock.ToString());

    return true;
}

void SidechainDB::RestorePaidWithdrawalTx(const std::vector<CTransactionRef>& vtx)
{
    // Observed in testing: a reorg across a payout restored
    // the bundle's work score from the parent's record, but SpendWithdrawal had
    // already dropped the raw bundle from vWithdrawalTxCache, so
    // CreateWithdrawalPayout found no outputs and silently built no payout -
    // block after block, until the bundle expired.
    //
    // A payout is the cached bundle plus the treasury input and the change
    // return, and GetBlindHash strips exactly those two, so the same transform
    // gives back the cached form byte for byte; the hash check below proves
    // it. Only bundles the (already resynced) parent state still lists as
    // pending are restored, so a bundle that is really gone is never offered
    // again. Nothing here is consensus state: the cache only feeds this node's
    // templates.
    for (const CTransactionRef& tx : vtx) {
        if (tx->IsCoinBase() || tx->vout.size() < 3)
            continue;
        uint8_t nSidechain;
        if (!tx->vout.back().scriptPubKey.IsDrivechain(nSidechain))
            continue;
        if (nSidechain >= vWithdrawalStatus.size())
            continue;
        uint256 hashBlind;
        if (!tx->GetBlindHash(hashBlind))
            continue;
        bool fPending = false;
        for (const SidechainWithdrawalState& s : vWithdrawalStatus[nSidechain]) {
            if (s.hash == hashBlind) {
                fPending = true;
                break;
            }
        }
        if (!fPending || HaveWithdrawalTxCached(hashBlind))
            continue;

        CMutableTransaction mtx(*tx);
        mtx.vin.clear();
        mtx.vin.resize(1);
        mtx.vin[0].scriptSig = CScript() << OP_0;
        mtx.vout.pop_back();
        if (mtx.GetHash() != hashBlind)
            continue;

        TemplateStateChanged();
        vWithdrawalTxCache.push_back(std::make_pair(nSidechain, mtx));
        LogPrintf("SCDB %s: Restored raw Withdrawal %s for sidechain %u from a disconnected payout.\n",
                __func__, hashBlind.ToString(), nSidechain);
    }
}

bool SidechainDB::UpdateSCDBIndex(const std::vector<std::string>& vVote, int nHeight, const uint256& hashBlock, bool fDebug, const std::map<uint8_t, uint256>& mapNewWithdrawal)
{
    TemplateStateChanged();
    if (vWithdrawalStatus.empty()) {
        if (fDebug)
            LogPrintf("SCDB %s: Update failed: vWithdrawalStatus is empty!\n",
                    __func__);
        return false;
    }

    // Remove expired withdrawals
    RemoveExpiredWithdrawals(nHeight, hashBlock);

    // Age existing withdrawals
    for (size_t x = 0; x < vWithdrawalStatus.size(); x++) {
        for (size_t y = 0; y < vWithdrawalStatus[x].size(); y++) {
            if (vWithdrawalStatus[x][y].nBlocksLeft > 0)
                vWithdrawalStatus[x][y].nBlocksLeft--;
        }
    }

    if (vVote.size() != vWithdrawalStatus.size()) {
        if (fDebug)
            LogPrintf("SCDB %s: Update failed: vVote size is invalid!\n",
                    __func__);
        return false;
    }

    // Update withdrawal scores
    for (size_t x = 0; x < vWithdrawalStatus.size(); x++) {
        if (vVote[x].empty()) {
            if (fDebug)
                LogPrintf("SCDB %s: Update failed: vote characters invalid!\n",
                        __func__);
            return false;
        }

        // What type of vote do we have for this sidechain?
        uint256 hash = uint256();
        char vote = SCDB_ABSTAIN;
        if (vVote[x].size() == 64) {
            hash = uint256S(vVote[x]);
            if (hash.IsNull()) {
                if (fDebug)
                    LogPrintf("SCDB %s: Update failed: upvote hash invalid!\n",
                            __func__);
                return false;
            }
            vote = SCDB_UPVOTE;
        }
        else
        if (vVote[x].front() == SCDB_DOWNVOTE)
            vote = SCDB_DOWNVOTE;

        // Apply score changes. Do not apply score changes to withdrawals for
        // any sidechain that has added a new withdrawal
        for (size_t y = 0; y < vWithdrawalStatus[x].size(); y++) {
            if (mapNewWithdrawal.find(x) != mapNewWithdrawal.end())
                continue;

            if (vote == SCDB_UPVOTE) {
                if (vWithdrawalStatus[x][y].hash == hash) {
                    // Was a literal 65535 - the uint16_t anti-wrap guard. Left
                    // alone it freezes every score at 65,535 while the mainnet
                    // threshold is 129,600, so NO withdrawal could ever be paid
                    // out. The guard is still needed, at the new width.
                    if (vWithdrawalStatus[x][y].nWorkScore < std::numeric_limits<uint32_t>::max())
                        vWithdrawalStatus[x][y].nWorkScore++;
                } else {
                    if (vWithdrawalStatus[x][y].nWorkScore > 0)
                        vWithdrawalStatus[x][y].nWorkScore--;
                }
            }
            else
            if (vote == SCDB_DOWNVOTE) {
                    if (vWithdrawalStatus[x][y].nWorkScore > 0)
                        vWithdrawalStatus[x][y].nWorkScore--;
            }
        }
    }

    // Add new withdrawals
    for (const std::pair<uint8_t, uint256>& p : mapNewWithdrawal) {
        if (!AddWithdrawal(p.first, p.second, nHeight, true /* fDebug */)) {
            if (fDebug)
                LogPrintf("SCDB %s: Failed to add withdrawal!\n", __func__);
            return false;
        }
    }

    return true;
}

void SidechainDB::ApplyDefaultUpdate(int nHeight, const uint256& hashBlock)
{
    TemplateStateChanged();
    if (!HasState())
        return;

    // Decrement nBlocksLeft, nothing else changes
    for (size_t x = 0; x < vWithdrawalStatus.size(); x++) {
        for (size_t y = 0; y < vWithdrawalStatus[x].size(); y++) {
            if (vWithdrawalStatus[x][y].nBlocksLeft > 0)
                vWithdrawalStatus[x][y].nBlocksLeft--;
        }
    }

    // Remove expired Withdrawal(s)
    RemoveExpiredWithdrawals(nHeight, hashBlock);
}

void SidechainDB::UpdateActivationStatus(const std::vector<uint256>& vHash, int nHeight)
{
    TemplateStateChanged();
    // TODO change containers

    // Increment the age of all sidechain proposals and remove expired.
    std::vector<SidechainActivationStatus>::iterator it;
    for (it = vActivationStatus.begin(); it != vActivationStatus.end();) {
        it->nAge++;

        int nPeriod = 0;
        if (IsSidechainActive(it->proposal.nSidechain))
            nPeriod = GetSidechainReplacementPeriod(nHeight);
        else
            nPeriod = GetSidechainActivationPeriod(nHeight);

        if (it->nAge > nPeriod) {
            LogPrintf("SCDB %s: Sidechain proposal expired:\n%s\n",
                    __func__,
                    it->proposal.ToString());

            it = vActivationStatus.erase(it);
        } else {
            it++;
        }
    }

    // Calculate failures. Sidechain proposals with activation status will have
    // their activation failure count increased by 1 if a activation commitment
    // for them is not found in the block. New sidechain proposals (age = 1)
    // count as an activation commitment.
    for (size_t i = 0; i < vActivationStatus.size(); i++) {
        // Skip new sidechain proposals
        if (vActivationStatus[i].nAge == 1)
            continue;

        // Search for sidechain activation commitments
        bool fFound = false;
        for (const uint256& u : vHash) {
            if (u == vActivationStatus[i].proposal.GetSerHash()) {
                fFound = true;
                break;
            }
        }
        if (!fFound)
            vActivationStatus[i].nFail++;
    }

    // Remove sidechain proposals with too many failures to activate
    for (it = vActivationStatus.begin(); it != vActivationStatus.end();) {
        if (it->nFail >= GetSidechainActivationMaxFailures(nHeight)) {
            LogPrintf("SCDB %s: Sidechain proposal rejected:\n%s\n",
                    __func__,
                    it->proposal.ToString());

            it = vActivationStatus.erase(it);
        } else {
            it++;
        }
    }

    // Search for sidechains that have passed the test and should be activated.
    for (it = vActivationStatus.begin(); it != vActivationStatus.end();) {
        // The required period to be activated is either the normal sidechain
        // activation period for a new sidechain, or the same as the Withdrawal
        // minimum workscore for a proposal that replaces an active sidechain.
        int nPeriodRequired = 0;
        if (IsSidechainActive(it->proposal.nSidechain))
            nPeriodRequired = GetSidechainReplacementPeriod(nHeight);
        else
            nPeriodRequired = GetSidechainActivationPeriod(nHeight);

        // If a proposal makes it to the required age without being killed off
        // by failures then it will be activated.
        //
        // Unreachable on a chain that obeyed the commitment rule above
        // (a proposal cannot reach this age without commitments this rule
        // refused), kept so the active count can never pass the limit by
        // any path: refuse the activation and drop the proposal instead.
        if (it->nAge == nPeriodRequired &&
                nHeight >= Params().GetConsensus().SmallBlockHeight &&
                !IsSidechainActive(it->proposal.nSidechain) &&
                GetActiveSidechainCount() >= SIDECHAIN_SMALL_BLOCK_MAX_ACTIVE) {
            LogPrintf("SCDB %s: Sidechain proposal refused at activation - %u sidechains are already active, the limit from SmallBlockHeight:\n%s\n",
                    __func__, GetActiveSidechainCount(), it->proposal.ToString());
            it = vActivationStatus.erase(it);
            continue;
        }
        // Escrow rules: from EscrowRulesHeight a proposal that would
        // REPLACE an active sidechain is refused while the slot's treasury
        // holds coins. Activation below erases the slot's CTIP, which strands
        // every coin in it: no withdrawal can spend a treasury no node points
        // at, and the incoming sidechain starts a new one. A slot with no
        // treasury, or an empty one, is still replaceable under the unchanged
        // replacement rule. Refused here, at the moment of activation, rather
        // than at proposal time, because the treasury can be emptied (or
        // refilled) during the replacement period.
        if (it->nAge == nPeriodRequired &&
                nHeight >= Params().GetConsensus().EscrowRulesHeight &&
                IsSidechainActive(it->proposal.nSidechain)) {
            std::map<uint8_t, SidechainCTIP>::const_iterator itCTIP = mapCTIP.find(it->proposal.nSidechain);
            if (itCTIP != mapCTIP.end() && itCTIP->second.amount > 0) {
                LogPrintf("SCDB %s: Sidechain replacement refused - slot %u treasury holds %d, the escrow rules from EscrowRulesHeight:\n%s\n",
                        __func__, it->proposal.nSidechain, itCTIP->second.amount, it->proposal.ToString());
                it = vActivationStatus.erase(it);
                continue;
            }
        }
        if (it->nAge == nPeriodRequired) {
            // Create sidechain object from proposal
            Sidechain sidechain;
            sidechain.fActive = true;
            sidechain.nSidechain    = it->proposal.nSidechain;
            sidechain.nVersion      = it->proposal.nVersion;
            sidechain.hashID1       = it->proposal.hashID1;
            sidechain.hashID2       = it->proposal.hashID2;
            sidechain.title         = it->proposal.title;
            sidechain.description   = it->proposal.description;

            // Update nSidechain slot with new sidechain params
            vSidechain[sidechain.nSidechain] = sidechain;

            // Remove from cache of our own proposals
            for (size_t j = 0; j < vSidechainProposal.size(); j++) {
                if (it->proposal == vSidechainProposal[j]) {
                    vSidechainProposal[j] = vSidechainProposal.back();
                    vSidechainProposal.pop_back();
                    break;
                }
            }
            // Remove SCDB proposal activation status
            it = vActivationStatus.erase(it);

            // Reset Withdrawal status for new sidechain
            vWithdrawalStatus[sidechain.nSidechain].clear();

            // Reset deposits for new sidechain. Shared with the rebuild pass,
            // which sees this handover as a change of occupant between two
            // consecutive records and has to reproduce its effect exactly.
            ResetSlotDeposits(sidechain.nSidechain);

            // Reset CTIP for new sidechain, and its treasury log entry with it:
            // the incoming occupant of the slot must not inherit the previous
            // one's pointer through the per-block record.
            mapCTIP.erase(sidechain.nSidechain);
            mapTreasury.erase(sidechain.nSidechain);

            // Drop the previous occupant's bundles and the standing vote for
            // them. Clearing the score table above destroys a mid-scoring
            // bundle's record without writing a failure, so AddWithdrawal will
            // happily re-admit that bundle at score 1 - and the miner offers it
            // again automatically, because the raw bytes are still cached under
            // the same slot number and the sidechain script is built from the
            // slot alone. With the vote also surviving, the bundle can reach
            // the threshold again and pay the previous sidechain's withdrawers
            // out of the incoming sidechain's treasury, with nobody making a
            // fresh decision and nothing to detect it: value is conserved and
            // the treasury pointer stays consistent.
            vWithdrawalTxCache.erase(
                    std::remove_if(vWithdrawalTxCache.begin(), vWithdrawalTxCache.end(),
                                   [&sidechain](const std::pair<uint8_t, CMutableTransaction>& p) {
                                       return p.first == sidechain.nSidechain;
                                   }),
                    vWithdrawalTxCache.end());
            for (std::set<std::pair<uint8_t, uint256>>::iterator it = setDisplacedWithdrawal.begin();
                    it != setDisplacedWithdrawal.end(); ) {
                if (it->first == sidechain.nSidechain)
                    it = setDisplacedWithdrawal.erase(it);
                else
                    ++it;
            }

            if (sidechain.nSidechain < vVoteCache.size())
                vVoteCache[sidechain.nSidechain] = std::string(1, SCDB_ABSTAIN);

            LogPrintf("SCDB %s: Slot %u changed occupant - dropped its cached bundles and reset its vote.\n",
                    __func__, sidechain.nSidechain);

            LogPrintf("SCDB %s: Sidechain activated:\n%s\n",
                    __func__,
                    sidechain.ToString());
        } else {
            it++;
        }
    }
}

bool SidechainDB::SortSCDBDeposits()
{
    std::vector<std::vector<SidechainDeposit>> vDepositSorted;

    // Loop through deposits and sort the vector for each sidechain
    for (size_t nSidechain = 0; nSidechain < vDepositCache.size(); nSidechain++) {
        const std::vector<SidechainDeposit>& v = vDepositCache[nSidechain];
        std::vector<SidechainDeposit> vDeposit;
        if (!SortDeposits(v, vDeposit)) {
            // Return before assigning: on failure the whole cache must stay
            // exactly as it was (insertion order), on every node alike.
            LogPrintf("%s: sidechain slot %u deposits not sortable (see the line above); cache left untouched\n", __func__, (unsigned)nSidechain);
            return false;
        }
        vDepositSorted.push_back(vDeposit);
    }

    // Update deposit cache with sorted list
    vDepositCache = vDepositSorted;

    return true;
}

bool SidechainDB::UpdateCTIP(const std::set<uint8_t>& setSlot)
{
    for (const uint8_t x : setSlot) {
        if (x >= vDepositCache.size())
            continue;

        if (vDepositCache[x].size()) {
            const SidechainDeposit& d = vDepositCache[x].back();

            if (d.nBurnIndex >= d.tx.vout.size())
                return false;

            const COutPoint out(d.tx.GetHash(), d.nBurnIndex);
            const CAmount amount = d.tx.vout[d.nBurnIndex].nValue;

            SidechainCTIP ctip;
            ctip.out = out;
            ctip.amount = amount;

            // Advance the treasury log only when the pointer actually moves.
            // UpdateCTIP runs after every AddDeposits and after Undo, most of
            // which leave the pointer where it was; counting those would make
            // the movement counter a call counter instead.
            std::map<uint8_t, SidechainCTIP>::const_iterator itOld = mapCTIP.find(d.nSidechain);
            const bool fMoved = (itOld == mapCTIP.end() || itOld->second.out != out ||
                                 itOld->second.amount != amount);
            if (fMoved) {
                SidechainTreasuryEntry entry;
                entry.nSidechain = d.nSidechain;
                entry.out = out;
                entry.amount = amount;
                entry.amountPrev = (itOld != mapCTIP.end()) ? itOld->second.amount : 0;

                std::map<uint8_t, SidechainTreasuryEntry>::const_iterator itLog = mapTreasury.find(d.nSidechain);
                entry.nSeq = (itLog != mapTreasury.end()) ? itLog->second.nSeq + 1 : 0;

                mapTreasury[d.nSidechain] = entry;
            }

            mapCTIP[d.nSidechain] = ctip;

            // Log the update
            LogPrintf("SCDB %s: Updated sidechain CTIP for nSidechain: %u. CTIP output: %s CTIP amount: %i.\n",
                __func__,
                d.nSidechain,
                out.ToString(),
                amount);
        } else if (!fTreasuryFromRecord) {
            // If there are no deposits now, remove CTIP for nSidechain
            std::map<uint8_t, SidechainCTIP>::const_iterator it;
            it = mapCTIP.find(x);

            if (it != mapCTIP.end()) {
                mapCTIP.erase(it);
                // Drop the log entry with it: the record stores the treasury of
                // the sidechains that have one, so a stale entry left behind
                // here would be written back out and restored as a pointer the
                // chain no longer supports.
                //
                // Skipped entirely when the treasury came from the per-block
                // record: there the pointer is the record's to state, an empty
                // cache means only that this node holds no deposit history for
                // the slot, and erasing would write a treasury the chain still
                // supports out of the next block's record. A slot losing its
                // occupant is not this case - activation erases the pointer
                // itself.
                mapTreasury.erase((uint8_t)x);
                LogPrintf("SCDB %s: Removed sidechain CTIP.\n",
                    __func__);
            }

        }
    }
    return true;
}

bool DecodeWithdrawalFees(const CScript& script, CAmount& amount)
{
    // Security fix (OOB read): check the size BEFORE indexing script[0]. The
    // script here is an attacker-supplied tx.vout[1].scriptPubKey which may be
    // empty; the old order dereferenced script[0] on an empty prevector first
    // (undefined behaviour). && short-circuits, so size 10 is verified first.
    if (script.size() != 10 || script[0] != OP_RETURN) {
        LogPrintf("%s: Error: Invalid script!\n", __func__);
        return false;
    }

    CScript::const_iterator it = script.begin() + 1;
    std::vector<unsigned char> vch;
    opcodetype opcode;

    if (!script.GetOp(it, opcode, vch)) {
        LogPrintf("%s: Error: GetOp failed!\n", __func__);
        return false;
    }

    if (vch.empty()) {
        LogPrintf("%s: Error: Amount bytes empty!\n", __func__);
        return false;
    }

    if (vch.size() > 8) {
        LogPrintf("%s: Error: Amount bytes too large!\n", __func__);
        return false;
    }

    try {
        CDataStream ds(vch, SER_NETWORK, PROTOCOL_VERSION);
        ds >> amount;
    } catch (const std::exception&) {
        LogPrintf("%s: Error: Failed to deserialize amount!\n", __func__);
        return false;
    }

    // Nothing read out of a script is an amount until it has been range
    // checked. The two callers that do arithmetic on this one subtract it from
    // a treasury value - the change equation in SpendWithdrawal, and the
    // amount half of the treasury anchor in ConnectBlock - and a value outside
    // the money range does not make those sums fail, it makes them wrap: the
    // tree is built with -fwrapv, so the wrap is well defined and identical on
    // every release binary. That is the worse outcome of the two, because it
    // is choosable. An attacker picks the eight bytes that make the wrapped
    // equality hold, and a check that can be satisfied by wraparound is not
    // checking anything. Rejecting it here covers both of them in one place,
    // and rejects a negative fee total as well, which the format has no reason
    // ever to carry.
    //
    // This bounds the encoded fee term; the other term is a transaction's own
    // value out, which consensus already caps at MAX_MONEY.
    if (!MoneyRange(amount)) {
        LogPrintf("%s: Error: Amount out of range!\n", __func__);
        return false;
    }

    return true;
}

bool GetWithdrawalChangeDeposit(const CTransaction& tx, int nTx, const uint256& hashBlock,
                                uint8_t nSidechain, SidechainDeposit& deposit)
{
    // Find the single output returning change to the sidechain script. More
    // than one makes the bundle invalid, which SpendWithdrawal rejects before
    // it ever gets here.
    bool fFound = false;
    uint32_t nBurnIndex = 0;
    for (size_t i = 0; i < tx.vout.size(); i++) {
        const CScript& scriptPubKey = tx.vout[i].scriptPubKey;
        if (!scriptPubKey.size())
            continue;

        uint8_t nSidechainScript;
        if (!scriptPubKey.IsDrivechain(nSidechainScript))
            continue;

        if (fFound)
            return false;

        if (nSidechainScript != nSidechain)
            return false;

        nBurnIndex = i;
        fFound = true;
    }

    if (!fFound)
        return false;

    deposit.nSidechain = nSidechain;
    deposit.strDest = SIDECHAIN_WITHDRAWAL_RETURN_DEST;
    deposit.tx = tx;
    deposit.nBurnIndex = nBurnIndex;
    deposit.nTx = nTx;
    deposit.hashBlock = hashBlock;

    return true;
}

bool SortDeposits(const std::vector<SidechainDeposit>& vDeposit, std::vector<SidechainDeposit>& vDepositSorted)
{
    if (vDeposit.empty())
        return true;

    if (vDeposit.size() == 1) {
        vDepositSorted = vDeposit;
        return true;
    }

    // Security fix (CPU-exhaustion DoS): the previous implementation was two
    // nested O(n^2) loops that recomputed dy.tx.GetHash() (an UNCACHED full
    // serialize + double-SHA256) on every iteration, so sorting a cache of n
    // deposits cost ~n^2 transaction hashes on the ConnectBlock hot path. This
    // rewrite is O(n log n): it computes each deposit's CTIP outpoint exactly
    // ONCE (n hashes total) and then walks the spend chain via a map. The
    // ordering it produces is byte-identical to the old code - same "first
    // deposit is the one spending a CTIP not in the list (exactly one)" rule
    // and the same "first spender in list order" tie-break (std::map::emplace
    // keeps the first insertion, matching the old begin()-rescan).

    // Compute each deposit's own CTIP outpoint once.
    std::vector<COutPoint> vCTIP(vDeposit.size());
    std::set<COutPoint> setCTIP;
    for (size_t x = 0; x < vDeposit.size(); x++) {
        vCTIP[x] = COutPoint(vDeposit[x].tx.GetHash(), vDeposit[x].nBurnIndex);
        setCTIP.insert(vCTIP[x]);
    }

    // Map each in-list CTIP outpoint to the first deposit (list order) that
    // spends it, and find the single deposit that spends no in-list CTIP - the
    // head of the chain.
    std::map<COutPoint, size_t> mapSpender;
    int nMissingCTIP = 0;
    size_t nFirst = 0;
    for (size_t x = 0; x < vDeposit.size(); x++) {
        bool fFound = false;
        for (const CTxIn& in : vDeposit[x].tx.vin) {
            if (setCTIP.count(in.prevout)) {
                fFound = true;
                mapSpender.emplace(in.prevout, x); // keeps first spender
            }
        }
        if (!fFound) {
            nMissingCTIP++;
            if (nMissingCTIP > 1) {
                // Not an error of this node: "Multiple missing CTIP" means the
                // deposits form more than one chain, i.e. the on-chain deposit
                // history itself forked. On mainnet that is Thunder's second
                // treasury chain, started by a January-2024 deposit that did not
                // spend the then-current CTIP,
                // so every node logs this at every startup resync and whenever a
                // block adds a deposit to that slot. The caller keeps insertion
                // order and the CTIP is unaffected.
                LogPrintf("%s: Multiple missing CTIP - %u deposits form more than one chain (forked deposit history; expected on mainnet); not sortable, insertion order kept, CTIP unaffected\n",
                          __func__, (unsigned)vDeposit.size());
                return false;
            }
            nFirst = x;
        }
    }

    if (nMissingCTIP == 0) {
        LogPrintf("%s: Error: Could not find first deposit in list!\n", __func__);
        return false;
    }

    // Walk the spend chain forward from the head. The size guard bounds any
    // malformed/cyclic input (which then fails the size check below, exactly
    // as the old implementation's result-size check did).
    vDepositSorted.push_back(vDeposit[nFirst]);
    COutPoint prevout = vCTIP[nFirst];
    std::map<COutPoint, size_t>::const_iterator itSpender = mapSpender.find(prevout);
    while (itSpender != mapSpender.end() && vDepositSorted.size() <= vDeposit.size()) {
        const size_t idx = itSpender->second;
        vDepositSorted.push_back(vDeposit[idx]);
        prevout = vCTIP[idx];
        itSpender = mapSpender.find(prevout);
    }

    if (vDeposit.size() != vDepositSorted.size()) {
        LogPrintf("%s: Error: Invalid result size! In: %u Out: %u\n", __func__,
                vDeposit.size(), vDepositSorted.size());
        return false;
    }

    return true;
}

bool ParseSCDBBytes(const CScript& script, const std::vector<std::vector<SidechainWithdrawalState>>& vOldScores, std::vector<std::string>& vVote)
{
    if (script.size() < 8 || !script.IsSCDBBytes()) {
        LogPrintf("SCDB %s: Error: script not SCDB update bytes!\n", __func__);
        return false;
    }

    if (vOldScores.empty()) {
        LogPrintf("SCDB %s: Error: no old scores!\n", __func__);
        return false;
    }

    uint8_t nVersion = script[5];
    if (nVersion > SCDB_BYTES_MAX_VERSION) {
        LogPrintf("SCDB %s: Error: Invalid version!\n", __func__);
        return false;
    }

    for (const std::vector<SidechainWithdrawalState>& v : vOldScores) {
        if (v.empty()) {
            LogPrintf("SCDB %s: Error: invalid (empty) old scores!\n", __func__);
            return false;
        }
    }

    vVote.clear();
    vVote = std::vector<std::string>(SIDECHAIN_ACTIVATION_MAX_ACTIVE, std::string(1, SCDB_ABSTAIN));

    CScript bytes = CScript(script.begin() + 6, script.end());

    // Security fix (consensus split / OOB read): votes are encoded as exactly
    // two bytes each. The loop below reads bytes[i] and bytes[i + 1] with step
    // 2, so an odd-length payload would read bytes[bytes.size()] one past the
    // end of the prevector-backed CScript (operator[] does no bounds check ->
    // undefined behaviour). The garbage byte would then decide the vote, so
    // different nodes could accept/reject the identical block. IsSCDBBytes()
    // does not constrain parity, so reject an odd-length payload here.
    if (bytes.size() % 2 != 0) {
        LogPrintf("SCDB %s: Error: odd number of SCDB update bytes!\n", __func__);
        return false;
    }

    // The score index is the current vector of withdrawal bundle scores
    // we are looping through. This is different than the sidechain number,
    // because a vector of scores will only be passed in for sidechains
    // with pending withdrawals and otherwise skipped.
    size_t nScoreIndex = 0;
    for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
        if (nScoreIndex >= vOldScores.size()) {
            LogPrintf("SCDB %s: Error: invalid upvote index - too large!\n", __func__);
            return false;
        }

        // Copy sidechain number from first withdrawal at score index
        size_t nSidechain = vOldScores[nScoreIndex][0].nSidechain;

        if (bytes[i] == 0xFF && bytes[i + 1] == 0xFF) {
            // Abstain bytes
            vVote[nSidechain] = SCDB_ABSTAIN;
        }
        else
        if (bytes[i] == 0xFF && bytes[i + 1] == 0xFE) {
            // Downvote bytes
            vVote[nSidechain] = SCDB_DOWNVOTE;
        }
        else {
            // Upvote index
            uint16_t n = bytes[i] | bytes[i + 1] << 8;

            if (n >= vOldScores[nScoreIndex].size()) {
                LogPrintf("SCDB %s: Error: invalid upvote index - too large!\n", __func__);
                return false;
            }

            // Lookup withdrawal bundle hash and add to votes
            vVote[nSidechain] = vOldScores[nScoreIndex][n].hash.ToString();
        }

        nScoreIndex++;
    }

    return true;
}
