// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <uint256.h>
#include <limits>
#include <map>
#include <string>

namespace Consensus {

enum DeploymentPos
{
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_CSV, // Deployment of BIP68, BIP112, and BIP113.
    DEPLOYMENT_SEGWIT, // Deployment of BIP141, BIP143, and BIP147.
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in versionbits.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit;
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime;
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout;

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /** Block height at which BIP16 becomes active */
    int BIP16Height;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which Drivechain becomes active */
    int DrivechainHeight;
    /** Block height at which the small-block rule becomes active (part of
     *  the hard fork). From this height on, a block's committed size (see
     *  MAX_SMALL_BLOCK_SERIALIZED_SIZE) must not exceed that limit. */
    int SmallBlockHeight;
    /** Block height from which the first block of each difficulty adjustment
     *  period must have nTime >= prev->nTime - MAX_TIMEWARP. Tightening soft
     *  fork (timewarp guard); see chain.h MAX_TIMEWARP. */
    int TimewarpGuardHeight;
    /** Block height from which the production Drivechain sidechain parameters
     *  (withdrawal verification period / min workscore, activation period /
     *  max failures) replace the legacy testing values. Coordinated flag day:
     *  all nodes must agree. See GetSidechain*() in sidechain.h. */
    int SidechainParamsHeight;
    /** The production withdrawal window, in blocks, used at/after
     *  SidechainParamsHeight.
     *
     *  PER-NETWORK, and that is the point of them living here rather than as
     *  globals in sidechain.h. The window is a wall-clock policy - how long the
     *  social-defense period should be - and the networks do not share a block
     *  spacing (mainnet 60s, testnet 10s), so one block count cannot express
     *  one policy on both. Every previous discussion of these values assumed a
     *  single global number; that assumption is what these two fields retire.
     *
     *  WithdrawalMinWorkScore is how many upvoting blocks a bundle must
     *  accumulate; WithdrawalVerificationPeriod is how long it may remain
     *  votable, conventionally twice the former. Both are hashed into the SCDB
     *  commitment by way of SidechainWithdrawalState, so changing them at a
     *  reachable height is a coordinated fork. */
    int WithdrawalMinWorkScore;
    int WithdrawalVerificationPeriod;
    /** How long a withdrawal bundle that FAILED at or after
     *  SidechainParamsHeight stays in the failed set, in blocks. At block
     *  height h every failure recorded at height f >= SidechainParamsHeight
     *  with f + WithdrawalFailedRetention <= h is dropped, so the set that
     *  GetCommitmentHash hashes into every block and the per-block record
     *  carries is bounded. Failures recorded below
     *  SidechainParamsHeight are a fixed, finite set and are never dropped.
     *  Consensus from SidechainParamsHeight: it decides whether AddWithdrawal
     *  re-admits a hash. Per-network for the same reason as the window. */
    int WithdrawalFailedRetention;
    /** Whether the block AT SidechainParamsHeight expires the in-flight
     *  bundles WITHOUT recording them failed (the boundary sweep, chosen
     *  on purpose). True on mainnet and regtest. False on
     *  testnet only because testnet already crossed that height
     *  under earlier rules, which recorded one bundle failed there;
     *  turning the sweep on retroactively would make
     *  this release reject the existing testnet chain. */
    bool fWithdrawalBoundarySweep;
    /** The production sidechain ACTIVATION window, in blocks, used at/after
     *  SidechainParamsHeight.
     *
     *  Per-network for the same reason the withdrawal window is: 2,016 blocks
     *  is Drivechain's count for Bitcoin's 600s spacing - 14 days there, 1.4
     *  days on mainnet here, and 5.6 HOURS on testnet at 10s. One number cannot
     *  be one policy on three chains with three spacings.
     *
     *  It also sets a floor under the withdrawal window: a chain whose
     *  withdrawal window is SHORTER than its activation window is one where
     *  bundles pay out faster than sidechains activate, which mainnet can never
     *  be, so a testnet configured that way cannot reproduce mainnet's failure
     *  modes.
     *
     *  ActivationMaxFailures rides it: the BIP300 ~90% commitment ratio
     *  (201/2016) is spacing-independent and must be preserved when the period
     *  moves. */
    int SidechainActivationPeriod;
    int SidechainActivationMaxFailures;
    /** Block height from which every block's coinbase must carry exactly one
     *  SCDB hash commitment (OP_RETURN D8 5C DB C0 + 32 bytes) matching
     *  SidechainDB::GetCommitmentHash() of the post-connect state.
     *  Coordinated flag day: all nodes must agree, and a node whose sidechain
     *  state diverged before the height rejects every honest block from it -
     *  deliberately, which is why activation requires the census first.
     *  This is the SCDB state commitment. */
    int SCDBCommitmentHeight;
    /** Block height from which every carried sidechain treasury pointer must
     *  be anchored to the unspent output set: its coin unspent, with script
     *  [OP_DRIVECHAIN, n] and exactly its recorded amount; a block's deposits
     *  for a slot that holds a pointer must chain from it; and a withdrawal's
     *  amounts must satisfy the objective equations read from the spent coin
     *  rather than from the recorded pointer.
     *  The pointer is still carried state and its transition is unchanged -
     *  this anchors it, it never derives it, which is what keeps the
     *  committed form of the state identical either side of the height.
     *  Coordinated flag day, and it must not ride the same activation as
     *  SCDBCommitmentHeight. This is the deposit-chain anchor. */
    int CTIPAnchorHeight;
    /** Block height from which two BIP300 escrow rules apply (the
     *  2026-10-31 hard fork):
     *   - an M6 (withdrawal payout) whose fee-commitment output, vout[1],
     *     carries any value is invalid (BIP300 as revised 2023-07-26,
     *     bips 796c80eb: that output must be zero-value);
     *   - a proposal that would REPLACE an active sidechain is refused at
     *     activation while that slot's treasury (CTIP) holds coins, so a
     *     replacement can no longer strand the escrow. A slot whose treasury
     *     is empty, or has none, may still be replaced under the unchanged
     *     replacement rule.
     *  Coordinated flag day. On mainnet it must equal the other fork gates
     *  (1,976,112). */
    int EscrowRulesHeight;
    /** Minimum valid blockchain height */
    int MinimumHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    bool fPowNoRetargeting;
    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    uint256 nMinimumChainWork;
    uint256 defaultAssumeValid;
};
} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
