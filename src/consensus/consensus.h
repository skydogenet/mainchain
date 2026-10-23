// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <stdlib.h>
#include <stdint.h>


/** The maximum allowed size for a serialized block, in bytes (only for buffer size limits) */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 4000000;
/** The maximum allowed weight for a block, see BIP 141 (network rule) */
static const unsigned int MAX_BLOCK_WEIGHT = 4000000;
/** The maximum allowed number of signature check operations in a block (network rule) */
static const int64_t MAX_BLOCK_SIGOPS_COST = 80000;
/** The maximum allowed COMMITTED serialized size for a block, in bytes, at and
 *  after Consensus::Params::SmallBlockHeight (network rule).
 *
 *  READ "COMMITTED" CAREFULLY - this is NOT the block's wire size. The enforced
 *  measure is GetCommittedSerializedSize(), which serialises with
 *  SERIALIZE_TRANSACTION_NO_DRIVECHAIN and therefore EXCLUDES every
 *  transaction's criticalData. That was deliberate: criticalData is malleable
 *  by a third party, so counting it let someone push an otherwise-valid block
 *  over the limit after the fact.
 *
 *  Witness bytes DO count at par, which removes the witness discount for blocks
 *  bound by this limit. Because block weight is always >= total serialized size,
 *  every block satisfying this rule also satisfies MAX_BLOCK_WEIGHT: the rule
 *  only tightens validity.
 *
 *  WHY A FIXED CHARGE. Because criticalData is excluded, a block's wire and
 *  disk size could otherwise reach ~96,400 bytes against this 50,000 cap:
 *    - SerializeTransaction sets `flags |= 2` for EVERY nVersion==3 transaction
 *      with NO IsNull() test, so the extended format (2) + vBytes length (1) +
 *      hashCritical (32) + vBytes (<=21) = up to 56 UNCOMMITTED wire bytes ride
 *      on each one.
 *    - The coinbase-commitment requirement does not bound their number: the
 *      match loop in ContextualCheckBlock breaks on the FIRST matching output
 *      and never consumes it, so ONE commitment satisfies EVERY transaction
 *      carrying the same (hashCritical, vBytes).
 *    - ~832 minimal v3 transactions fit the committed cap; 832 * 56 = ~46,600
 *      uncommitted bytes on top of it.
 *  A v3 transaction with NULL criticalData still costs 35 such bytes and needs
 *  no commitment at all, so ~1.58x is reachable with no setup whatsoever.
 *
 *  A CONSENSUS RULE OVER THE RECEIVED WIRE SIZE IS NOT MERELY UNSAFE, IT IS
 *  ILL-DEFINED. BIP152 short IDs are computed from GetWitnessHash()
 *  (blockencodings.cpp), which also excludes criticalData, so compact-block
 *  reconstruction fills in the LOCAL MEMPOOL's criticalData. Two honest nodes
 *  legitimately materialise different wire bytes for the same block under the
 *  same hash. There is no single quantity for such a rule to constrain.
 *
 *  THE FIX, now in the enforced measure: every nVersion==3 transaction is
 *  charged a FIXED 2 + 1 + MAX_CRITICAL_DATA_BYTES + 32 bytes
 *  (SMALL_BLOCK_V3_TX_CHARGE_BYTES, primitives/transaction.h) on top of its
 *  committed size, regardless of what its criticalData actually holds.
 *  nVersion IS committed, so the measure stays a function of committed data
 *  only - no malleability, no BIP152 problem - while being a provable UPPER
 *  BOUND on the wire size, so enforcing 50,000 really does mean 50,000 on the
 *  wire. The charge is written as that expression, not as a literal, so
 *  raising MAX_CRITICAL_DATA_BYTES moves the bound. The miner budgets and
 *  checks in the same measure (GetChargedSerializedSize). The size rule is
 *  not corruption-possible. It is a hard-fork rule: every node must upgrade. */
static const unsigned int MAX_SMALL_BLOCK_SERIALIZED_SIZE = 50000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

static const int WITNESS_SCALE_FACTOR = 4;



static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction


/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);
/** Use GetMedianTimePast() instead of nTime for end point timestamp. */
static constexpr unsigned int LOCKTIME_MEDIAN_TIME_PAST = (1 << 1);


/** Maximum number of bytes for a sidechain deposit destination encoding
 * OP_RETURN outptut. 68 bytes + PUSHDATA + OP_RETURN.
 */
static const int MAX_DEPOSIT_DESTINATION_BYTES = 70;

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
