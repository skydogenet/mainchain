// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_PRIMITIVES_TRANSACTION_H
#define BITCOIN_PRIMITIVES_TRANSACTION_H

#include <stdint.h>
#include <amount.h>
#include <script/script.h>
#include <serialize.h>
#include <uint256.h>

static const int SERIALIZE_TRANSACTION_NO_WITNESS = 0x40000000;
static const int SERIALIZE_TRANSACTION_NO_DRIVECHAIN = 0x20000000;

/** Maximum number of extra bytes on a critical (v3/BMM) transaction. Defined
 *  here rather than in validation.h so CCriticalData deserialization can bound
 *  vBytes (a transaction-layer property). */
static const int MAX_CRITICAL_DATA_BYTES = 21;

/** Fixed bytes the small-block cap charges every nVersion==3 transaction on
 *  top of its committed size, whatever its criticalData actually holds: the
 *  extended-format marker and flags (2), the vBytes length (1), vBytes at its
 *  parse bound and hashCritical (32). nVersion IS committed, so the charged
 *  measure stays a function of committed data only, and it is a provable
 *  upper bound on the wire bytes the committed measure leaves out. Kept as
 *  the expression so that raising MAX_CRITICAL_DATA_BYTES moves the bound.
 *  Rationale in consensus/consensus.h; enforced by GetCommittedSerializedSize. */
static const unsigned int SMALL_BLOCK_V3_TX_CHARGE_BYTES = 2 + 1 + MAX_CRITICAL_DATA_BYTES + 32;

static const unsigned char TX_REPLAY_BYTES = 0x3f;
static const int32_t TX_REPLAY_VERSION = 12566463;

/** An outpoint - a combination of a transaction hash and an index n into its vout */
class COutPoint
{
public:
    uint256 hash;
    uint32_t n;

    COutPoint(): n((uint32_t) -1) { }
    COutPoint(const uint256& hashIn, uint32_t nIn): hash(hashIn), n(nIn) { }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(hash);
        READWRITE(n);
    }

    void SetNull() { hash.SetNull(); n = (uint32_t) -1; }
    bool IsNull() const { return (hash.IsNull() && n == (uint32_t) -1); }

    friend bool operator<(const COutPoint& a, const COutPoint& b)
    {
        int cmp = a.hash.Compare(b.hash);
        return cmp < 0 || (cmp == 0 && a.n < b.n);
    }

    friend bool operator==(const COutPoint& a, const COutPoint& b)
    {
        return (a.hash == b.hash && a.n == b.n);
    }

    friend bool operator!=(const COutPoint& a, const COutPoint& b)
    {
        return !(a == b);
    }

    std::string ToString() const;

    uint256 GetHash() const;
};

/** An input of a transaction.  It contains the location of the previous
 * transaction's output that it claims and a signature that matches the
 * output's public key.
 */
class CTxIn
{
public:
    COutPoint prevout;
    CScript scriptSig;
    uint32_t nSequence;
    CScriptWitness scriptWitness; //! Only serialized through CTransaction

    /* Setting nSequence to this value for every input in a transaction
     * disables nLockTime. */
    static const uint32_t SEQUENCE_FINAL = 0xffffffff;

    /* Below flags apply in the context of BIP 68*/
    /* If this flag set, CTxIn::nSequence is NOT interpreted as a
     * relative lock-time. */
    static const uint32_t SEQUENCE_LOCKTIME_DISABLE_FLAG = (1 << 31);

    /* If CTxIn::nSequence encodes a relative lock-time and this flag
     * is set, the relative lock-time has units of 512 seconds,
     * otherwise it specifies blocks with a granularity of 1. */
    static const uint32_t SEQUENCE_LOCKTIME_TYPE_FLAG = (1 << 22);

    /* If CTxIn::nSequence encodes a relative lock-time, this mask is
     * applied to extract that lock-time from the sequence field. */
    static const uint32_t SEQUENCE_LOCKTIME_MASK = 0x0000ffff;

    /* In order to use the same number of bits to encode roughly the
     * same wall-clock duration, and because blocks are naturally
     * limited to occur every 600s on average, the minimum granularity
     * for time-based relative lock-time is fixed at 512 seconds.
     * Converting from CTxIn::nSequence to seconds is performed by
     * multiplying by 512 = 2^9, or equivalently shifting up by
     * 9 bits. */
    static const int SEQUENCE_LOCKTIME_GRANULARITY = 9;

    CTxIn()
    {
        nSequence = SEQUENCE_FINAL;
    }

    explicit CTxIn(COutPoint prevoutIn, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);
    CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn=CScript(), uint32_t nSequenceIn=SEQUENCE_FINAL);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(prevout);
        READWRITE(scriptSig);
        READWRITE(nSequence);
    }

    friend bool operator==(const CTxIn& a, const CTxIn& b)
    {
        return (a.prevout   == b.prevout &&
                a.scriptSig == b.scriptSig &&
                a.nSequence == b.nSequence);
    }

    friend bool operator!=(const CTxIn& a, const CTxIn& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

/** An output of a transaction.  It contains the public key that the next input
 * must be able to sign with to claim it.
 */
class CTxOut
{
public:
    CAmount nValue;
    CScript scriptPubKey;

    CTxOut()
    {
        SetNull();
    }

    CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn);

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(nValue);
        READWRITE(scriptPubKey);
    }

    void SetNull()
    {
        nValue = -1;
        scriptPubKey.clear();
    }

    bool IsNull() const
    {
        return (nValue == -1);
    }

    friend bool operator==(const CTxOut& a, const CTxOut& b)
    {
        return (a.nValue       == b.nValue &&
                a.scriptPubKey == b.scriptPubKey);
    }

    friend bool operator!=(const CTxOut& a, const CTxOut& b)
    {
        return !(a == b);
    }

    std::string ToString() const;
};

struct CMutableTransaction;

class CCriticalData
{
public:
    std::vector<unsigned char> vBytes;
    uint256 hashCritical;

    CCriticalData()
    {
        SetNull();
    }

    // Hand-written rather than ADD_SERIALIZE_METHODS, because the read and the
    // write are not symmetric here and the SerializationOp form compiles BOTH
    // branches for every stream type - including read-only and size-computing
    // streams that have only one of read()/write().
    //
    // Bound the BMM critical-data bytes at deserialization. Consensus already
    // rejects vBytes > MAX_CRITICAL_DATA_BYTES, but criticalData is excluded
    // from the txid and witness hash while still counted in the serialized
    // block size/weight, so an unbounded vBytes lets a peer pad a copy of an
    // honest block past the cap without changing its hash and get that hash
    // marked permanently invalid. Refuse to parse an over-long value.
    //
    // The length is checked BEFORE the vector is sized, which is the whole
    // point of spelling this out. The generic vector reader allocates the
    // DECLARED length in ~5 MB chunks and only then runs out of data, so
    // checking afterwards still let a peer spend the node's memory and CPU on
    // a length it never had to send the bytes for - a few bytes on the wire to
    // make the node allocate megabytes, from any peer, repeatedly. Bounded
    // first, the largest allocation this field can ask for is 21 bytes.
    //
    // Byte-identical on the wire to the generic vector<unsigned char> path it
    // replaces - same CompactSize, same payload, same order - so nothing
    // serialises differently and the set of transactions that parse is
    // unchanged: anything over the bound was already refused here, only later
    // and more expensively. The exception type and message are kept too, so
    // ProcessMessages classifies the failure exactly as it did before.
    template <typename Stream>
    void Serialize(Stream& s) const
    {
        WriteCompactSize(s, vBytes.size());
        if (!vBytes.empty())
            s.write((const char*)vBytes.data(), vBytes.size());
        ::Serialize(s, hashCritical);
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        const uint64_t nSize = ReadCompactSize(s);
        if (nSize > (uint64_t)MAX_CRITICAL_DATA_BYTES)
            // "size too large" is LOAD-BEARING, not description - see the same
            // point in serialize.h. ProcessMessages classifies
            // ios_base::failure by SUBSTRING; a message matching none of its
            // three buckets falls to PrintExceptionContinue, which writes to
            // debug.log AND stderr unconditionally and unthrottled, so a few
            // bytes on the wire buy ~360 bytes of output per message from any
            // peer. The serialize.h bound had the same problem and was fixed
            // first; this sibling is the older of the two.
            throw std::ios_base::failure("ReadCompactSize(): size too large (CCriticalData::vBytes exceeds MAX_CRITICAL_DATA_BYTES)");
        vBytes.resize((size_t)nSize);
        if (nSize)
            s.read((char*)vBytes.data(), (size_t)nSize);
        ::Unserialize(s, hashCritical);
    }

    void SetNull()
    {
        vBytes.clear();
        hashCritical.SetNull();
    }

    bool IsNull() const
    {
        return (vBytes.empty() && hashCritical.IsNull());
    }

    // Check if critical data is a BMM request
    bool IsBMMRequest() const;
    bool IsBMMRequest(uint8_t& nSidechain, std::string& strPrevBlock) const;

    friend bool operator==(const CCriticalData& a, const CCriticalData& b)
    {
        return (a.vBytes == b.vBytes &&
                a.hashCritical == b.hashCritical);
    }
};

/**
 * Basic transaction serialization format:
 * - int32_t nVersion
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - uint32_t nLockTime
 *
 * Extended transaction serialization format:
 * - int32_t nVersion
 * - unsigned char dummy = 0x00
 * - unsigned char flags (!= 0)
 * - std::vector<CTxIn> vin
 * - std::vector<CTxOut> vout
 * - if (flags & 1):
 *   - CScriptWitness scriptWitness;
 * - if (flags & 2):
 *   - CCriticalData criticalData;
 * - uint32_t nLockTime
 */
template<typename Stream, typename TxType>
inline void UnserializeTransaction(TxType& tx, Stream& s) {
    const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);

    s >> tx.nVersion;
    if (tx.nVersion == TX_REPLAY_VERSION) {
        unsigned char noreplay;
        s >> noreplay;
    }

    const bool fAllowCriticalData = fAllowWitness &&
        !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_DRIVECHAIN) &&
        tx.nVersion == 3;

    unsigned char flags = 0;
    tx.vin.clear();
    tx.vout.clear();
    /* Try to read the vin. In case the dummy is there, this will be read as an empty vector. */
    s >> tx.vin;
    if (tx.vin.size() == 0 && fAllowWitness) {
        /* We read a dummy or an empty vin. */
        s >> flags;
        if (flags != 0) {
            s >> tx.vin;
            s >> tx.vout;
        }
    } else {
        /* We read a non-empty vin. Assume a normal vout follows. */
        s >> tx.vout;
    }
    if ((flags & 1) && fAllowWitness) {
        /* The witness flag is present, and we support witnesses. */
        flags ^= 1;
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s >> tx.vin[i].scriptWitness.stack;
        }
    }
    if ((flags & 2) && fAllowCriticalData) {
        /* The critical data flag is present, and we support critical data. */
        flags ^= 2;
        s >> tx.criticalData;
    }
    if (flags) {
        /* Unknown flag in the serialization */
        throw std::ios_base::failure("Unknown transaction optional data");
    }
    s >> tx.nLockTime;
}

template<typename Stream, typename TxType>
inline void SerializeTransaction(const TxType& tx, Stream& s) {
    const bool fAllowWitness = !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_WITNESS);
    const bool fAllowCriticalData = fAllowWitness &&
        !(s.GetVersion() & SERIALIZE_TRANSACTION_NO_DRIVECHAIN) &&
        tx.nVersion == 3;

    s << tx.nVersion;
    if (tx.nVersion == TX_REPLAY_VERSION) {
        s << TX_REPLAY_BYTES;
    }
    unsigned char flags = 0;
    /* Check whether extra data needs to be serialized. */
    if (fAllowWitness) {
        /* Check whether witnesses need to be serialized. */
        if (tx.HasWitness()) {
            flags |= 1;
        }
    }
    if (fAllowCriticalData) {
        flags |= 2;
    }
    if (flags) {
        /* Use extended format in case extra data is to be serialized. */
        std::vector<CTxIn> vinDummy;
        s << vinDummy;
        s << flags;
    }
    s << tx.vin;
    s << tx.vout;
    if (flags & 1) {
        for (size_t i = 0; i < tx.vin.size(); i++) {
            s << tx.vin[i].scriptWitness.stack;
        }
    }
    if (flags & 2) {
        s << tx.criticalData;
    }
    s << tx.nLockTime;
}


/** The basic transaction that is broadcasted on the network and contained in
 * blocks.  A transaction can contain multiple inputs and outputs.
 */
class CTransaction
{
public:
    // Default transaction version.
    static const int32_t CURRENT_VERSION=9;

    // Changing the default transaction version requires a two step process: first
    // adapting relay policy by bumping MAX_STANDARD_VERSION, and then later date
    // bumping the default CURRENT_VERSION at which point both CURRENT_VERSION and
    // MAX_STANDARD_VERSION will be equal.
    static const int32_t MAX_STANDARD_VERSION=10;

    // The local variables are made const to prevent unintended modification
    // without updating the cached hash value. However, CTransaction is not
    // actually immutable; deserialization and assignment are implemented,
    // and bypass the constness. This is safe, as they update the entire
    // structure, including the hash.
    const std::vector<CTxIn> vin;
    const std::vector<CTxOut> vout;
    const CCriticalData criticalData;
    const int32_t nVersion;
    const uint32_t nLockTime;

private:
    /** Memory only. */
    const uint256 hash;

    uint256 ComputeHash() const;

public:
    /** Construct a CTransaction that qualifies as IsNull() */
    CTransaction();

    /** Convert a CMutableTransaction into a CTransaction. */
    CTransaction(const CMutableTransaction &tx);
    CTransaction(CMutableTransaction &&tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s);
    }

    /** This deserializing constructor is provided instead of an Unserialize method.
     *  Unserialize is not possible, since it would require overwriting const fields. */
    template <typename Stream>
    CTransaction(deserialize_type, Stream& s) : CTransaction(CMutableTransaction(deserialize, s)) {}

    bool IsNull() const {
        return vin.empty() && vout.empty();
    }

    const uint256& GetHash() const {
        return hash;
    }

    // Compute a hash that includes both transaction and witness data
    uint256 GetWitnessHash() const;

    // Compute blind hash of withdrawal tx (remove inputs and sidechain change)
    bool GetBlindHash(uint256& hashRet) const;

    /** Out-parameter, like GetBlindHash above and for the same reason: the
     *  empty-transaction case has to be reportable. Returning the amount
     *  directly left no error channel - a failure converted to CAmount 0,
     *  which is a valid money value, so a caller could not tell "no outputs"
     *  from "zero". */
    bool GetBlindValueOut(CAmount& amountRet) const;

    // Return sum of txouts.
    CAmount GetValueOut() const;
    // GetValueIn() is a method on CCoinsViewCache, because
    // inputs must be known to compute value in.

    /**
     * Get the total transaction size in bytes, including witness data.
     * "Total Size" defined in BIP141 and BIP144.
     * @return Total transaction size in bytes
     */
    unsigned int GetTotalSize() const;

    bool IsCoinBase() const
    {
        return (vin.size() == 1 && vin[0].prevout.IsNull());
    }

    friend bool operator==(const CTransaction& a, const CTransaction& b)
    {
        return a.hash == b.hash;
    }

    friend bool operator!=(const CTransaction& a, const CTransaction& b)
    {
        return a.hash != b.hash;
    }

    std::string ToString() const;

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (!vin[i].scriptWitness.IsNull()) {
                return true;
            }
        }
        return false;
    }
};

/** A mutable version of CTransaction. */
struct CMutableTransaction
{
    std::vector<CTxIn> vin;
    std::vector<CTxOut> vout;
    CCriticalData criticalData;
    int32_t nVersion;
    uint32_t nLockTime;

    CMutableTransaction();
    CMutableTransaction(const CTransaction& tx);

    template <typename Stream>
    inline void Serialize(Stream& s) const {
        SerializeTransaction(*this, s);
    }


    template <typename Stream>
    inline void Unserialize(Stream& s) {
        UnserializeTransaction(*this, s);
    }

    template <typename Stream>
    CMutableTransaction(deserialize_type, Stream& s) {
        Unserialize(s);
    }

    /** Compute the hash of this CMutableTransaction. This is computed on the
     * fly, as opposed to GetHash() in CTransaction, which uses a cached result.
     */
    uint256 GetHash() const;

    friend bool operator==(const CMutableTransaction& a, const CMutableTransaction& b)
    {
        return a.GetHash() == b.GetHash();
    }

    bool HasWitness() const
    {
        for (size_t i = 0; i < vin.size(); i++) {
            if (!vin[i].scriptWitness.IsNull()) {
                return true;
            }
        }
        return false;
    }
};

typedef std::shared_ptr<const CTransaction> CTransactionRef;
static inline CTransactionRef MakeTransactionRef() { return std::make_shared<const CTransaction>(); }
template <typename Tx> static inline CTransactionRef MakeTransactionRef(Tx&& txIn) { return std::make_shared<const CTransaction>(std::forward<Tx>(txIn)); }

#endif // BITCOIN_PRIMITIVES_TRANSACTION_H
