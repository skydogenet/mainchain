// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDB_H
#define BITCOIN_TXDB_H

#include <coins.h>
#include <chain.h>
#include <dbwrapper.h>
#include <sidechain.h>

#include <map>
#include <string>
#include <utility>
#include <vector>

class CBlockIndex;
class CCoinsViewDBCursor;
class uint256;

//! No need to periodic flush if at least this much space still available.
static constexpr int MAX_BLOCK_COINSDB_USAGE = 10;
//! -dbcache default (MiB)
static const int64_t nDefaultDbCache = 2048;
//! -dbbatchsize default (bytes)
static const int64_t nDefaultDbBatchSize = 16 << 20;
//! max. -dbcache (MiB)
static const int64_t nMaxDbCache = sizeof(void*) > 4 ? 16384 : 1024;
//! min. -dbcache (MiB)
static const int64_t nMinDbCache = 4;
//! Max memory allocated to block tree DB specific cache, if no -txindex (MiB)
static const int64_t nMaxBlockDBCache = 2;
//! Max memory allocated to block tree DB specific cache, if -txindex (MiB)
// Unlike for the UTXO database, for the txindex scenario the leveldb cache make
// a meaningful difference: https://github.com/bitcoin/bitcoin/pull/8273#issuecomment-229601991
static const int64_t nMaxBlockDBAndTxIndexCache = 1024;
//! Max memory allocated to coin DB specific cache (MiB)
static const int64_t nMaxCoinsDBCache = 8;

static const int64_t nOPReturnCache = 500;

struct CDiskTxPos : public CDiskBlockPos
{
    unsigned int nTxOffset; // after header

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(*static_cast<CDiskBlockPos*>(this));
        READWRITE(VARINT(nTxOffset));
    }

    CDiskTxPos(const CDiskBlockPos &blockIn, unsigned int nTxOffsetIn) : CDiskBlockPos(blockIn.nFile, blockIn.nPos), nTxOffset(nTxOffsetIn) {
    }

    CDiskTxPos() {
        SetNull();
    }

    void SetNull() {
        CDiskBlockPos::SetNull();
        nTxOffset = 0;
    }
};

/** CCoinsView backed by the coin database (chainstate/) */
class CCoinsViewDB final : public CCoinsView
{
protected:
    CDBWrapper db;
public:
    explicit CCoinsViewDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    bool GetCoin(const COutPoint &outpoint, Coin &coin) const override;
    bool HaveCoin(const COutPoint &outpoint) const override;
    uint256 GetBestBlock() const override;
    std::vector<uint256> GetHeadBlocks() const override;
    bool BatchWrite(CCoinsMap &mapCoins, const uint256 &hashBlock) override;
    CCoinsViewCursor *Cursor() const override;

    //! Attempt to update from an older database format. Returns whether an error occurred.
    bool Upgrade();
    size_t EstimateSize() const override;
};

/** Specialization of CCoinsViewCursor to iterate over a CCoinsViewDB */
class CCoinsViewDBCursor: public CCoinsViewCursor
{
public:
    ~CCoinsViewDBCursor() {}

    bool GetKey(COutPoint &key) const override;
    bool GetValue(Coin &coin) const override;
    unsigned int GetValueSize() const override;

    bool Valid() const override;
    void Next() override;

private:
    CCoinsViewDBCursor(CDBIterator* pcursorIn, const uint256 &hashBlockIn):
        CCoinsViewCursor(hashBlockIn), pcursor(pcursorIn) {}
    std::unique_ptr<CDBIterator> pcursor;
    std::pair<char, COutPoint> keyTmp;

    friend class CCoinsViewDB;
};

/** Access to the block database (blocks/index/) */
class CBlockTreeDB : public CDBWrapper
{
public:
    explicit CBlockTreeDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);

    CBlockTreeDB(const CBlockTreeDB&) = delete;
    CBlockTreeDB& operator=(const CBlockTreeDB&) = delete;

    bool WriteBatchSync(const std::vector<std::pair<int, const CBlockFileInfo*> >& fileInfo, int nLastFile, const std::vector<const CBlockIndex*>& blockinfo);
    bool ReadBlockFileInfo(int nFile, CBlockFileInfo &info);
    bool ReadLastBlockFile(int &nFile);
    bool WriteReindexing(bool fReindexing);
    bool ReadReindexing(bool &fReindexing);
    bool ReadTxIndex(const uint256 &txid, CDiskTxPos &pos);
    bool WriteTxIndex(const std::vector<std::pair<uint256, CDiskTxPos> > &vect);
    bool WriteFlag(const std::string &name, bool fValue);
    bool ReadFlag(const std::string &name, bool &fValue);
    bool LoadBlockIndexGuts(const Consensus::Params& consensusParams, std::function<CBlockIndex*(const uint256&)> insertBlockIndex);
};

/** Access to the sidechain database (blocks/sidechain/) */
class CSidechainTreeDB : public CDBWrapper
{
public:
    CSidechainTreeDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
    bool WriteSidechainIndex(const std::vector<std::pair<uint256, const SidechainObj *> > &list);
    bool WriteSidechainBlockData(const std::pair<uint256, const SidechainBlockData>& data);

    bool GetBlockData(const uint256& /* hashBlock */, SidechainBlockData& data) const;
    bool HaveBlockData(const uint256& hashBlock) const;
};

struct OPReturnData
{
    uint256 txid;
    CScript script;
    unsigned int nSize;
    CAmount fees;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(txid);
        READWRITE(script);
        READWRITE(nSize);
        READWRITE(fees);
    }
};

struct NewsType
{
    // A series of bytes to distinguish this news
    CScript header;
    // The GUI title of the news type
    std::string title;
    // Number of days news in this category is collected and ranked before
    // staring a new period. If the number is 7 then the last 7 days of this
    // news type should be ranked and displayed on the news table at a time.
    int nDays;

    ADD_SERIALIZE_METHODS

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(header);
        READWRITE(title);
        READWRITE(nDays);
    }

    uint256 GetHash() const {
        return SerializeHash(*this);
    }

    std::string GetShareURL() const;

    bool SetURL(const std::string& strURL);
};

/** Access to the OP_RETURN cache database (blocks/opreturn/) */
class OPReturnDB : public CDBWrapper
{
public:
    OPReturnDB(size_t nCacheSize, bool fMemory = false, bool fWipe = false);
    bool WriteBlockData(const std::pair<uint256, const std::vector<OPReturnData>>& data);

    bool GetBlockData(const uint256& /* hashBlock */, std::vector<OPReturnData>& vData) const;
    bool HaveBlockData(const uint256& hashBlock) const;

    void GetNewsTypes(std::vector<NewsType>& vType);
    void WriteNewsType(NewsType type);
    void EraseNewsType(uint256 hash);
};

#endif // BITCOIN_TXDB_H
