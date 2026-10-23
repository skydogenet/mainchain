// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <utilstrencodings.h>
#include <crypto/common.h>

#include <cstddef>
#include <cstring>

uint256 CBlockHeader::GetHash() const
{
    //return SerializeHash(*this);
    // Security fix (remote CPU-DoS): memoize the ~44x-SHA256d skydoge_hash.
    // The hashed input is the contiguous 80-byte POD region [nVersion..nNonce];
    // this layout assumption is NOT new - the skydoge_hash(BEGIN,END) call has
    // always relied on it - so make it explicit. The cache self-validates by
    // comparing the live 80 bytes against the snapshot, so any field mutation
    // transparently forces a recompute and the returned value is bit-identical.
    static_assert(offsetof(CBlockHeader, nNonce) + sizeof(uint32_t) -
                      offsetof(CBlockHeader, nVersion) == 80,
                  "CBlockHeader hashed region must be 80 contiguous bytes");
    if (fHashCached && memcmp(hashCacheInput, BEGIN(nVersion), 80) == 0)
        return hashCache;
    memcpy(hashCacheInput, BEGIN(nVersion), 80);
    hashCache = skydoge_hash(BEGIN(nVersion), END(nNonce));
    fHashCached = true;
    return hashCache;
}


std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
