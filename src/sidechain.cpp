// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <sidechain.h>

#include <base58.h>
#include <bech32.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h>
#include <chainparams.h> // for Params() in the height-gated parameter accessors
#include <util.h> // for LogPrintf

// Security fix (fund-theft window): height-gated sidechain parameter accessors.
// Return the production value at/after Consensus::Params::SidechainParamsHeight,
// the legacy testing value below it, so consensus reproduces historical SCDB
// state byte-for-byte on reindex while enforcing production rules after the
// coordinated flag day.
int GetSidechainWithdrawalVerificationPeriod(int nHeight)
{
    if (nHeight >= Params().GetConsensus().SidechainParamsHeight)
        return Params().GetConsensus().WithdrawalVerificationPeriod;
    return SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD;
}

int GetSidechainMinWorkScore(int nHeight)
{
    if (nHeight >= Params().GetConsensus().SidechainParamsHeight)
        return Params().GetConsensus().WithdrawalMinWorkScore;
    return SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE;
}

int GetSidechainActivationMaxFailures(int nHeight)
{
    if (nHeight >= Params().GetConsensus().SidechainParamsHeight)
        return Params().GetConsensus().SidechainActivationMaxFailures;
    return SIDECHAIN_ACTIVATION_MAX_FAILURES;
}

int GetSidechainActivationPeriod(int nHeight)
{
    if (nHeight >= Params().GetConsensus().SidechainParamsHeight)
        return Params().GetConsensus().SidechainActivationPeriod;
    return SIDECHAIN_ACTIVATION_PERIOD;
}

int GetSidechainReplacementPeriod(int nHeight)
{
    return GetSidechainMinWorkScore(nHeight);
}
#include <clientversion.h>
#include <core_io.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <script/script.h>
#include <streams.h>
#include <utilstrencodings.h>

#include <sstream>

bool Sidechain::operator==(const Sidechain& s) const
{
    return (title == s.title &&
            description == s.description &&
            hashID1 == s.hashID1 &&
            hashID2 == s.hashID2 &&
            nVersion == s.nVersion &&
            nSidechain == s.nSidechain);
}

std::string Sidechain::GetSidechainName() const
{
    return title;
}

std::string Sidechain::ToString() const
{
    std::stringstream ss;
    ss << "fActive=" << fActive << std::endl;
    ss << "nSidechain=" << (unsigned int)nSidechain << std::endl;
    ss << "nVersion=" << nVersion << std::endl;
    ss << "title=" << title << std::endl;
    ss << "description=" << description << std::endl;
    ss << "hashID1=" << hashID1.ToString() << std::endl;
    ss << "hashID2=" << hashID2.ToString() << std::endl;
    return ss.str();
}

bool SidechainDeposit::operator==(const SidechainDeposit& a) const
{
    return (a.nSidechain == nSidechain &&
            a.strDest == strDest &&
            a.tx == tx &&
            a.nBurnIndex == nBurnIndex &&
            a.nTx == nTx &&
            a.hashBlock == hashBlock);
}

std::string SidechainDeposit::ToString() const
{
    std::stringstream ss;
    ss << "nsidechain=" << (unsigned int)nSidechain << std::endl;
    ss << "strDest=" << strDest << std::endl;
    ss << "txid=" << tx.GetHash().ToString() << std::endl;
    ss << "nBurnIndex=" << nBurnIndex << std::endl;
    ss << "nTx=" << nTx << std::endl;
    ss << "hashblock=" << hashBlock.ToString() << std::endl;
    return ss.str();
}

std::string SidechainCTIP::ToString() const
{
    std::stringstream ss;
    ss << "outpoint=" << out.ToString() << std::endl;
    ss << "amount=" << amount << std::endl;
    return ss.str();
}

std::string SidechainTreasuryEntry::ToString() const
{
    std::stringstream ss;
    ss << "nsidechain=" << (unsigned int)nSidechain << std::endl;
    ss << "nseq=" << nSeq << std::endl;
    ss << "outpoint=" << out.ToString() << std::endl;
    ss << "amount=" << amount << std::endl;
    ss << "amountprev=" << amountPrev << std::endl;
    return ss.str();
}

bool SidechainWithdrawalState::operator==(const SidechainWithdrawalState& a) const
{
    return (a.nSidechain == nSidechain &&
            a.hash == hash);
}

std::string SidechainWithdrawalState::ToString() const
{
    std::stringstream ss;
    ss << "serhash=" << GetSerHash().ToString() << std::endl;
    ss << "nsidechain=" << (unsigned int)nSidechain << std::endl;
    ss << "nBlocksLeft=" << (unsigned int)nBlocksLeft << std::endl;
    ss << "nWorkScore=" << (unsigned int)nWorkScore << std::endl;
    ss << "hash=" << hash.ToString() << std::endl;
    return ss.str();
}

bool Sidechain::DeserializeFromProposalScript(const CScript& script)
{
    if (!script.IsSidechainProposalCommit())
        return false;

    CScript::const_iterator pc = script.begin() + 5;
    std::vector<unsigned char> vch;

    opcodetype opcode;
    if (!script.GetOp(pc, opcode, vch))
        return false;
    if (vch.empty())
        return false;

    // Deserialize proposal

    const char *vch0 = (const char *) &vch.begin()[0];
    CDataStream ds(vch0, vch0+vch.size(), SER_DISK, CLIENT_VERSION);

    Sidechain sidechain;
    // Security fix (chain halt): the stream is built over
    // attacker-controlled coinbase bytes. A truncated or over-long field makes
    // DeserializeProposal throw std::ios_base::failure (or std::bad_alloc).
    // Catch it here so the exception can NEVER escape ApplyUpdate ->
    // scdb.Update -> ConnectBlock (none of which have a try/catch): an escaping
    // throw leaves the poison block un-marked-invalid, keeps it a most-work
    // candidate, and every ActivateBestChain re-throws = permanent network
    // halt. A malformed proposal is instead treated as "not a proposal".
    try {
        sidechain.DeserializeProposal(ds);
    } catch (const std::exception& e) {
        LogPrintf("%s: Error: malformed sidechain proposal: %s\n", __func__, e.what());
        return false;
    }

    fActive = false;
    nSidechain = sidechain.nSidechain;
    nVersion = sidechain.nVersion;
    title = sidechain.title;
    description = sidechain.description;
    hashID1 = sidechain.hashID1;
    hashID2 = sidechain.hashID2;

    return true;
}

uint256 SidechainActivationStatus::GetSerHash() const
{
    return SerializeHash(*this);
}

uint256 SidechainDeposit::GetSerHash() const
{
    return SerializeHash(*this);
}

uint256 Sidechain::GetSerHash() const
{
    return SerializeHash(*this);
}

uint256 SidechainWithdrawalState::GetSerHash() const
{
    return SerializeHash(*this);
}

uint256 SidechainWithdrawalStateLegacy::GetSerHash() const
{
    return SerializeHash(*this);
}

uint256 SidechainCTIP::GetSerHash() const
{
    return SerializeHash(*this);
}

uint256 SidechainBlockData::GetSerHash() const
{
    return SerializeHash(*this);
}

CScript Sidechain::GetProposalScript() const
{
    CDataStream ds(SER_DISK, CLIENT_VERSION);
    ((Sidechain *) this)->SerializeProposal(ds);
    std::vector<unsigned char> vch(ds.begin(), ds.end());

    CScript script;
    script.resize(5);
    script[0] = OP_RETURN;
    script[1] = 0xD5;
    script[2] = 0xE0;
    script[3] = 0xC4;
    script[4] = 0xAF;
    script << vch;

    return script;
}

uint256 SidechainObj::GetSerHash(void) const
{
    uint256 ret;
    if (sidechainop == DB_SIDECHAIN_BLOCK_OP)
        ret = SerializeHash(*(SidechainBlockData *) this);

    return ret;
}

std::string SidechainObj::ToString(void) const
{
    std::stringstream str;
    str << "sidechainop=" << sidechainop << std::endl;
    return str.str();
}

std::string SidechainBlockData::ToString() const
{
    std::stringstream str;
    str << "sidechainop=" << sidechainop << std::endl;
    return str.str();
}

bool ParseDepositAddress(const std::string& strAddressIn, std::string& strAddressOut, unsigned int& nSidechainOut)
{
    if (strAddressIn.empty())
        return false;

    // First character should be 's'
    if (strAddressIn.front() != 's')
        return false;

    unsigned int delim1 = strAddressIn.find_first_of("_") + 1;
    unsigned int delim2 = strAddressIn.find_last_of("_");

    if (delim1 == std::string::npos || delim2 == std::string::npos)
        return false;
    if (delim1 >= strAddressIn.size() || delim2 + 1 >= strAddressIn.size())
        return false;

    std::string strSidechain = strAddressIn.substr(1, delim1);
    if (strSidechain.empty())
        return false;

    // Get sidechain number
    try {
        nSidechainOut = std::stoul(strSidechain);
    } catch (...) {
        return false;
    }

    // Check sidechain number is within range
    if (nSidechainOut > 255)
        return false;

    // Get substring without prefix or suffix
    strAddressOut = "";
    strAddressOut = strAddressIn.substr(delim1, delim2 - delim1);
    if (strAddressOut.empty())
        return false;

    // Get substring without checksum (for generating our checksum)
    std::string strNoCheck = strAddressIn.substr(0, delim2 + 1);
    if (strNoCheck.empty())
        return false;

    // Generate our own checksum of the address - checksum
    std::vector<unsigned char> vch;
    vch.resize(CSHA256::OUTPUT_SIZE);
    CSHA256().Write((unsigned char*)&strNoCheck[0], strNoCheck.size()).Finalize(&vch[0]);
    std::string strHash = HexStr(vch.begin(), vch.end());

    if (strHash.size() != 64)
        return false;

    // Get checksum from address string
    std::string strCheck = strAddressIn.substr(delim2 + 1, strAddressIn.size());
    if (strCheck.size() != 6)
        return false;

    // Compare address checksum with our checksum
    if (strCheck != strHash.substr(0, 6))
        return false;

    return true;
}

// DecodeBase58Check is declared inline in base58.h but defined in base58.cpp,
// so it cannot be linked from here; the same check, written out.
static bool DecodeBase58CheckE1(const std::string& str, std::vector<unsigned char>& vchRet)
{
    if (!DecodeBase58(str, vchRet) || vchRet.size() < 4) {
        vchRet.clear();
        return false;
    }
    const uint256 hash = Hash(vchRet.begin(), vchRet.end() - 4);
    if (memcmp(hash.begin(), &vchRet[vchRet.size() - 4], 4) != 0) {
        vchRet.clear();
        return false;
    }
    vchRet.resize(vchRet.size() - 4);
    return true;
}

bool IsPlausibleSidechainDestination(const std::string& strDest)
{
    if (strDest.empty())
        return false;

    // Ethereum-style account: 0x + 20 bytes in hex
    if (strDest.size() == 42 && strDest[0] == '0' && (strDest[1] == 'x' || strDest[1] == 'X')) {
        for (size_t i = 2; i < strDest.size(); i++)
            if (HexDigit(strDest[i]) < 0)
                return false;
        return true;
    }

    // Base58Check, one or two version bytes + a 20-byte hash. Not 33/34
    // bytes: that is a WIF private key, which would be published on chain.
    std::vector<unsigned char> vch;
    if (DecodeBase58CheckE1(strDest, vch))
        return vch.size() == 21 || vch.size() == 22;

    // bech32, any human-readable part
    const std::pair<std::string, std::vector<uint8_t>> bech = bech32::Decode(strDest);
    if (!bech.first.empty() && !bech.second.empty())
        return true;

    return false;
}

std::string DepositPolicyError(CAmount nAmount, const std::string& strDest, bool fAllowUnknownFormat)
{
    if (nAmount <= SIDECHAIN_DEPOSIT_FEE) {
        return strprintf("Deposit amount %s is not greater than the sidechain deposit fee %s: "
                         "the depositor would receive nothing on the sidechain",
                         FormatMoney(nAmount), FormatMoney(SIDECHAIN_DEPOSIT_FEE));
    }
    if (strDest == SIDECHAIN_WITHDRAWAL_RETURN_DEST)
        return "Invalid sidechain address. Cannot be SIDECHAIN_WITHDRAWAL_RETURN_DEST";
    if (!fAllowUnknownFormat && !IsPlausibleSidechainDestination(strDest)) {
        return "The sidechain address inside the deposit address is not a valid address "
               "(not Base58Check, bech32 or 0x-hex): the sidechain could not pay it";
    }
    return "";
}
