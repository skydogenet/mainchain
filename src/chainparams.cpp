// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <arith_uint256.h>

#include <assert.h>

#include <chainparamsseeds.h>

static void MineGenesis(CBlockHeader& genesisBlock, const uint256& powLimit, bool noProduction)
{
    if(noProduction)
        genesisBlock.nTime = std::time(0);
    genesisBlock.nNonce = 1;

    printf("NOTE: Genesis nTime = %u \n", genesisBlock.nTime);
    printf("WARN: Genesis nNonce (BLANK!) = %u \n", genesisBlock.nNonce);

    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(genesisBlock.nBits, &fNegative, &fOverflow);
    arith_uint256 besthash;
    memset(&besthash,0xFF,32);
    arith_uint256 hashTarget = UintToArith256(powLimit);
    printf("Target: %s\n", hashTarget.GetHex().c_str());
    arith_uint256 newhash = UintToArith256(genesisBlock.GetHash());
    while (newhash > bnTarget) {
        genesisBlock.nNonce++;
        if (genesisBlock.nNonce == 0) {
            printf("NONCE WRAPPED, incrementing time\n");
            ++genesisBlock.nTime;
        }
        // If nothing found after trying for a while, print status
        if ((genesisBlock.nNonce & 0xfff) == 0)
            printf("nonce %08X: hash = %s (target = %s)\n",
                   genesisBlock.nNonce, newhash.ToString().c_str(),
                   hashTarget.ToString().c_str());

        if(newhash < besthash) {
            besthash = newhash;
            printf("New best: %s\n", newhash.GetHex().c_str());
        }
        newhash = UintToArith256(genesisBlock.GetHash());
    }

    printf("Genesis nTime = %u \n", genesisBlock.nTime);
    printf("Genesis nNonce = %u \n", genesisBlock.nNonce);
    printf("Genesis nBits: %08x\n", genesisBlock.nBits);
    printf("Genesis Hash = %s\n", newhash.ToString().c_str());
    printf("Genesis Hash Merkle Root = %s\n", genesisBlock.hashMerkleRoot.ToString().c_str());
}

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 9;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "The Doge Times 06/Nov/2021 Retribution is coming";
    const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {



        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 2100000;
        consensus.BIP16Height = 0; // P2SH
        consensus.BIP34Height = 1; // Block height in coinbase scriptSig
        consensus.BIP34Hash = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP65Height = 0; // CLTV
        consensus.BIP66Height = 0; // Strict DER signatures
        consensus.nPowTargetTimespan = 60 * 60; // one hour
        consensus.nPowTargetSpacing = 60;
        consensus.powLimit = uint256S("0000005fffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000001d5fffff");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x5a86f07cf871fb4d8125aa6f8701e3ba3e876bddfcb6d11754cfb459eedf2e8c");
        consensus.DrivechainHeight = 1;

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0xc3;
        pchMessageStart[1] = 0xd8;
        pchMessageStart[2] = 0xef;
        pchMessageStart[3] = 0x81;
        nDefaultPort = 12345;//9324;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1670198450, 16757179, 0x1d5fffff, 1, 50000 * COIN);
        //MineGenesis(genesis,consensus.powLimit,false);
        consensus.hashGenesisBlock = genesis.GetHash();

        // PoW: 0000001f96ca6bf561489eee7630a3e8e002e4aebf46ef9f235f0469676a239f
        assert(consensus.hashGenesisBlock == uint256S("0x000000204da4f2092d957aa155339b91892c9e35de481c0a8efe099986936695"));
        assert(genesis.hashMerkleRoot == uint256S("0x160ace8d7230cd2879c999e1262333cca48d2fb87b67c06a6556d474f224fa80"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SIDECHAIN_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,125);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SIDECHAIN_SCRIPT_ADDRESS] = std::vector<unsigned char>(1,63);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                { 0, uint256S("0x0000000b2b10496bb3520722e9e197377d22671e39f1def14ed3455b473e9afa")},
            }
        };

        chainTxData = ChainTxData{
            /* nTime    */ 1645542140,
            /* nTxCount */ 712531200,
            /* dTxRate  */ 2.9
        };
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 2100000;
        consensus.BIP16Height = 0; // P2SH
        consensus.BIP34Height = 1; // Block height in coinbase scriptSig
        consensus.BIP34Hash = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP65Height = 0; // CLTV
        consensus.BIP66Height = 0; // Strict DER signatures
        consensus.powLimit = uint256S("005fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 1;
        consensus.DrivechainHeight = 1;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1; // 75% for testchains
        consensus.nMinerConfirmationWindow = 1; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000001d5f");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0738a06a8f21f36a14e071ce389d612d6ff487ed481e6c42a9e863f92c657868");

        pchMessageStart[0] = 0xd5;
        pchMessageStart[1] = 0xa3;
        pchMessageStart[2] = 0xe8;
        pchMessageStart[3] = 0xf6;

        nDefaultPort = 18441;
        nPruneAfterHeight = 1000;
        genesis = CreateGenesisBlock(1670198460, 59539747, 0x1d5fffff, 1, 50 * COIN);

        //MineGenesis(genesis,consensus.powLimit,false);
        consensus.hashGenesisBlock = genesis.GetHash();


        // PoW: 000000007f35a199e3bd12f099078aa9ec69ce56b4e7d425303370633ba08c87
        assert(consensus.hashGenesisBlock == uint256S("0x00000005e65ea5a412b10fce8e3e4b740c71ce00552efa492856d923a2e357c0"));
        assert(genesis.hashMerkleRoot == uint256S("0xb04ef21971d8356eb6c8a3ed14eb84a8fafca3ecc8f103cb88e90778ef9b5e86"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //vSeeds.emplace_back("testnet-seed.bitcoin.jonasschnelli.ch");
        //vSeeds.emplace_back("seed.tbtc.petertodd.org");
        //vSeeds.emplace_back("seed.testnet.bitcoin.sprovoost.nl");
        //vSeeds.emplace_back("testnet-seed.bluematt.me"); // Just a static list of stable node(s), only supports x9

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SIDECHAIN_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,125);
        base58Prefixes[SIDECHAIN_SCRIPT_ADDRESS] = std::vector<unsigned char>(1,63);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                { 0, uint256S("0x00000005e65ea5a412b10fce8e3e4b740c71ce00552efa492856d923a2e357c0")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 2100000;
        consensus.BIP16Height = 0; // P2SH
        consensus.BIP34Height = 1; // Block height in coinbase scriptSig
        consensus.BIP34Hash = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");
        consensus.BIP65Height = 0; // CLTV
        consensus.BIP66Height = 0; // Strict DER signatures
        consensus.DrivechainHeight = 1;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 1; // 75% for testchains
        consensus.nMinerConfirmationWindow = 1; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;


        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x000000000000000000000000000000000000000000000000000000001d5fffff");

        // By default assume that the signatures in ancestors of this block are valid.
        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0738a06a8f21f36a14e071ce389d612d6ff487ed481e6c42a9e863f92c657868");

        pchMessageStart[0] = 0xa0;
        pchMessageStart[1] = 0x9d;
        pchMessageStart[2] = 0xed;
        pchMessageStart[3] = 0x83;

        nDefaultPort = 18442;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1670198460, 59539747, 0x1d5fffff, 1, 50 * COIN);

        //MineGenesis(genesis,consensus.powLimit,false);
        consensus.hashGenesisBlock = genesis.GetHash();


        // PoW: 000000007f35a199e3bd12f099078aa9ec69ce56b4e7d425303370633ba08c87
        assert(consensus.hashGenesisBlock == uint256S("0x00000005e65ea5a412b10fce8e3e4b740c71ce00552efa492856d923a2e357c0"));
        assert(genesis.hashMerkleRoot == uint256S("0xb04ef21971d8356eb6c8a3ed14eb84a8fafca3ecc8f103cb88e90778ef9b5e86"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks =true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                { 0, uint256S("0x00000005e65ea5a412b10fce8e3e4b740c71ce00552efa492856d923a2e357c0")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SIDECHAIN_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,125);
        base58Prefixes[SIDECHAIN_SCRIPT_ADDRESS] = std::vector<unsigned char>(1,63);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
