// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <sidechain.h> // the former global *_PROD window constants, now seeded per network
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

void CChainParams::UpdateSmallBlockHeight(int nHeight)
{
    consensus.SmallBlockHeight = nHeight;
}

void CChainParams::UpdateTimewarpGuardHeight(int nHeight)
{
    consensus.TimewarpGuardHeight = nHeight;
}

void CChainParams::UpdateSidechainParamsHeight(int nHeight)
{
    consensus.SidechainParamsHeight = nHeight;
}

void CChainParams::UpdateWithdrawalWindow(int nVerificationPeriod, int nMinWorkScore, int nFailedRetention)
{
    consensus.WithdrawalVerificationPeriod = nVerificationPeriod;
    consensus.WithdrawalMinWorkScore = nMinWorkScore;
    consensus.WithdrawalFailedRetention = nFailedRetention;
}

void CChainParams::UpdateSCDBCommitmentHeight(int nHeight)
{
    consensus.SCDBCommitmentHeight = nHeight;
}

void CChainParams::UpdateCTIPAnchorHeight(int nHeight)
{
    consensus.CTIPAnchorHeight = nHeight;
}

void CChainParams::UpdateEscrowRulesHeight(int nHeight)
{
    consensus.EscrowRulesHeight = nHeight;
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
        // NOT nPowTargetTimespan / nPowTargetSpacing, whatever this comment used
        // to say - that quotient is 60 here. The versionbits period and the
        // difficulty retarget period are the same thing on Bitcoin and have
        // diverged on this chain: retarget is every 60 blocks (1 hour), while a
        // BIP9 window is 2016 blocks (1.4 days at 60s). No correctness bug
        // follows - versionbits only needs a consistent period, not retarget
        // alignment - but do not derive one of these from the other.
        consensus.nMinerConfirmationWindow = 2016;
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


        // The best chain should have at least this much work. Set to the real
        // chain work at height 1,830,000 - buried roughly a week below the tip -
        // so a chain with less work than that is refused outright. Together with
        // the checkpoint at the same height this bounds how far back a fork can
        // be offered to us, which matters more here than on a large chain: the
        // one-hour retarget lets difficulty fall quickly on a fork, so headers
        // below the checkpoint would otherwise be cheap to produce in bulk.
        // Neither is a validity rule for blocks at the tip, so no fork risk.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000005d086d4027e9b264");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x000000000040fddbb0be39cec3ee4790d0d299e92176c8a518439f7e54c99fbd");
        consensus.DrivechainHeight = 1;
        // FLAG DAY — three coupled consensus changes: the 50 KB small-block cap,
        // the timewarp guard, and the switch to production sidechain parameters.
        // THE 2026-10-31 HARD FORK: SmallBlockHeight, TimewarpGuardHeight,
        // SidechainParamsHeight, SCDBCommitmentHeight and EscrowRulesHeight all
        // activate at H = 1,976,112 (about 2026-10-31 01:55 UTC at
        // ~62 s per block). A node of an older release follows a different
        // chain from H. The five must stay equal.
        //
        // CTIPAnchorHeight follows 4,032 blocks later, at 1,980,144 (below).
        consensus.SmallBlockHeight = 1976112;
        consensus.TimewarpGuardHeight = 1976112;
        consensus.SidechainParamsHeight = 1976112;
        // Per-network withdrawal window: 129,600 blocks = 90 days at
        // 60 s, verification period 259,200 = 180 days. Slot replacement
        // uses the same 129,600.
        consensus.WithdrawalMinWorkScore = 129600;
        consensus.WithdrawalVerificationPeriod = 259200;
        // a bundle that fails at or after the fork height is
        // remembered for two windows (518,400 blocks, ~1 year at 60s) and then
        // dropped from the failed set, so the committed set is bounded. With
        // the pending cap (SIDECHAIN_WITHDRAWAL_MAX_PENDING) at most 32 bundles
        // can fail per slot per 129,600 blocks, so the set never exceeds
        // 32 x 4 = 128 post-fork entries per active slot.
        consensus.WithdrawalFailedRetention = 2 * 259200;
        // the block at SidechainParamsHeight sweeps the
        // in-flight bundles without blacklisting them.
        consensus.fWithdrawalBoundarySweep = true;
        consensus.SidechainActivationPeriod = SIDECHAIN_ACTIVATION_PERIOD_PROD;
        consensus.SidechainActivationMaxFailures = SIDECHAIN_ACTIVATION_MAX_FAILURES_PROD;
        // FLAG DAY - the SCDB coinbase hash commitment, riding
        // SmallBlockHeight's value at the fork height. Every
        // node must run it before that height.
        consensus.SCDBCommitmentHeight = 1976112;
        // FLAG DAY - the treasury-pointer anchor: deposit
        // continuity, the destination half
        // (a treasury spend may not claim the withdrawal-return "D"), the
        // withdrawal amount equations and the pointer-to-coin anchor itself.
        // It must NOT ride SCDBCommitmentHeight's activation: it activates
        // 4,032 blocks (about three days) after the commitment, so a
        // commitment divergence shows before the anchor binds and a follow-up
        // release can still move this height out.
        consensus.CTIPAnchorHeight = 1980144;
        // FLAG DAY - the BIP300 escrow rules (zero-value M6 fee output; no
        // replacement of a slot whose treasury holds coins), at the SAME height
        // as SmallBlockHeight, TimewarpGuardHeight, SidechainParamsHeight and
        // SCDBCommitmentHeight; they must stay equal.
        consensus.EscrowRulesHeight = 1976112;

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

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        //
        // None of these publish the "x<servicebits>." record that
        // ThreadDNSAddressSeed looks up first, so that lookup fails and the
        // entry is used as a one-shot instead: the node connects to the host on
        // the default port, asks it for addresses and disconnects. That still
        // bootstraps a fresh node, but it means each entry has to be a reachable
        // node rather than just a name serving A records.
        vSeeds.emplace_back("pool.skydoge.net");
        vSeeds.emplace_back("treenode.net");
        vSeeds.emplace_back("skydoge.org");

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
                { 534647, uint256S("0x000000000007fe51ecfdfa34837b2d4a8f2c53eb41289d531f8a5b25fb348259")},
                { 1830000, uint256S("0x000000000040fddbb0be39cec3ee4790d0d299e92176c8a518439f7e54c99fbd")},
            }
        };

        chainTxData = ChainTxData{
            /* nTime    */ 1784996470,
            /* nTxCount */ 2175173,
            /* dTxRate  */ 0.023119
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
        consensus.powLimit = uint256S("000005ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60; // one hour (NOT two weeks; that was Bitcoin's)
        consensus.nPowTargetSpacing = 10;
        consensus.DrivechainHeight = 1;
        // The fork gates are NOT coded on testnet: SmallBlockHeight,
        // TimewarpGuardHeight, SidechainParamsHeight and SCDBCommitmentHeight
        // stay at 1e9 here and can be moved for testing with the matching
        // -smallblockheight / -timewarpguardheight / -sidechainparamsheight /
        // -scdbcommitmentheight options. That is NOT how mainnet works:
        // mainnet codes all five gates at 1,976,112 above. EscrowRulesHeight
        // is the one gate coded on testnet (188,640, below).
        consensus.SmallBlockHeight = 1000000000;
        consensus.TimewarpGuardHeight = 1000000000;
        consensus.SidechainParamsHeight = 1000000000;
        // Per-network withdrawal window, much shorter than mainnet's so a full
        // sidechain cycle can be tested in hours.
        //
        // A full test cycle is propose -> activate -> deposit -> bundle -> accrue
        // work score -> pay out, so its wall clock is roughly the activation
        // period plus the withdrawal window. At 10s spacing:
        //
        //     activation   360 blocks =  1 h   (exactly one retarget period)
        //     window     1,440 blocks =  4 h   (four retarget periods)
        //     ratio                     4.0x
        //     full cycle              ~ 5 h    -> several test cycles per day
        //
        // THE 4x RATIO IS THE POINT, NOT THE HOURS. The withdrawal window must
        // exceed the ACTIVATION period or bundles pay out faster than sidechains
        // activate - an ordering mainnet can never have, which would make a
        // re-proposal racing a pending withdrawal, or a bundle expiring
        // mid-activation of a competitor, structurally unreproducible here.
        // Keeping 4x while shrinking both is what buys cycles without losing the
        // regime.
        //
        // Max failures scales with the period to hold BIP300's ~90% commitment
        // rule: 201/2016 is 9.97%, and 360 * 0.0997 = 36.
        consensus.WithdrawalMinWorkScore = 1440;
        consensus.WithdrawalVerificationPeriod = 2880;
        // NOT two windows as on mainnet (that would be 5,760): the testnet
        // chain already holds failed bundles, and a short retention would drop
        // them within hours and make this release disagree with nodes that
        // recorded them. 86,400 blocks is 10 days at 10s.
        consensus.WithdrawalFailedRetention = 86400;
        // Off on testnet only: the testnet chain already crossed 188,640
        // without the sweep; see consensus/params.h.
        consensus.fWithdrawalBoundarySweep = false;
        consensus.SidechainActivationPeriod = 360;
        consensus.SidechainActivationMaxFailures = 36;
        // The SCDB coinbase hash commitment, inert here as on mainnet.
        consensus.SCDBCommitmentHeight = 1000000000;
        // The treasury-pointer anchor, inert here as on mainnet.
        consensus.CTIPAnchorHeight = 1000000000;
        // The BIP300 escrow rules. NOT inert here, unlike the gates above:
        // they are coded at 188,640 on testnet, so a testnet node needs no
        // override line for them. No testnet block around that height breaks
        // either rule (no withdrawal payout, single-output deposits, no
        // replacement of a funded slot).
        // -escrowrulesheight moves it if that ever stops being true.
        consensus.EscrowRulesHeight = 188640;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        // 1 of 1 is 100%, not 75%, and the window is not the timespan/spacing
        // quotient either - that would be 360 here (3600s / 10s). Every block is
        // its own versionbits period on this network.
        consensus.nRuleChangeActivationThreshold = 1;
        consensus.nMinerConfirmationWindow = 1;
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
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000001d5ffff");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0738a06a8f21f36a14e071ce389d612d6ff487ed481e6c42a9e863f92c657868");

        pchMessageStart[0] = 0xd5;
        pchMessageStart[1] = 0xa3;
        pchMessageStart[2] = 0xe8;
        pchMessageStart[3] = 0xf6;

        nDefaultPort = 18441;
        nPruneAfterHeight = 1000;
        // nBits here is 0x1d5fffff, which is mainnet's powLimit compacted, not
        // this chain's - testnet's own limit compacts to 0x1e05ffff, so the
        // genesis is 256x harder than the floor it should sit on. Harmless in
        // practice: testnet retargets, so GetNextWorkRequired's walk-back stops
        // at an adjustment boundary and has not reached this block since the
        // first adjustment. It is left alone because changing it changes the
        // genesis hash, which forks a live chain.
        //
        // IF TESTNET IS EVER RESET, fix it then: set nBits to
        // powLimit.GetCompact() and re-grind the nonce, as CRegTestParams now
        // does. A reset is the only cost-free moment to correct this.
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

// Change testnet address to mainnet to make sidechains withdrawal works on testnet

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SIDECHAIN_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,125);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SIDECHAIN_SCRIPT_ADDRESS] = std::vector<unsigned char>(1,63);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

//        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
//        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
//        base58Prefixes[SIDECHAIN_PUBKEY_ADDRESS] = std::vector<unsigned char>(1,125);
//        base58Prefixes[SIDECHAIN_SCRIPT_ADDRESS] = std::vector<unsigned char>(1,63);
//        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
//        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
//        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

//        bech32_hrp = "tb";

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
            /* nTime    */ 1784680004,
            /* nTxCount */ 130099,
            /* dTxRate  */ 0.165951
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
        // Small-block soft fork (50 KB serialized block size limit).
        // Low height so functional tests can cover both sides of activation.
        consensus.SmallBlockHeight = 300;
        consensus.TimewarpGuardHeight = 300;
        consensus.SidechainParamsHeight = 300;
        // Per-network withdrawal window. Unchanged from the former global
        // *_PROD constants at this commit; the values are set separately.
        // left at the inherited value: regtest windows are set per-test via -sidechainparamsheight
        consensus.WithdrawalMinWorkScore = SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE_PROD;
        consensus.WithdrawalVerificationPeriod = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD_PROD;
        // Two windows, the mainnet ratio. -withdrawalwindow shrinks all three
        // per test (regtest only).
        consensus.WithdrawalFailedRetention = 2 * SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD_PROD;
        consensus.fWithdrawalBoundarySweep = true;
        consensus.SidechainActivationPeriod = SIDECHAIN_ACTIVATION_PERIOD_PROD;
        consensus.SidechainActivationMaxFailures = SIDECHAIN_ACTIVATION_MAX_FAILURES_PROD;
        // Low like the three above, so every fresh test chain that runs
        // past 300 exercises commitment generation and both checks for free.
        consensus.SCDBCommitmentHeight = 300;
        // Low for the same reason, and deliberately the SAME height as the
        // commitment on regtest only: a fresh test chain then exercises
        // both flag days at once, which is what proves the anchor changes
        // nothing the commitment covers. On the live networks they must ride
        // separate releases; see the mainnet block above.
        consensus.CTIPAnchorHeight = 300;
        // The BIP300 escrow rules, low like the rest so every fresh-chain
        // test chain past 300 runs them; -escrowrulesheight moves them per test.
        consensus.EscrowRulesHeight = 300;
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 60 * 60; // one hour (NOT two weeks; that was Bitcoin's)
        consensus.nPowTargetSpacing = 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        // 1, not 144, and 1 of 1 is 100% not 75%. EVERY BLOCK IS ITS OWN
        // VERSIONBITS PERIOD HERE, which is why upstream's trick of moving a
        // deployment's nStartTime off ALWAYS_ACTIVE to keep it inactive does not
        // work on this chain - it only delays activation by about three blocks.
        // See the comment in TestChain100Setup (src/test/test_skydoge.cpp).
        consensus.nRuleChangeActivationThreshold = 1;
        consensus.nMinerConfirmationWindow = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;


        // No minimum work on a chain that is created from nothing every run.
        //
        // These two carried the testnet values, which is wrong in both cases and
        // not merely untidy. A node stays in initial block download until its
        // chain passes nMinimumChainWork, and a node in that state does not
        // announce the blocks it mines; at the regtest difficulty the testnet
        // figure needs roughly 1,200 blocks to clear. Every regtest network
        // below that height therefore mines in silence, and multi-node tests
        // quietly observe nothing propagating - which is exactly the setup
        // needed to exercise reorganisation and block disconnection.
        //
        // The assume-valid hash named a testnet block that cannot exist on a
        // regtest chain, so it never matched and no signature check was ever
        // actually skipped.
        consensus.nMinimumChainWork = uint256S("0x00");
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xa0;
        pchMessageStart[1] = 0x9d;
        pchMessageStart[2] = 0xed;
        pchMessageStart[3] = 0x83;

        nDefaultPort = 18442;
        nPruneAfterHeight = 1000;

        // nBits MUST be powLimit.GetCompact(). fPowAllowMinDifficultyBlocks is
        // set below, and GetNextWorkRequired only returns the minimum target
        // when a block's timestamp clears its parent by more than twice the
        // spacing; otherwise it walks back past the min-difficulty blocks and
        // returns the difficulty of the last block that was not one - which,
        // on a chain this short, is always the genesis. A genesis mined harder
        // than powLimit therefore becomes the floor for every block mined at
        // wall-clock speed. This was 0x1d5fffff, a mainnet-style value 2^24
        // times harder than the limit, which made regtest mine at about two
        // minutes per block and made the PoW-grinding unit test fixtures
        // appear to hang. Upstream uses the limit here for this reason.
        //
        // Testnet declares a byte-identical genesis line and is deliberately
        // NOT changed - it is a live chain and a new genesis would fork it. It
        // does not have this problem anyway: it retargets, so the walk-back
        // stops at a recent adjustment boundary instead of running all the way
        // to the genesis, and its genesis nBits stopped mattering after the
        // first adjustment. Only a chain where nothing retargets can have its
        // genesis act as a permanent floor.
        genesis = CreateGenesisBlock(1670198460, 1, 0x207fffff, 1, 50 * COIN);

        //MineGenesis(genesis,consensus.powLimit,false);
        consensus.hashGenesisBlock = genesis.GetHash();


        assert(consensus.hashGenesisBlock == uint256S("0x68c411a59b55aa9d1470cedd1e1e1d27163f4571eaf57a9c97b32b5b4da9aae3"));
        assert(genesis.hashMerkleRoot == uint256S("0xb04ef21971d8356eb6c8a3ed14eb84a8fafca3ecc8f103cb88e90778ef9b5e86"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks =true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                { 0, uint256S("0x68c411a59b55aa9d1470cedd1e1e1d27163f4571eaf57a9c97b32b5b4da9aae3")},
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

void UpdateSmallBlockHeight(int nHeight)
{
    globalChainParams->UpdateSmallBlockHeight(nHeight);
}

void UpdateTimewarpGuardHeight(int nHeight)
{
    globalChainParams->UpdateTimewarpGuardHeight(nHeight);
}

void UpdateSidechainParamsHeight(int nHeight)
{
    globalChainParams->UpdateSidechainParamsHeight(nHeight);
}

void UpdateWithdrawalWindow(int nVerificationPeriod, int nMinWorkScore, int nFailedRetention)
{
    globalChainParams->UpdateWithdrawalWindow(nVerificationPeriod, nMinWorkScore, nFailedRetention);
}

void UpdateSCDBCommitmentHeight(int nHeight)
{
    globalChainParams->UpdateSCDBCommitmentHeight(nHeight);
}

void UpdateCTIPAnchorHeight(int nHeight)
{
    globalChainParams->UpdateCTIPAnchorHeight(nHeight);
}

void UpdateEscrowRulesHeight(int nHeight)
{
    globalChainParams->UpdateEscrowRulesHeight(nHeight);
}
