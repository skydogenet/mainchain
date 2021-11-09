// Copyright (c) 2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"
#include "consensus/validation.h"
#include "core_io.h"
#include "miner.h"
#include "random.h"
#include "script/script.h"
#include "script/standard.h"
#include "script/sigcache.h"
#include "sidechain.h"
#include "sidechaindb.h"
#include "uint256.h"
#include "utilstrencodings.h"
#include "validation.h"

#include "test/test_skydoge.h"

#include <boost/test/unit_test.hpp>

CScript EncodeWithdrawalFees(const CAmount& amount)
{
    CDataStream s(SER_NETWORK, PROTOCOL_VERSION);
    s << amount;

    CScript script;
    script << OP_RETURN;
    script << std::vector<unsigned char>(s.begin(), s.end());

    return script;
}

BOOST_FIXTURE_TEST_SUITE(sidechaindb_tests, TestingSetup)

bool ActivateTestSidechain(SidechainDB& scdbTest, int nHeight = 0)
{
    // Activate a test sidechain as sidechain #0

    Sidechain proposal;
    proposal.nSidechain = 0;
    proposal.nVersion = 0;
    proposal.title = "Test";
    proposal.description = "Description";
    proposal.strKeyID = "58c63096724814c3dcdf088b9bb0dc48e6e1a89c";
    proposal.strPrivKey = "91jbRcYNm4RpdJy4u99g8KyFTUsWxvXcJcYXYbQp9MU7mX1vg3K";

    std::vector<unsigned char> vch = ParseHex("76a91458c63096724814c3dcdf088b9bb0dc48e6e1a89c88ac");
    proposal.scriptPubKey = CScript(vch.begin(), vch.end());

    proposal.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    return ActivateSidechain(scdbTest, proposal, nHeight);
}

BOOST_AUTO_TEST_CASE(sidechaindb_withdrawal)
{
    // Test creating a withdrawal and approving it with enough workscore
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    uint256 hash = GetRandHash();

    SidechainWithdrawalState state;
    state.hash= hash;
    state.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state.nSidechain = 0;
    int nHeight = 0;
    for (int i = 1; i <= SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE; i++) {
        state.nWorkScore = i;
        BOOST_CHECK(scdbTest.UpdateSCDBIndex(std::vector<SidechainWithdrawalState>{state}));
        nHeight++;
    }

    // Withdrawal should pass with valid workscore
    BOOST_CHECK(scdbTest.CheckWorkScore(0, hash));
}

BOOST_AUTO_TEST_CASE(sidechaindb_mutli_withdraw_one_expires)
{
    // Test multiple verification periods, approve multiple withdrawals on the
    // same sidechain and let one withdrawal expire.
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // Withdrawal hash for first period
    uint256 hash1 = GetRandHash();

    // Verify first transaction, check work score
    SidechainWithdrawalState state1;
    state1.hash = hash1;
    state1.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state1.nSidechain = 0;
    int nHeight = 0;
    int nBlocksLeft = state1.nBlocksLeft + 1;
    for (int i = 1; i <= SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE; i++) {
        state1.nWorkScore = i;
        BOOST_CHECK(scdbTest.UpdateSCDBIndex(std::vector<SidechainWithdrawalState> {state1}));
        nHeight++;
        nBlocksLeft--;
    }
    BOOST_CHECK(scdbTest.CheckWorkScore(0, hash1));

    // Keep updating until the first withdrawal expires
    while (nBlocksLeft >= 0) {
        BOOST_CHECK(scdbTest.UpdateSCDBIndex(std::vector<SidechainWithdrawalState> {state1}, false, std::map<uint8_t, uint256>(), false, true));
        nHeight++;
        nBlocksLeft--;
    }

    // Create dummy coinbase tx
    CMutableTransaction mtx;
    mtx.nVersion = 1;
    mtx.vin.resize(1);
    mtx.vout.resize(1);
    mtx.vin[0].scriptSig = CScript() << 486604799;
    mtx.vout.push_back(CTxOut(50 * CENT, CScript() << OP_RETURN));

    // Withdrawal hash for second period
    uint256 hash2 = GetRandHash();

    // Add new withdrawal
    std::vector<SidechainWithdrawalState> vState;
    SidechainWithdrawalState state2;
    state2.hash = hash2;
    state2.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state2.nSidechain = 0;
    state2.nWorkScore = 1;
    vState.push_back(state2);
    BOOST_CHECK(scdbTest.UpdateSCDBIndex(vState));
    BOOST_CHECK(!scdbTest.CheckWorkScore(0, hash2));

    // Verify that scdbTest has updated to correct withdrawal
    vState = scdbTest.GetState(0);
    BOOST_CHECK(vState.size() == 1 && vState[0].hash == hash2);

    // Give second transaction sufficient workscore and check work score
    nHeight = 0;
    for (int i = 1; i <= SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE; i++) {
        state2.nWorkScore = i;
        scdbTest.UpdateSCDBIndex(std::vector<SidechainWithdrawalState>{state2});
        nHeight++;
    }
    BOOST_CHECK(scdbTest.CheckWorkScore(0, hash2));
}

BOOST_AUTO_TEST_CASE(sidechaindb_MT_single)
{
    // Merkle tree based scdbTest update test with only scdbTest data (no LD)
    // in the tree, and a single withdrawal to be updated.
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // Create scdbTest with initial withdrawal
    std::vector<SidechainWithdrawalState> vState;

    SidechainWithdrawalState state;
    state.hash= GetRandHash();
    state.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state.nWorkScore = 1;
    state.nSidechain = 0;

    vState.push_back(state);
    scdbTest.UpdateSCDBIndex(vState);

    // Create a copy of the scdbTest to manipulate
    SidechainDB scdbTestCopy = scdbTest;

    // Update the scdbTest copy to get a new MT hash
    vState.clear();
    state.nWorkScore++;
    vState.push_back(state);
    scdbTestCopy.UpdateSCDBIndex(vState);

    BOOST_CHECK(scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash()));
}

BOOST_AUTO_TEST_CASE(sidechaindb_MT_multipleSC)
{
    // TODO finish: does not actually test multiple sidechains
    //
    // Merkle tree based scdbTest update test with multiple sidechains that each
    // have one withdrawal to update. Only one withdrawal out of the three will
    // be updated. This test ensures that nBlocksLeft is properly decremented
    // even when a withdrawal's score is unchanged.
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // Add initial withdrawals to scdbTest
    SidechainWithdrawalState state;
    state.hash= GetRandHash();
    state.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state.nSidechain = 0;
    state.nWorkScore = 1;

    std::vector<SidechainWithdrawalState> vState;
    vState.push_back(state);

    scdbTest.UpdateSCDBIndex(vState);

    // Create a copy of the scdbTest to manipulate
    SidechainDB scdbTestCopy = scdbTest;

    // Update the scdbTest copy to get a new MT hash
    state.nWorkScore++;

    vState.clear();
    vState.push_back(state);

    scdbTestCopy.UpdateSCDBIndex(vState);

    // Use MT hash prediction to update the original scdbTest
    BOOST_CHECK(scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash()));
}

BOOST_AUTO_TEST_CASE(sidechaindb_MT_multiple_withdrawal)
{
    // TODO finish: does not actually have multiple sidechains
    // Merkle tree based scdbTest update test with multiple sidechains and
    // multiple withdrawals being updated. This tests that MT based scdbTest
    // update will work if work scores are updated for more than one sidechain
    // per block.
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // Add initial withdrawal to scdbTest
    SidechainWithdrawalState state;
    state.hash = GetRandHash();
    state.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state.nSidechain = 0;
    state.nWorkScore = 1;

    std::vector<SidechainWithdrawalState> vState;
    vState.push_back(state);

    scdbTest.UpdateSCDBIndex(vState);

    // Create a copy of the scdbTest to manipulate
    SidechainDB scdbTestCopy = scdbTest;

    // Update the scdbTest copy to get a new MT hash
    state.nWorkScore++;

    vState.clear();
    vState.push_back(state);

    scdbTestCopy.UpdateSCDBIndex(vState);

    // Use MT hash prediction to update the original scdbTest
    BOOST_CHECK(scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash()));
}

BOOST_AUTO_TEST_CASE(sidechaindb_wallet_ctip_create)
{
    // Create a deposit (and CTIP) for a single sidechain
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();

    CKey key;
    CPubKey pubkey;

    key.MakeNewKey(true);
    pubkey = key.GetPubKey();

    // User deposit data script
    CScript dataScript = CScript() << OP_RETURN << ToByteVector(pubkey.GetID());

    mtx.vout.push_back(CTxOut(CAmount(0), dataScript));

    CScript sidechainScript;
    BOOST_CHECK(scdbTest.GetSidechainScript(0, sidechainScript));

    // Add deposit output
    mtx.vout.push_back(CTxOut(50 * CENT, sidechainScript));

    SidechainDeposit deposit;
    deposit.nSidechain = 0;
    deposit.strDest = "";
    deposit.tx = mtx;
    deposit.nBurnIndex = 1;
    deposit.nTx = 1;
    deposit.hashBlock = GetRandHash();

    scdbTest.AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // Check if deposit was cached
    std::vector<SidechainDeposit> vDeposit = scdbTest.GetDeposits(0);
    BOOST_CHECK(vDeposit.size() == 1 && vDeposit.front() == deposit);

    // Check if CTIP was updated
    SidechainCTIP ctip;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctip));
    BOOST_CHECK(ctip.out.hash == deposit.tx.GetHash());
    BOOST_CHECK(ctip.out.n == 1);
}

BOOST_AUTO_TEST_CASE(sidechaindb_wallet_ctip_multi_sidechain)
{
    // Create a deposit (and CTIP) for multiple sidechains
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);
}

BOOST_AUTO_TEST_CASE(sidechaindb_wallet_ctip_multi_deposits)
{
    // Create many deposits and make sure that single valid CTIP results
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // TODO use the wallet function
    // Create deposit
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();

    CKey key;
    CPubKey pubkey;

    key.MakeNewKey(true);
    pubkey = key.GetPubKey();

    // User deposit data script
    CScript dataScript = CScript() << OP_RETURN << ToByteVector(pubkey.GetID());

    mtx.vout.push_back(CTxOut(CAmount(0), dataScript));

    Sidechain sidechain;
    BOOST_CHECK(scdbTest.GetSidechain(0, sidechain));

    CScript sidechainScript;
    BOOST_CHECK(scdbTest.GetSidechainScript(0, sidechainScript));

    // Add deposit output
    mtx.vout.push_back(CTxOut(50 * CENT, sidechainScript));

    SidechainDeposit deposit;
    deposit.nSidechain = 0;
    deposit.strDest = "";
    deposit.tx = mtx;
    deposit.nBurnIndex = 1;
    deposit.nTx = 1;

    scdbTest.AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // Check if we cached it
    std::vector<SidechainDeposit> vDeposit = scdbTest.GetDeposits(0);
    BOOST_CHECK(vDeposit.size() == 1 && vDeposit.front().tx == mtx);

    // Compare with scdbTest CTIP
    SidechainCTIP ctip;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctip));
    BOOST_CHECK(ctip.out.hash == mtx.GetHash());
    BOOST_CHECK(ctip.out.n == 1);

    // Create another deposit
    CMutableTransaction mtx2;
    mtx2.vin.resize(1);
    mtx2.vin[0].prevout.SetNull();

    CKey key2;
    CPubKey pubkey2;

    key2.MakeNewKey(true);
    pubkey2 = key2.GetPubKey();

    // User deposit data script
    CScript dataScript2 = CScript() << OP_RETURN << ToByteVector(pubkey2.GetID());

    mtx2.vout.push_back(CTxOut(CAmount(0), dataScript2));

    // Add deposit output
    mtx2.vout.push_back(CTxOut(25 * CENT, sidechainScript));

    deposit.tx = mtx2;

    scdbTest.AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // Check if we cached it
    vDeposit.clear();
    vDeposit = scdbTest.GetDeposits(0);
    BOOST_CHECK(vDeposit.size() == 2 && vDeposit.back().tx == mtx2);

    // Compare with scdbTest CTIP
    SidechainCTIP ctip2;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctip2));
    BOOST_CHECK(ctip2.out.hash == mtx2.GetHash());
    BOOST_CHECK(ctip2.out.n == 1);
}

BOOST_AUTO_TEST_CASE(sidechaindb_wallet_ctip_multi_deposits_multi_sidechain)
{
    // TODO
    // Create many deposits and make sure that single valid CTIP results
    // for multiple sidechains.
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);
}

BOOST_AUTO_TEST_CASE(sidechaindb_wallet_ctip_spend_withdrawal)
{
    // Create a deposit (and CTIP) for a single sidechain and then spend it
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // TODO use the wallet function
    // Create deposit
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();

    CKey key;
    CPubKey pubkey;

    key.MakeNewKey(true);
    pubkey = key.GetPubKey();

    // User deposit data script
    CScript dataScript = CScript() << OP_RETURN << ToByteVector(pubkey.GetID());

    mtx.vout.push_back(CTxOut(CAmount(0), dataScript));

    Sidechain sidechain;
    BOOST_CHECK(scdbTest.GetSidechain(0, sidechain));

    CScript sidechainScript;
    BOOST_CHECK(scdbTest.GetSidechainScript(0, sidechainScript));

    // Add deposit output
    mtx.vout.push_back(CTxOut(50 * CENT, sidechainScript));

    SidechainDeposit deposit;
    deposit.nSidechain = 0;
    deposit.strDest = "";
    deposit.tx = mtx;
    deposit.nBurnIndex = 1;
    deposit.nTx = 1;

    scdbTest.AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // Check if we cached it
    std::vector<SidechainDeposit> vDeposit = scdbTest.GetDeposits(0);
    BOOST_CHECK(vDeposit.size() == 1 && vDeposit.front().tx == mtx);

    // Compare with scdbTest CTIP
    SidechainCTIP ctip;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctip));
    BOOST_CHECK(ctip.out.hash == mtx.GetHash());
    BOOST_CHECK(ctip.out.n == 1);

    // Create a withdrawal that spends the CTIP
    CMutableTransaction wmtx;
    wmtx.nVersion = 2;
    wmtx.vin.push_back(CTxIn(ctip.out.hash, ctip.out.n));
    wmtx.vout.push_back(CTxOut(CAmount(0), CScript() << OP_RETURN << ParseHex(HexStr(SIDECHAIN_WITHDRAWAL_RETURN_DEST) )));
    wmtx.vout.push_back(CTxOut(CAmount(0), EncodeWithdrawalFees(1 * CENT)));
    wmtx.vout.push_back(CTxOut(25 * CENT, GetScriptForDestination(pubkey.GetID())));
    wmtx.vout.push_back(CTxOut(24 * CENT, sidechainScript));

    // Give it sufficient work score
    SidechainWithdrawalState state;
    uint256 hashBlind;
    BOOST_CHECK(CTransaction(wmtx).GetBlindHash(hashBlind));
    state.hash = hashBlind;
    state.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state.nSidechain = 0;
    int nHeight = 0;
    for (int i = 1; i <= SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE; i++) {
        state.nWorkScore = i;
        BOOST_CHECK(scdbTest.UpdateSCDBIndex(std::vector<SidechainWithdrawalState>{state}, nHeight));
        nHeight++;
    }

    // The withdrawal should have valid workscore
    BOOST_CHECK(scdbTest.CheckWorkScore(0, hashBlind));

    // Spend the withdrawal
    BOOST_CHECK(scdbTest.SpendWithdrawal(0, GetRandHash(), wmtx, 1));

    // Check that the CTIP has been updated to the change amount
    SidechainCTIP ctipFinal;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctipFinal));
    BOOST_CHECK(ctipFinal.out.hash == wmtx.GetHash());
    BOOST_CHECK(ctipFinal.out.n == 3);
}

BOOST_AUTO_TEST_CASE(sidechaindb_wallet_ctip_spend_withdrawal_then_deposit)
{
    // Create a deposit (and CTIP) for a single sidechain, and then spend it.
    // After doing that, create another deposit.
    SidechainDB scdbTest;

    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // TODO use the wallet function
    // Create deposit
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();

    CKey key;
    CPubKey pubkey;

    key.MakeNewKey(true);
    pubkey = key.GetPubKey();

    // User deposit data script
    CScript dataScript = CScript() << OP_RETURN << ToByteVector(pubkey.GetID());

    mtx.vout.push_back(CTxOut(CAmount(0), dataScript));

    Sidechain sidechain;
    BOOST_CHECK(scdbTest.GetSidechain(0, sidechain));

    CScript sidechainScript;
    BOOST_CHECK(scdbTest.GetSidechainScript(0, sidechainScript));

    // Add deposit output
    mtx.vout.push_back(CTxOut(50 * CENT, sidechainScript));

    SidechainDeposit deposit;
    deposit.nSidechain = 0;
    deposit.strDest = "";
    deposit.tx = mtx;
    deposit.nBurnIndex = 1;
    deposit.nTx = 1;

    scdbTest.AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // Check if we cached it
    std::vector<SidechainDeposit> vDeposit = scdbTest.GetDeposits(0);
    BOOST_CHECK(vDeposit.size() == 1 && vDeposit.front().tx == mtx);

    // Compare with scdbTest CTIP
    SidechainCTIP ctip;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctip));
    BOOST_CHECK(ctip.out.hash == mtx.GetHash());
    BOOST_CHECK(ctip.out.n == 1);

    // Create a withdrawal that spends the CTIP
    CMutableTransaction wmtx;
    wmtx.nVersion = 2;
    wmtx.vin.push_back(CTxIn(ctip.out.hash, ctip.out.n));
    wmtx.vout.push_back(CTxOut(CAmount(0), CScript() << OP_RETURN << ParseHex(HexStr(SIDECHAIN_WITHDRAWAL_RETURN_DEST) )));
    wmtx.vout.push_back(CTxOut(CAmount(0), EncodeWithdrawalFees(1 * CENT)));
    wmtx.vout.push_back(CTxOut(25 * CENT, GetScriptForDestination(pubkey.GetID())));
    wmtx.vout.push_back(CTxOut(24 * CENT, sidechainScript));

    // Give it sufficient work score
    SidechainWithdrawalState state;
    uint256 hashBlind;
    BOOST_CHECK(CTransaction(wmtx).GetBlindHash(hashBlind));
    state.hash= hashBlind;
    state.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state.nSidechain = 0;
    int nHeight = 0;
    for (int i = 1; i <= SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE; i++) {
        state.nWorkScore = i;
        scdbTest.UpdateSCDBIndex(std::vector<SidechainWithdrawalState>{state}, nHeight);
        nHeight++;
    }

    // Withdrawal should have valid workscore
    BOOST_CHECK(scdbTest.CheckWorkScore(0, hashBlind));

    // Spend the withdrawal
    BOOST_CHECK(scdbTest.SpendWithdrawal(0, GetRandHash(), wmtx, 1));

    // Check that the CTIP has been updated to the return amount
    SidechainCTIP ctipFinal;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctipFinal));
    BOOST_CHECK(ctipFinal.out.hash == wmtx.GetHash());
    BOOST_CHECK(ctipFinal.out.n == 3);

    // Create another deposit
    CMutableTransaction mtx2;
    mtx2.vin.resize(1);
    mtx2.vin[0].prevout.SetNull();

    CKey key2;
    CPubKey pubkey2;

    key2.MakeNewKey(true);
    pubkey2 = key2.GetPubKey();

    // User deposit data script
    CScript dataScript2 = CScript() << OP_RETURN << ToByteVector(pubkey2.GetID());

    mtx2.vout.push_back(CTxOut(CAmount(0), dataScript2));

    // Add deposit output
    mtx2.vout.push_back(CTxOut(25 * CENT, sidechainScript));

    deposit.tx = mtx2;

    scdbTest.AddDeposits(std::vector<SidechainDeposit>{ deposit });

    // Check if we cached it
    vDeposit.clear();
    vDeposit = scdbTest.GetDeposits(0);
    // Should now have 3 deposits cached (first deposit, withdrawal change,
    // this deposit)
    BOOST_CHECK(vDeposit.size() == 3 && vDeposit.back().tx == mtx2);

    // Compare with scdbTest CTIP
    SidechainCTIP ctip2;
    BOOST_CHECK(scdbTest.GetCTIP(0, ctip2));
    BOOST_CHECK(ctip2.out.hash == mtx2.GetHash());
    BOOST_CHECK(ctip2.out.n == 1);
}

BOOST_AUTO_TEST_CASE(IsCriticalHashCommit)
{
    // TODO
}

BOOST_AUTO_TEST_CASE(IsSCDBHashMerkleRootCommit)
{
    // TODO
}

BOOST_AUTO_TEST_CASE(IsWithdrawalHashCommit)
{
    // TODO test invalid
    // Test hash commitments for nSidechain 0-255 with random withdrawal hashes
    for (unsigned int i = 0; i < 256; i++) {
        uint256 hash = GetRandHash();
        uint8_t nSidechain = i;

        CBlock block;
        CMutableTransaction mtx;
        mtx.vin.resize(1);
        mtx.vin[0].prevout.SetNull();
        block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
        GenerateWithdrawalHashCommitment(block, hash, nSidechain, Params().GetConsensus());

        uint256 hashFromCommit;
        uint8_t nSidechainFromCommit;
        BOOST_CHECK(block.vtx[0]->vout[0].scriptPubKey.IsWithdrawalHashCommit(hashFromCommit, nSidechainFromCommit));

        BOOST_CHECK(hash == hashFromCommit);
        BOOST_CHECK(nSidechain == nSidechainFromCommit);
    }
}

BOOST_AUTO_TEST_CASE(IsSidechainProposalCommit)
{
    // TODO test more proposals with different data, versions etc
    // TODO test invalid

    // Create sidechain proposal
    Sidechain proposal;
    proposal.nVersion = 0;
    proposal.title = "Test";
    proposal.description = "Description";
    proposal.strKeyID = "80dca759b4ff2c9e9b65ec790703ad09fba844cd";

    std::vector<unsigned char> vchPubKey = ParseHex("76a91480dca759b4ff2c9e9b65ec790703ad09fba844cd88ac");
    proposal.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());

    proposal.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r";
    proposal.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Create transaction output with sidechain proposal
    CTxOut out;
    out.scriptPubKey = proposal.GetProposalScript();
    out.nValue = 50 * CENT;

    BOOST_CHECK(out.scriptPubKey.IsSidechainProposalCommit());
}

BOOST_AUTO_TEST_CASE(IsSidechainActivationCommit)
{
    // TODO test more proposals with different data, versions etc
    // TODO test invalid

    // Create sidechain proposal
    Sidechain proposal;
    proposal.nVersion = 0;
    proposal.title = "Test";
    proposal.description = "Description";
    proposal.strKeyID = "80dca759b4ff2c9e9b65ec790703ad09fba844cd";

    std::vector<unsigned char> vchPubKey = ParseHex("76a91480dca759b4ff2c9e9b65ec790703ad09fba844cd88ac");
    proposal.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());

    proposal.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r";
    proposal.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Use the function from validation to generate the commit, and then
    // copy it from the block.
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    GenerateSidechainActivationCommitment(block, proposal.GetHash(), Params().GetConsensus());

    uint256 hashSidechain;
    BOOST_CHECK(block.vtx[0]->vout[0].scriptPubKey.IsSidechainActivationCommit(hashSidechain));

    BOOST_CHECK(hashSidechain == proposal.GetHash());
}


BOOST_AUTO_TEST_CASE(IsSidechainUpdateBytes)
{
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    CScript script;
    GenerateSCDBUpdateScript(block, script, std::vector<std::vector<SidechainWithdrawalState>>{}, std::vector<SidechainCustomVote>{}, Params().GetConsensus());

    BOOST_CHECK(block.vtx[0]->vout[0].scriptPubKey.IsSCDBUpdate());
}

BOOST_AUTO_TEST_CASE(update_helper_basic)
{
    // A test of the minimal functionality of generating and parsing an SCDB
    // update script. Two sidechains with one withdrawal each.
    // Abstain withdrawal of sidechain 0 and downvote for sidechain 1.
    SidechainDB scdbTest;

    // Activate first sidechain (default test sidechain)
    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // A second sidechain proposal
    Sidechain proposal;
    proposal.nSidechain = 1;
    proposal.nVersion = 0;
    proposal.title = "sidechain2";
    proposal.description = "test";
    proposal.strKeyID = "c37afd89181060fa69deb3b26a0b95c02986ec78";

    std::vector<unsigned char> vchPubKey = ParseHex("76a91480dca759b4ff2c9e9b65ec790703ad09fba844cd88ac");
    proposal.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());

    proposal.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r"; // TODO
    proposal.hashID1 = GetRandHash();
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Activate second sidechain
    BOOST_CHECK(ActivateSidechain(scdbTest, proposal, 0));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 2);

    // Add initial withdrawals to scdbTest
    SidechainWithdrawalState state1;
    state1.hash = GetRandHash();
    state1.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state1.nSidechain = 0; // For first sidechain
    state1.nWorkScore = 1;

    SidechainWithdrawalState state2;
    state2.hash = GetRandHash();
    state2.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state2.nSidechain = 1; // For second sidechain
    state2.nWorkScore = 1;

    std::vector<SidechainWithdrawalState> vState;
    vState.push_back(state1);
    vState.push_back(state2);

    BOOST_CHECK(scdbTest.UpdateSCDBIndex(vState));
    BOOST_CHECK(scdbTest.GetState(0).size() == 1);
    BOOST_CHECK(scdbTest.GetState(1).size() == 1);

    // Create a copy of the scdbTest to manipulate
    SidechainDB scdbTestCopy = scdbTest;

    // Update the scdbTest copy to get a new MT hash
    // No change to withdrawal 1 means it will have a default abstain vote
    state2.nWorkScore--;

    vState.clear();
    vState.push_back(state1);
    vState.push_back(state2);

    BOOST_CHECK(scdbTestCopy.UpdateSCDBIndex(vState));

    // MT hash prediction should fail here without update script
    BOOST_CHECK(!scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash()));

    // Create custom vote for withdrawal 2
    SidechainCustomVote vote;
    vote.nSidechain = 1;
    vote.hash = state2.hash;
    vote.vote = SCDB_DOWNVOTE;

    // Generate an update script
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));

    std::vector<std::vector<SidechainWithdrawalState>> vOldScores;
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOldScores.push_back(scdbTest.GetState(s.nSidechain));
    }
    CScript script;
    GenerateSCDBUpdateScript(block, script, vOldScores, std::vector<SidechainCustomVote>{vote}, Params().GetConsensus());

    BOOST_CHECK(script.IsSCDBUpdate());

    // Use ParseUpdateScript from validation to read it
    std::vector<SidechainWithdrawalState> vNew;
    std::vector<std::vector<SidechainWithdrawalState>> vOld;
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOld.push_back(scdbTest.GetState(s.nSidechain));
    }
    BOOST_CHECK(ParseSCDBUpdateScript(script, vOld, vNew));

    BOOST_CHECK(scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash(), vNew));
}

BOOST_AUTO_TEST_CASE(update_helper_basic_3_withdrawals)
{
    // A test of the minimal functionality of generating and parsing an SCDB
    // update script. One sidechain with three withdrawals.
    // Upvote the middle withdrawal.
    SidechainDB scdbTest;

    // Activate sidechain (default test sidechain)
    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // Add initial withdrawals to scdbTest
    SidechainWithdrawalState state1;
    state1.hash = GetRandHash();
    state1.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state1.nSidechain = 0;
    state1.nWorkScore = 1;

    SidechainWithdrawalState state2;
    state2.hash = GetRandHash();
    state2.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state2.nSidechain = 0;
    state2.nWorkScore = 1;

    SidechainWithdrawalState state3;
    state3.hash = GetRandHash();
    state3.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state3.nSidechain = 0;
    state3.nWorkScore = 1;

    std::vector<SidechainWithdrawalState> vState;
    vState.push_back(state1);
    vState.push_back(state2);
    vState.push_back(state3);

    for (const SidechainWithdrawalState& state : vState) {
        std::map<uint8_t, uint256> mapNewWithdrawal;
        mapNewWithdrawal[state.nSidechain] = state.hash;
        BOOST_CHECK(scdbTest.UpdateSCDBIndex(std::vector<SidechainWithdrawalState>{ state }, false, mapNewWithdrawal));
    }

    BOOST_CHECK(scdbTest.GetState(0).size() == 3);

    // Create a copy of the scdbTest to manipulate
    SidechainDB scdbTestCopy = scdbTest;

    // Update the scdbTest copy to get a new MT hash

    state2.nWorkScore = 1;

    vState.clear();
    vState.push_back(state2);

    BOOST_CHECK(scdbTestCopy.UpdateSCDBIndex(vState));

    // MT hash prediction should fail here without update script
    BOOST_CHECK(!scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash()));

    // Create custom vote for withdrawal 2
    SidechainCustomVote vote;
    vote.nSidechain = 0;
    vote.hash = state2.hash;
    vote.vote = SCDB_UPVOTE;

    // Generate an update script
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));

    std::vector<std::vector<SidechainWithdrawalState>> vOldScores;
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOldScores.push_back(scdbTest.GetState(s.nSidechain));
    }
    CScript script;
    GenerateSCDBUpdateScript(block, script, vOldScores, std::vector<SidechainCustomVote>{vote}, Params().GetConsensus());

    BOOST_CHECK(script.IsSCDBUpdate());

    // Use ParseUpdateScript from validation to read it
    std::vector<SidechainWithdrawalState> vNew;
    std::vector<std::vector<SidechainWithdrawalState>> vOld;
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOld.push_back(scdbTest.GetState(s.nSidechain));
    }
    BOOST_CHECK(ParseSCDBUpdateScript(script, vOld, vNew));

    BOOST_CHECK(scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash(), vNew));
}

BOOST_AUTO_TEST_CASE(update_helper_basic_four_withdrawals)
{
    // A test of the minimal functionality of generating and parsing an SCDB
    // update script. One sidechain with four withdrawals. Upvote the third.
    SidechainDB scdbTest;

    // Activate sidechain (default test sidechain)
    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // Add initial withdrawals to scdbTest
    SidechainWithdrawalState state1;
    state1.hash = GetRandHash();
    state1.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state1.nSidechain = 0;
    state1.nWorkScore = 1;

    SidechainWithdrawalState state2;
    state2.hash = GetRandHash();
    state2.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state2.nSidechain = 0;
    state2.nWorkScore = 1;

    SidechainWithdrawalState state3;
    state3.hash = GetRandHash();
    state3.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state3.nSidechain = 0;
    state3.nWorkScore = 1;

    SidechainWithdrawalState state4;
    state4.hash = GetRandHash();
    state4.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state4.nSidechain = 0;
    state4.nWorkScore = 1;

    std::vector<SidechainWithdrawalState> vState;
    vState.push_back(state1);
    vState.push_back(state2);
    vState.push_back(state3);
    vState.push_back(state4);

    for (const SidechainWithdrawalState& state : vState) {
        std::map<uint8_t, uint256> mapNewWithdrawal;
        mapNewWithdrawal[state.nSidechain] = state.hash;
        BOOST_CHECK(scdbTest.UpdateSCDBIndex(std::vector<SidechainWithdrawalState>{ state }, false, mapNewWithdrawal));
    }

    BOOST_CHECK(scdbTest.GetState(0).size() == 4);

    // Create a copy of the scdbTest to manipulate
    SidechainDB scdbTestCopy = scdbTest;

    // Update the scdbTest copy to get a new MT hash

    state3.nWorkScore = 1;

    vState.clear();
    vState.push_back(state3);

    BOOST_CHECK(scdbTestCopy.UpdateSCDBIndex(vState));

    // MT hash prediction should fail here without update script
    BOOST_CHECK(!scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash()));

    // Create custom vote for withdrawal 2
    SidechainCustomVote vote;
    vote.nSidechain = 0;
    vote.hash = state3.hash;
    vote.vote = SCDB_UPVOTE;

    // Generate an update script
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));

    std::vector<std::vector<SidechainWithdrawalState>> vOldScores;
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOldScores.push_back(scdbTest.GetState(s.nSidechain));
    }
    CScript script;
    GenerateSCDBUpdateScript(block, script, vOldScores, std::vector<SidechainCustomVote>{vote}, Params().GetConsensus());

    BOOST_CHECK(script.IsSCDBUpdate());

    // Use ParseUpdateScript from validation to read it
    std::vector<SidechainWithdrawalState> vNew;
    std::vector<std::vector<SidechainWithdrawalState>> vOld;
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOld.push_back(scdbTest.GetState(s.nSidechain));
    }
    BOOST_CHECK(ParseSCDBUpdateScript(script, vOld, vNew));

    BOOST_CHECK(scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash(), vNew));
}

BOOST_AUTO_TEST_CASE(update_helper_multi_custom)
{
    // SCDB update script test with custom votes for more than one withdrawal
    // and three active sidechains but still only one withdrawal per sidechain.
    SidechainDB scdbTest;

    // Activate first sidechain (default test sidechain)
    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // A second sidechain proposal
    Sidechain proposal;
    proposal.nSidechain = 1;
    proposal.nVersion = 0;
    proposal.title = "sidechain2";
    proposal.description = "test 2";
    proposal.strKeyID = "c37afd89181060fa69deb3b26a0b95c02986ec78";

    std::vector<unsigned char> vchPubKey = ParseHex("76a91480dca759b4ff2c9e9b65ec790703ad09fba844cd88ac");
    proposal.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());

    proposal.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r"; // TODO
    proposal.hashID1 = GetRandHash();
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Activate second sidechain
    BOOST_CHECK(ActivateSidechain(scdbTest, proposal, 0));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 2);

    // A third sidechain proposal
    Sidechain proposal2;
    proposal2.nSidechain = 2;
    proposal2.nVersion = 0;
    proposal2.title = "sidechain3";
    proposal2.description = "test 3";
    proposal2.hashID1 = GetRandHash();
    proposal2.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Activate second sidechain
    BOOST_CHECK(ActivateSidechain(scdbTest, proposal2, 0, true));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 3);

    // Add initial withdrawals to scdbTest
    SidechainWithdrawalState state1;
    state1.hash = GetRandHash();
    state1.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state1.nSidechain = 0; // For first sidechain
    state1.nWorkScore = 1;

    SidechainWithdrawalState state2;
    state2.hash = GetRandHash();
    state2.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state2.nSidechain = 1; // For second sidechain
    state2.nWorkScore = 1;

    SidechainWithdrawalState state3;
    state3.hash = GetRandHash();
    state3.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state3.nSidechain = 2; // For third sidechain
    state3.nWorkScore = 1;

    std::vector<SidechainWithdrawalState> vState;
    vState.push_back(state1);
    vState.push_back(state2);
    vState.push_back(state3);

    BOOST_CHECK(scdbTest.UpdateSCDBIndex(vState));
    BOOST_CHECK(scdbTest.GetState(0).size() == 1);
    BOOST_CHECK(scdbTest.GetState(1).size() == 1);
    BOOST_CHECK(scdbTest.GetState(2).size() == 1);

    // Create a copy of the scdbTest to manipulate
    SidechainDB scdbTestCopy = scdbTest;

    // Update the scdbTest copy to get a new MT hash
    // No change to withdrawal 1 means it will have a default abstain vote

    state2.nWorkScore--;
    state3.nWorkScore++;

    vState.clear();
    vState.push_back(state1);
    vState.push_back(state2);
    vState.push_back(state3);

    BOOST_CHECK(scdbTestCopy.UpdateSCDBIndex(vState));

    // MT hash prediction should fail here without update script
    BOOST_CHECK(!scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash()));

    // Create custom vote for withdrawal 2
    SidechainCustomVote vote;
    vote.nSidechain = 1;
    vote.hash = state2.hash;
    vote.vote = SCDB_DOWNVOTE;

    // Create custom vote for withdrawal 3
    SidechainCustomVote vote2;
    vote2.nSidechain = 2;
    vote2.hash = state3.hash;
    vote2.vote = SCDB_UPVOTE;

    // Generate an update script
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));

    std::vector<std::vector<SidechainWithdrawalState>> vOldScores;
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOldScores.push_back(scdbTest.GetState(s.nSidechain));
    }
    CScript script;
    GenerateSCDBUpdateScript(block, script, vOldScores, std::vector<SidechainCustomVote>{vote, vote2}, Params().GetConsensus());

    BOOST_CHECK(script.IsSCDBUpdate());

    // Use ParseUpdateScript from validation to read it
    std::vector<SidechainWithdrawalState> vNew;
    std::vector<std::vector<SidechainWithdrawalState>> vOld;
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOld.push_back(scdbTest.GetState(s.nSidechain));
    }
    BOOST_CHECK(vOld.size() == 3);
    BOOST_CHECK(ParseSCDBUpdateScript(script, vOld, vNew));
    BOOST_CHECK(vNew.size() == 2);

    BOOST_CHECK(scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash(), vNew));
}

BOOST_AUTO_TEST_CASE(update_helper_multi_custom_multi_withdraw)
{
    // SCDB update script test with custom votes for more than one withdrawal
    // and three active sidechains with multiple withdrawals per sidechain.
    SidechainDB scdbTest;

    // Activate first sidechain (default test sidechain)
    BOOST_CHECK(ActivateTestSidechain(scdbTest));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // A second sidechain proposal
    Sidechain proposal;
    proposal.nSidechain = 1;
    proposal.nVersion = 0;
    proposal.title = "sidechain2";
    proposal.description = "test 2";
    proposal.strKeyID = "c37afd89181060fa69deb3b26a0b95c02986ec78";

    std::vector<unsigned char> vchPubKey = ParseHex("76a91480dca759b4ff2c9e9b65ec790703ad09fba844cd88ac");
    proposal.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());

    proposal.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r"; // TODO
    proposal.hashID1 = GetRandHash();
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Activate second sidechain
    BOOST_CHECK(ActivateSidechain(scdbTest, proposal, 0));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 2);

    // A third sidechain proposal
    Sidechain proposal2;
    proposal2.nSidechain = 2;
    proposal2.nVersion = 0;
    proposal2.title = "sidechain3";
    proposal2.description = "test 3";
    proposal2.hashID1 = GetRandHash();
    proposal2.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Activate third sidechain
    BOOST_CHECK(ActivateSidechain(scdbTest, proposal2, 0, true));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 3);

    // Add initial withdrawals to scdbTest
    SidechainWithdrawalState state1a;
    state1a.hash = GetRandHash();
    state1a.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state1a.nSidechain = 0; // For first sidechain
    state1a.nWorkScore = 1;

    SidechainWithdrawalState state2a;
    state2a.hash = GetRandHash();
    state2a.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state2a.nSidechain = 1; // For second sidechain
    state2a.nWorkScore = 1;

    SidechainWithdrawalState state3a;
    state3a.hash = GetRandHash();
    state3a.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state3a.nSidechain = 2; // For third sidechain
    state3a.nWorkScore = 1;

    std::vector<SidechainWithdrawalState> vState;
    vState.push_back(state1a);
    vState.push_back(state2a);
    vState.push_back(state3a);

    BOOST_CHECK(scdbTest.UpdateSCDBIndex(vState));
    BOOST_CHECK(scdbTest.GetState(0).size() == 1);
    BOOST_CHECK(scdbTest.GetState(1).size() == 1);
    BOOST_CHECK(scdbTest.GetState(2).size() == 1);

    // Create a copy of the scdbTest to manipulate
    SidechainDB scdbTestCopy = scdbTest;

    // Update the scdbTest copy to get a new MT hash
    state3a.nWorkScore++;

    vState.clear();
    vState.push_back(state3a);

    BOOST_CHECK(scdbTestCopy.UpdateSCDBIndex(vState));

    // MT hash prediction should fail here without update script
    BOOST_CHECK(!scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash()));

    // Create custom vote for withdrawal 1
    SidechainCustomVote vote;
    vote.nSidechain = 0;
    vote.hash = state1a.hash;
    vote.vote = SCDB_DOWNVOTE;

    // Create custom vote for withdrawal 2
    SidechainCustomVote vote1;
    vote1.nSidechain = 1;
    vote1.hash = state2a.hash;
    vote1.vote = SCDB_DOWNVOTE;

    // Create custom vote for withdrawal 3
    SidechainCustomVote vote2;
    vote2.nSidechain = 2;
    vote2.hash = state3a.hash;
    vote2.vote = SCDB_UPVOTE;

    // Generate an update script
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));

    std::vector<std::vector<SidechainWithdrawalState>> vOldScores;
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOldScores.push_back(scdbTest.GetState(s.nSidechain));
    }
    CScript script;
    GenerateSCDBUpdateScript(block, script, vOldScores, std::vector<SidechainCustomVote>{vote2}, Params().GetConsensus());

    BOOST_CHECK(script.IsSCDBUpdate());

    // Use ParseUpdateScript from validation to read it
    std::vector<SidechainWithdrawalState> vNew;
    std::vector<std::vector<SidechainWithdrawalState>> vOld;
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOld.push_back(scdbTest.GetState(s.nSidechain));
    }
    BOOST_CHECK(vOld.size() == 3);
    BOOST_CHECK(ParseSCDBUpdateScript(script, vOld, vNew));
    BOOST_CHECK(vNew.size() == 1);

    BOOST_CHECK(scdbTest.UpdateSCDBMatchMT(2, scdbTestCopy.GetSCDBHash(), vNew));

    // Now add more withdrawals to the existing sidechains
    SidechainWithdrawalState state1b;
    state1b.hash = GetRandHash();
    state1b.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state1b.nSidechain = 0; // For first sidechain
    state1b.nWorkScore = 1;

    SidechainWithdrawalState state2b;
    state2b.hash = GetRandHash();
    state2b.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state2b.nSidechain = 1; // For second sidechain
    state2b.nWorkScore = 1;

    SidechainWithdrawalState state3b;
    state3b.hash = GetRandHash();
    state3b.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
    state3b.nSidechain = 2; // For third sidechain
    state3b.nWorkScore = 1;

    vState.clear();
    vState.push_back(state1b);
    vState.push_back(state2b);
    vState.push_back(state3b);

    BOOST_CHECK(scdbTest.UpdateSCDBIndex(vState));
    BOOST_CHECK(scdbTest.GetState(0).size() == 2);
    BOOST_CHECK(scdbTest.GetState(1).size() == 2);
    BOOST_CHECK(scdbTest.GetState(2).size() == 2);

    // Create a copy of the scdbTest to manipulate
    SidechainDB scdbTestCopy2 = scdbTest;

    state3b.nWorkScore++;

    vState.clear();
    vState.push_back(state3b);

    BOOST_CHECK(scdbTestCopy2.UpdateSCDBIndex(vState));

    // MT hash prediction should fail here without update script
    BOOST_CHECK(!scdbTest.UpdateSCDBMatchMT(4, scdbTestCopy2.GetSCDBHash()));

    // Create custom votes for withdrawals
    SidechainCustomVote vote3;
    vote3.nSidechain = 0;
    vote3.hash = state1a.hash;
    vote3.vote = SCDB_DOWNVOTE;

    SidechainCustomVote vote4;
    vote4.nSidechain = 1;
    vote4.hash = state2a.hash;
    vote4.vote = SCDB_DOWNVOTE;

    SidechainCustomVote vote5;
    vote5.nSidechain = 2;
    vote5.hash = state3b.hash;
    vote5.vote = SCDB_UPVOTE;

    // Generate an update script
    CBlock block2;
    CMutableTransaction mtx2;
    mtx2.vin.resize(1);
    mtx2.vin[0].prevout.SetNull();
    block2.vtx.push_back(MakeTransactionRef(std::move(mtx2)));

    vOldScores.clear();
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOldScores.push_back(scdbTest.GetState(s.nSidechain));
    }
    CScript script2;
    GenerateSCDBUpdateScript(block2, script2, vOldScores, std::vector<SidechainCustomVote>{vote3, vote4, vote5}, Params().GetConsensus());

    BOOST_CHECK(script2.IsSCDBUpdate());

    // Use ParseUpdateScript from validation to read it
    vNew.clear();
    vOld.clear();
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOld.push_back(scdbTest.GetState(s.nSidechain));
    }
    BOOST_CHECK(vOld.size() == 3);
    BOOST_CHECK(ParseSCDBUpdateScript(script2, vOld, vNew));
    BOOST_CHECK(vNew.size() == 3);

    BOOST_CHECK(scdbTest.UpdateSCDBMatchMT(4, scdbTestCopy2.GetSCDBHash(), vNew));
}

BOOST_AUTO_TEST_CASE(update_helper_max_active)
{
    // Do a test where the maximum number of sidechains are active and we have
    // some custom votes
    SidechainDB scdbTest;

    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);

    Sidechain proposal;
    proposal.nVersion = 0;
    proposal.title = "sidechain";
    proposal.description = "test";
    proposal.hashID1 = GetRandHash();
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Activate the maximum number of sidechains allowed
    unsigned int nSidechains = 0;
    for (int i = 0; i < SIDECHAIN_ACTIVATION_MAX_ACTIVE; i++) {
        proposal.nSidechain = i;
        proposal.title = "sidechain" + std::to_string(i);

        BOOST_CHECK(ActivateSidechain(scdbTest, proposal, 0, true));

        nSidechains++;

        BOOST_CHECK(scdbTest.GetActiveSidechainCount() == nSidechains);
    }

    // Check that the maximum number have been activated
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == SIDECHAIN_ACTIVATION_MAX_ACTIVE);

    // Add one withdrawal to SCDB for each sidechain
    int nBlock = 0;
    std::vector<SidechainWithdrawalState> vState;
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        // Create withdrawal
        SidechainWithdrawalState state;
        state.hash = GetRandHash();
        state.nBlocksLeft = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD - 1;
        state.nSidechain = s.nSidechain;
        state.nWorkScore = 1;

        vState.push_back(state);
    }
    // Check that all of the withdrawals are added
    BOOST_CHECK(scdbTest.UpdateSCDBIndex(vState));
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        BOOST_CHECK(scdbTest.GetState(s.nSidechain).size() == 1);
    }
    nBlock++;

    // Create a copy of SCDB that we can modify the scores of. Use update helper
    // script to make scdbTest match scdbTestCopy
    SidechainDB scdbTestCopy = scdbTest;

    // Get the current scores of all withdrawals and then create new votes
    std::vector<SidechainWithdrawalState> vNewScores;
    std::vector<SidechainCustomVote> vUserVotes;
    int i = 0;
    for (const Sidechain& s : scdbTestCopy.GetActiveSidechains()) {
        // Get the current scores for this sidechain
        std::vector<SidechainWithdrawalState> vOldScores = scdbTestCopy.GetState(s.nSidechain);

        // There should be one score
        BOOST_CHECK(vOldScores.size() == 1);

        SidechainWithdrawalState state = vOldScores.front();

        // Create custom vote
        SidechainCustomVote vote;
        vote.nSidechain = s.nSidechain;
        vote.hash = state.hash;

        // If i is an even number set downvote otherwise upvote
        if (i % 2 == 0) {
            state.nWorkScore--;
            vote.vote = SCDB_DOWNVOTE;
        } else {
            state.nWorkScore++;
            vote.vote = SCDB_UPVOTE;
        }

        vNewScores.push_back(state);
        vUserVotes.push_back(vote);
        i++;
    }
    BOOST_CHECK(scdbTestCopy.UpdateSCDBIndex(vNewScores));

    // MT hash prediction should fail here without update script
    BOOST_CHECK(!scdbTest.UpdateSCDBMatchMT(nBlock, scdbTestCopy.GetSCDBHash()));

    // Generate an update script
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));

    std::vector<std::vector<SidechainWithdrawalState>> vOldScores;
    for (const Sidechain& s : scdbTestCopy.GetActiveSidechains()) {
        vOldScores.push_back(scdbTestCopy.GetState(s.nSidechain));
    }
    CScript script;
    GenerateSCDBUpdateScript(block, script, vOldScores, vUserVotes, Params().GetConsensus());

    BOOST_CHECK(script.IsSCDBUpdate());

    // Use ParseUpdateScript from validation to read it
    vNewScores.clear();
    vOldScores.clear();
    for (const Sidechain& s : scdbTest.GetActiveSidechains()) {
        vOldScores.push_back(scdbTest.GetState(s.nSidechain));
    }
    BOOST_CHECK(vOldScores.size() == 256);
    BOOST_CHECK(ParseSCDBUpdateScript(script, vOldScores, vNewScores));
    BOOST_CHECK(vNewScores.size() == 256);

    BOOST_CHECK(scdbTest.UpdateSCDBMatchMT(nBlock, scdbTestCopy.GetSCDBHash(), vNewScores));
    BOOST_CHECK(scdbTest.GetSCDBHash() == scdbTestCopy.GetSCDBHash());
}

BOOST_AUTO_TEST_CASE(custom_vote_cache)
{
    // Test the functionality of the custom vote cache

    unsigned int nMaxSidechain = 256;

    // Test that we can add a vote for every possible sidechain number

    std::vector<SidechainCustomVote> vVoteIn;
    for (size_t i = 0; i < nMaxSidechain; i++) {
        SidechainCustomVote vote;
        vote.nSidechain = i;
        vote.hash = GetRandHash();
        vote.vote = SCDB_UPVOTE;

        vVoteIn.push_back(vote);
    }
    BOOST_CHECK(scdb.CacheCustomVotes(vVoteIn));

    std::vector<SidechainCustomVote> vVoteOut = scdb.GetCustomVoteCache();
    BOOST_CHECK(vVoteOut.size() == nMaxSidechain);

    // Test that new votes replace old votes for the same sidechain

    // Add a new vote for each sidechain and check that they have replaced all
    // of the old votes
    vVoteIn.clear();
    for (size_t i = 0; i < nMaxSidechain; i++) {
        SidechainCustomVote vote;
        vote.nSidechain = i;
        vote.hash = GetRandHash();
        vote.vote = SCDB_ABSTAIN;

        vVoteIn.push_back(vote);
    }
    BOOST_CHECK(scdb.CacheCustomVotes(vVoteIn));

    vVoteOut.clear();
    vVoteOut = scdb.GetCustomVoteCache();
    BOOST_CHECK(vVoteOut.size() == nMaxSidechain);
    // Check that all of the new votes replaced the old ones (the votes were
    // set to abstain so this is easy to check)
    for (const SidechainCustomVote& v : vVoteOut) {
        BOOST_CHECK(v.vote == SCDB_ABSTAIN);
    }

    // Test that changing vote type updates the current vote

    // Pass in the same votes as currently in the cache, but with their vote
    // type changed to SCDB_DOWNVOTE and make sure they were all changed
    for (size_t i = 0; i < vVoteOut.size(); i++) {
        vVoteOut[i].vote = SCDB_DOWNVOTE;
        BOOST_CHECK(scdb.CacheCustomVotes(std::vector<SidechainCustomVote> { vVoteOut[i] }));
    }
    vVoteOut.clear();
    vVoteOut = scdb.GetCustomVoteCache();
    BOOST_CHECK(vVoteOut.size() == nMaxSidechain);
    for (const SidechainCustomVote& v : vVoteOut) {
        BOOST_CHECK(v.vote == SCDB_DOWNVOTE);
    }

    scdb.Reset();
    // Check that custom vote cache was cleared
    vVoteOut = scdb.GetCustomVoteCache();
    BOOST_CHECK(vVoteOut.empty());

    // Test adding each vote type and check that it is set correctly
    SidechainCustomVote upvote;
    upvote.nSidechain = 0;
    upvote.hash = GetRandHash();
    upvote.vote = SCDB_UPVOTE;

    SidechainCustomVote abstain;
    abstain.nSidechain = 1;
    abstain.hash = GetRandHash();
    abstain.vote = SCDB_ABSTAIN;

    SidechainCustomVote downvote;
    downvote.nSidechain = 2;
    downvote.hash = GetRandHash();
    downvote.vote = SCDB_DOWNVOTE;

    BOOST_CHECK(scdb.CacheCustomVotes(std::vector<SidechainCustomVote> { upvote, abstain, downvote }));

    vVoteOut = scdb.GetCustomVoteCache();
    BOOST_REQUIRE(vVoteOut.size() == 3);
    BOOST_CHECK(vVoteOut[0] == upvote);
    BOOST_CHECK(vVoteOut[1] == abstain);
    BOOST_CHECK(vVoteOut[2] == downvote);

    scdb.Reset();
    // Check that custom vote cache was cleared
    vVoteOut = scdb.GetCustomVoteCache();
    BOOST_CHECK(vVoteOut.empty());

    // Check that invalid vote types are rejected the current cache size is 3
    SidechainCustomVote invalidVote;
    invalidVote.nSidechain = 2;
    invalidVote.hash = GetRandHash();
    invalidVote.vote = 'z';

    BOOST_CHECK(!scdb.CacheCustomVotes(std::vector<SidechainCustomVote>{ invalidVote }));
    vVoteOut = scdb.GetCustomVoteCache();
    BOOST_CHECK(vVoteOut.empty());

    invalidVote.vote = ' ';

    BOOST_CHECK(!scdb.CacheCustomVotes(std::vector<SidechainCustomVote>{ invalidVote }));
    vVoteOut = scdb.GetCustomVoteCache();
    BOOST_CHECK(vVoteOut.empty());

    SidechainCustomVote nullHash;
    nullHash.nSidechain = 2;
    nullHash.hash.SetNull();
    nullHash.vote = SCDB_DOWNVOTE;

    BOOST_CHECK(!scdb.CacheCustomVotes(std::vector<SidechainCustomVote>{ nullHash }));
    vVoteOut = scdb.GetCustomVoteCache();
    BOOST_CHECK(vVoteOut.empty());
}

BOOST_AUTO_TEST_CASE(has_sidechain_script)
{
    // Test checking if a script is an active sidechain deposit script
    SidechainDB scdbTest;

    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);
    BOOST_CHECK(ActivateTestSidechain(scdbTest, 0));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    Sidechain sidechain;
    BOOST_CHECK(scdbTest.GetSidechain(0, sidechain));

    CScript scriptPubKey = sidechain.scriptPubKey;

    CScript scriptFromDB;
    BOOST_CHECK(scdbTest.GetSidechainScript(0, scriptFromDB));
    BOOST_CHECK(scriptFromDB == scriptPubKey);

    uint8_t nSidechain;
    BOOST_CHECK(scdbTest.HasSidechainScript(std::vector<CScript>{scriptPubKey}, nSidechain));
    BOOST_CHECK(nSidechain == 0);
    BOOST_CHECK(nSidechain == sidechain.nSidechain);

    CScript scriptInvalid = CScript() << 0x01 << 0x02 << 0x03 << 0x04;
    BOOST_CHECK(!scdbTest.HasSidechainScript(std::vector<CScript>{scriptInvalid}, nSidechain));
}

BOOST_AUTO_TEST_CASE(txn_to_deposit)
{
    // Test of the TxnToDeposit function. This is used by the memory pool and
    // connectBlock to easily decode a SidechainDeposit from a deposit transaction.

    // Activate test sidechain

    SidechainDB scdbTest;

    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);
    BOOST_CHECK(ActivateTestSidechain(scdbTest, 0));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // TODO add deposit serialization and check that deposit deserialized from
    // txn matches deposit example.

    // Serialized transaction
    std::string strTx1 = "0200000001021cfe01d1bbc1fdaa99126c0baba3573689fbd5f932a014b08612800b1329c40000000049483045022100a58e545a71f2c9cb03e06c0d8aff1a62f6bc204480db8650eeb0a3908d332aaf022038f9ae490fd3ed1825c1397c9ae41cd3aed7711b4e2d99a3a10e380506539da101ffffffff03807a7723010000001976a91470a3e11a039059d01bbf463af74c79c22a6270fd88ac0000000000000000246a227367596b444665487a745544583171384a4e726d614631435165723179527142507700e1f505000000001976a91458c63096724814c3dcdf088b9bb0dc48e6e1a89c88ac00000000";

    // Deserialize
    CMutableTransaction mtx;
    BOOST_CHECK(DecodeHexTx(mtx, strTx1));

    // TxnToDeposit
    SidechainDeposit deposit;
    BOOST_CHECK(scdbTest.TxnToDeposit(mtx, 0, {}, deposit));
}

BOOST_AUTO_TEST_SUITE_END()
