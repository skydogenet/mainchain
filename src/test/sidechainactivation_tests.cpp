// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <base58.h>
#include <chainparams.h>
#include <sidechain.h>
#include <sidechaindb.h>
#include <validation.h>

#include <test/test_skydoge.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(sidechainactivation_tests, TestingSetup)

BOOST_AUTO_TEST_CASE(proposal_single)
{
    // Test adding one proposal to scdbTest
    SidechainDB scdbTest;

    // Create sidechain proposal
    Sidechain proposal;
    proposal.nSidechain = 0;
    proposal.title = "test";
    proposal.description = "description";
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

    // Updated scdbTest to add the proposal
    uint256 hash = GetRandHash();
    scdbTest.Update(0, hash, uint256(), std::vector<CTxOut>{out});

    std::vector<SidechainActivationStatus> vActivation;
    vActivation = scdbTest.GetSidechainActivationStatus();

    // Verify scdbTest is tracking the proposal
    BOOST_CHECK((vActivation.size() == 1) && (vActivation.front().proposal.GetHash() == proposal.GetHash()));
}

BOOST_AUTO_TEST_CASE(proposal_multiple)
{
    // Test adding multiple proposal to scdbTest
    SidechainDB scdbTest;

    // Create sidechain proposal
    Sidechain proposal1;
    proposal1.nSidechain = 0;
    proposal1.title = "test1";
    proposal1.description = "description";
    proposal1.strKeyID = "80dca759b4ff2c9e9b65ec790703ad09fba844cd";
    proposal1.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r";

    std::vector<unsigned char> vchPubKey = ParseHex("76a91480dca759b4ff2c9e9b65ec790703ad09fba844cd88ac");
    proposal1.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());

    proposal1.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal1.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Create transaction output with sidechain proposal
    CTxOut out;
    out.scriptPubKey = proposal1.GetProposalScript();
    out.nValue = 50 * CENT;

    BOOST_CHECK(out.scriptPubKey.IsSidechainProposalCommit());

    // Update scdbTest to add the proposal
    uint256 hash1 = GetRandHash();
    scdbTest.Update(0, hash1, uint256(), std::vector<CTxOut>{out});

    // Create sidechain proposal
    Sidechain proposal2;
    proposal2.nSidechain = 1;
    proposal2.title = "test2";
    proposal2.description = "description";
    proposal2.strKeyID = "3542f8d0c4e68ec88220c035055176be5bd72be6";

    std::vector<unsigned char> vchPubKey2 = ParseHex("76a9143542f8d0c4e68ec88220c035055176be5bd72be688ac");
    proposal2.scriptPubKey = CScript(vchPubKey2.begin(), vchPubKey2.end());

    proposal2.strPrivKey = "5KTVDGCDPMvbZocXiTVdjFv7ZSZdYnEJps5ebkRxfzP8JCTVeqe";
    proposal2.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal2.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Create transaction output with sidechain proposal
    CTxOut out2;
    out2.scriptPubKey = proposal2.GetProposalScript();
    out2.nValue = 50 * CENT;

    BOOST_CHECK(out2.scriptPubKey.IsSidechainProposalCommit());

    // Update scdbTest to add the proposal
    scdbTest.Update(1, GetRandHash(), hash1, std::vector<CTxOut>{out2});

    std::vector<SidechainActivationStatus> vActivation;
    vActivation = scdbTest.GetSidechainActivationStatus();

    // Verify scdbTest is tracking the proposals
    BOOST_CHECK((vActivation.size() == 2) &&
            (vActivation.front().proposal.GetHash() == proposal1.GetHash()) &&
            (vActivation.back().proposal.GetHash() == proposal2.GetHash()));
}

BOOST_AUTO_TEST_CASE(proposal_perblock_limit)
{
    // Make sure multiple sidechain proposals in one block will be rejected.
    SidechainDB scdbTest;

    // Creat sidechain proposal
    Sidechain proposal1;
    proposal1.nSidechain = 0;
    proposal1.title = "test1";
    proposal1.description = "description";
    proposal1.strKeyID = "80dca759b4ff2c9e9b65ec790703ad09fba844cd";

    std::vector<unsigned char> vchPubKey = ParseHex("76a91480dca759b4ff2c9e9b65ec790703ad09fba844cd88ac");
    proposal1.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());

    proposal1.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r";
    proposal1.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal1.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Create transaction output with sidechain proposal
    CTxOut out;
    out.scriptPubKey = proposal1.GetProposalScript();
    out.nValue = 50 * CENT;

    BOOST_CHECK(out.scriptPubKey.IsSidechainProposalCommit());

    // Create sidechain proposal
    Sidechain proposal2;
    proposal2.nSidechain = 1;
    proposal2.title = "test2";
    proposal2.description = "description";
    proposal2.strKeyID = "80dca759b4ff2c9e9b65ec790703ad09fba844cd";

    std::vector<unsigned char> vchPubKey2 = ParseHex("76a9143542f8d0c4e68ec88220c035055176be5bd72be688ac");
    proposal2.scriptPubKey = CScript(vchPubKey2.begin(), vchPubKey2.end());

    proposal2.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r";
    proposal2.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal2.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Create transaction output with sidechain proposal
    CTxOut out2;
    out2.scriptPubKey = proposal2.GetProposalScript();
    out2.nValue = 50 * CENT;

    BOOST_CHECK(out2.scriptPubKey.IsSidechainProposalCommit());

    // Update scdbTest to add the proposal
    scdbTest.Update(0, GetRandHash(), uint256(), std::vector<CTxOut>{out, out2});

    std::vector<SidechainActivationStatus> vActivation;
    vActivation = scdbTest.GetSidechainActivationStatus();

    // Nothing should have been added
    BOOST_CHECK(vActivation.empty());
}

BOOST_AUTO_TEST_CASE(activate_single)
{
    SidechainDB scdbTest;

    // Creat sidechain proposal
    Sidechain proposal;
    proposal.nSidechain = 0;
    proposal.nVersion = 0;
    proposal.nVersion = 0;
    proposal.title = "test";
    proposal.description = "description";
    proposal.strKeyID = "80dca759b4ff2c9e9b65ec790703ad09fba844cd";

    std::vector<unsigned char> vchPubKey = ParseHex("76a91480dca759b4ff2c9e9b65ec790703ad09fba844cd88ac");
    proposal.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());

    proposal.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r";
    proposal.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");


    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);
    BOOST_CHECK(ActivateSidechain(scdbTest, proposal, 0));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);
}

BOOST_AUTO_TEST_CASE(activate_multiple)
{
    SidechainDB scdbTest;

    Sidechain proposal1;
    proposal1.nSidechain = 0;
    proposal1.nVersion = 0;
    proposal1.title = "sidechain1";
    proposal1.description = "description";
    proposal1.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal1.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");


    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);
    BOOST_CHECK(ActivateSidechain(scdbTest, proposal1, 0, true));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // Proposal for a second sidechain
    Sidechain proposal2;
    proposal2.nSidechain = 1;
    proposal2.nVersion = 0;
    proposal2.title = "sidechain2";
    proposal2.description = "test";
    proposal2.hashID1 = GetRandHash();
    proposal2.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");


    BOOST_CHECK(ActivateSidechain(scdbTest, proposal2, 0, true));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 2);

    // Copy sidechain 2
    Sidechain proposal3 = proposal2;
    proposal3.nSidechain = 2;
    proposal3.title = "abc";

    BOOST_CHECK(ActivateSidechain(scdbTest, proposal3, 0, true));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 3);
}

BOOST_AUTO_TEST_CASE(activate_max)
{
    SidechainDB scdbTest;

    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);

    Sidechain proposal;
    proposal.nVersion = 0;
    proposal.title = "sidechain";
    proposal.description = "test";
    proposal.hashID1 = GetRandHash();
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

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

    std::vector<Sidechain> vSidechain = scdbTest.GetSidechains();
    BOOST_CHECK(vSidechain.size() == SIDECHAIN_ACTIVATION_MAX_ACTIVE);

    // Check sidechain numbers and active status
    for (size_t i = 0; i < vSidechain.size(); i++) {
        BOOST_CHECK(vSidechain[i].fActive == true);
        BOOST_CHECK(vSidechain[i].nSidechain == i);
    }
}

BOOST_AUTO_TEST_CASE(activate_fail)
{
    // Test adding one proposal to scdbTest and fail to activate it
    SidechainDB scdbTest;

    // Creat sidechain proposal
    Sidechain proposal;
    proposal.nSidechain = 0;
    proposal.nVersion = 0;
    proposal.title = "test";
    proposal.description = "description";
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

    uint256 hash1 = GetRandHash();
    scdbTest.Update(0, hash1, uint256(), std::vector<CTxOut>{out});

    std::vector<SidechainActivationStatus> vActivation;
    vActivation = scdbTest.GetSidechainActivationStatus();

    BOOST_CHECK((vActivation.size() == 1) && (vActivation.front().proposal.GetHash() == proposal.GetHash()));

    // Use the function from validation to generate the commit, and then
    // copy it from the block.
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    GenerateSidechainActivationCommitment(block, proposal.GetHash(), Params().GetConsensus());

    // Add votes until the sidechain is half way activated
    for (int i = 1; i <= SIDECHAIN_ACTIVATION_PERIOD / 2; i++) {
        uint256 hash2 = GetRandHash();
        scdbTest.Update(i, hash2, hash1, block.vtx.front()->vout);
        hash1 = hash2;
    }

    // Check activation status
    // Sidechain should still be in activation cache
    // Sidechain should not be in ValidSidechains
    std::vector<Sidechain> vSidechain = scdbTest.GetActiveSidechains();

    BOOST_CHECK(vSidechain.empty());
}

BOOST_AUTO_TEST_CASE(activate_remove_failed)
{
    // Test that sidechains which have no chance of success (based on their
    // rejection count) are pruned from the activation cache.
    SidechainDB scdbTest;

    // Creat sidechain proposal
    Sidechain proposal;
    proposal.nSidechain = 0;
    proposal.nVersion = 0;
    proposal.title = "test";
    proposal.description = "description";
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

    uint256 hash1 = GetRandHash();
    scdbTest.Update(0, hash1, uint256(), std::vector<CTxOut>{out});

    std::vector<SidechainActivationStatus> vActivation;
    vActivation = scdbTest.GetSidechainActivationStatus();

    BOOST_CHECK((vActivation.size() == 1) && (vActivation.front().proposal.GetHash() == proposal.GetHash()));

    // Pass coinbase without sidechain activation commit into scdbTest enough times
    // that the proposal is rejected and pruned.
    out.scriptPubKey = OP_TRUE;
    out.nValue = 50 * CENT;

    for (int i = 1; i <= SIDECHAIN_ACTIVATION_MAX_FAILURES + 1; i++) {
        vActivation = scdbTest.GetSidechainActivationStatus();
        uint256 hash2 = GetRandHash();
        scdbTest.Update(i, hash2, hash1, std::vector<CTxOut>{out});
        hash1 = hash2;
    }

    // Check activation status
    // Sidechain should have been pruned from activation cache
    // Sidechain should not be in ValidSidechains
    std::vector<SidechainActivationStatus> vActivationFinal;
    vActivationFinal = scdbTest.GetSidechainActivationStatus();
    BOOST_CHECK(vActivationFinal.empty());

    std::vector<Sidechain> vSidechain = scdbTest.GetActiveSidechains();
    BOOST_CHECK(vSidechain.empty());
}

BOOST_AUTO_TEST_CASE(duplicates)
{
    // Test that duplicate pending proposals are rejected.
    // Test that proposals that duplicate an active sidechain are rejected.
    //
    // A proposal is duplcate if any of the sidechain parameters are equal to
    // another sidechain / proposal.

    SidechainDB scdbTest;

    // Test that two exact duplicate proposals are rejected - the first should
    // be the only one that makes it into the activation cache

    // Create sidechain proposal
    Sidechain proposal1;
    proposal1.nSidechain = 0;
    proposal1.title = "test";
    proposal1.description = "description";
    proposal1.strKeyID = "80dca759b4ff2c9e9b65ec790703ad09fba844cd";

    std::vector<unsigned char> vchPubKey = ParseHex("76a91480dca759b4ff2c9e9b65ec790703ad09fba844cd88ac");
    proposal1.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());

    proposal1.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r";
    proposal1.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal1.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Create transaction output with sidechain proposal
    CTxOut out;
    out.scriptPubKey = proposal1.GetProposalScript();
    out.nValue = 50 * CENT;

    BOOST_CHECK(out.scriptPubKey.IsSidechainProposalCommit());

    // Update scdbTest to add the proposal
    uint256 hash1 = GetRandHash();
    BOOST_CHECK(scdbTest.Update(0, hash1, uint256(), std::vector<CTxOut>{out}));

    // Create sidechain proposal
    Sidechain proposal2;
    proposal2.nSidechain = 0;
    proposal2.title = "test";
    proposal2.description = "description";
    proposal2.strKeyID = "80dca759b4ff2c9e9b65ec790703ad09fba844cd";

    std::vector<unsigned char> vchPubKey2 = ParseHex("76a9143542f8d0c4e68ec88220c035055176be5bd72be688ac");
    proposal2.scriptPubKey = CScript(vchPubKey2.begin(), vchPubKey2.end());

    proposal2.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r";
    proposal2.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal2.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Create transaction output with sidechain proposal
    CTxOut out2;
    out2.scriptPubKey = proposal2.GetProposalScript();
    out2.nValue = 50 * CENT;

    BOOST_CHECK(out2.scriptPubKey.IsSidechainProposalCommit());

    // Update scdbTest to add the duplicate proposal - should fail
    BOOST_CHECK(!scdbTest.Update(1, GetRandHash(), hash1, std::vector<CTxOut>{out2}));

    std::vector<SidechainActivationStatus> vActivation;
    vActivation = scdbTest.GetSidechainActivationStatus();

    // Verify scdbTest is tracking only 1 of the 2 proposals
    BOOST_CHECK((vActivation.size() == 1) && (vActivation.front().proposal.GetHash() == proposal1.GetHash()));


    // Test proposing a sidechain that is an exact duplicate of a sidechain
    // that has already activated. Should be rejected.

    // TODO
}

BOOST_AUTO_TEST_CASE(none_active)
{
    // Test that when no sidechains have been activated, the sidechain list
    // lists all of them with inactive status and the correct sidechain number.
    SidechainDB scdbTest;

    // No sidechains should be active
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);

    std::vector<Sidechain> vActive = scdbTest.GetActiveSidechains();
    BOOST_CHECK(vActive.empty());

    std::vector<Sidechain> vSidechain = scdbTest.GetSidechains();
    BOOST_CHECK(vSidechain.size() == SIDECHAIN_ACTIVATION_MAX_ACTIVE);

    // Check sidechain numbers and active status
    for (size_t i = 0; i < vSidechain.size(); i++) {
        BOOST_CHECK(vSidechain[i].fActive == false);
        BOOST_CHECK(vSidechain[i].nSidechain == i);
    }
}

BOOST_AUTO_TEST_CASE(max_active_reverse)
{
    // Test activating the maximum number of sidechains but in reverse order
    // from sidechain #255 to #0.
    SidechainDB scdbTest;

    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);

    Sidechain proposal;
    proposal.nVersion = 0;
    proposal.description = "test";
    proposal.hashID1 = GetRandHash();
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    unsigned int nSidechains = 0;
    for (int i = SIDECHAIN_ACTIVATION_MAX_ACTIVE - 1; i >= 0; i--) {
        proposal.nSidechain = i;
        proposal.title = "sidechain" + std::to_string(i);

        BOOST_CHECK(ActivateSidechain(scdbTest, proposal, 0, true));

        nSidechains++;

        BOOST_CHECK(scdbTest.GetActiveSidechainCount() == nSidechains);
    }

    // Check that the maximum number have been activated
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == SIDECHAIN_ACTIVATION_MAX_ACTIVE);

    std::vector<Sidechain> vSidechain = scdbTest.GetSidechains();
    BOOST_CHECK(vSidechain.size() == SIDECHAIN_ACTIVATION_MAX_ACTIVE);

    // Check sidechain numbers and active status
    for (size_t i = 0; i < vSidechain.size(); i++) {
        BOOST_CHECK(vSidechain[i].fActive == true);
        BOOST_CHECK(vSidechain[i].nSidechain == i);
    }
}

BOOST_AUTO_TEST_CASE(every_other_active)
{
    // Test activating half of the maximum number of sidechains skipping one
    // sidechain slot between each activated sidechain.
    SidechainDB scdbTest;

    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);

    // TODO sidechains with the same key and IDs should be rejected
    Sidechain proposal;
    proposal.nVersion = 0;
    proposal.description = "test";
    proposal.hashID1 = GetRandHash();
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    unsigned int nSidechains = 0;
    for (int i = 0; i < SIDECHAIN_ACTIVATION_MAX_ACTIVE; i++) {
        if (i % 2 == 0)
            continue;

        proposal.nSidechain = i;
        proposal.title = "sidechain" + std::to_string(i);

        BOOST_CHECK(ActivateSidechain(scdbTest, proposal, 0, true));

        nSidechains++;

        BOOST_CHECK(scdbTest.GetActiveSidechainCount() == nSidechains);
    }

    // Check that half of the maximum number have been activated
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == SIDECHAIN_ACTIVATION_MAX_ACTIVE / 2);

    std::vector<Sidechain> vSidechain = scdbTest.GetSidechains();
    BOOST_CHECK(vSidechain.size() == SIDECHAIN_ACTIVATION_MAX_ACTIVE);

    // Check sidechain numbers and active status
    for (size_t i = 0; i < vSidechain.size(); i++) {
        if (i % 2 == 0)
            BOOST_CHECK(vSidechain[i].fActive == false);
        else
            BOOST_CHECK(vSidechain[i].fActive == true);

        BOOST_CHECK(vSidechain[i].nSidechain == i);
    }
}

BOOST_AUTO_TEST_CASE(replace_sidechain)
{
    SidechainDB scdbTest;

    // Activate first sidechain

    // Creat sidechain proposal
    Sidechain proposal;
    proposal.nSidechain = 0;
    proposal.nVersion = 0;
    proposal.nVersion = 0;
    proposal.title = "test";
    proposal.description = "description";
    proposal.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");


    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);
    BOOST_CHECK(ActivateSidechain(scdbTest, proposal, 0, true));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // Create replacement sidechain proposal

    // Creat sidechain proposal
    Sidechain proposal2;
    proposal2.nSidechain = 0;
    proposal2.nVersion = 0;
    proposal2.nVersion = 0;
    proposal2.title = "replacement";
    proposal2.description = "description";
    proposal2.strKeyID = "80dca759b4ff2c9e9b65ec790703ad09fba844cd";

    std::vector<unsigned char> vchPubKey = ParseHex("76a91480dca759b4ff2c9e9b65ec790703ad09fba844cd88ac");
    proposal2.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());

    proposal2.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r";
    proposal2.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal2.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Create transaction output with sidechain proposal
    CTxOut out;
    out.scriptPubKey = proposal2.GetProposalScript();
    out.nValue = 50 * CENT;

    BOOST_CHECK(out.scriptPubKey.IsSidechainProposalCommit());

    uint256 hash1 = GetRandHash();
    BOOST_CHECK(scdbTest.Update(0, hash1, scdbTest.GetHashBlockLastSeen(), std::vector<CTxOut>{out}));

    std::vector<SidechainActivationStatus> vActivation;
    vActivation = scdbTest.GetSidechainActivationStatus();

    BOOST_CHECK((vActivation.size() == 1) && (vActivation.front().proposal.GetHash() == proposal2.GetHash()));

    // Generate a sidechain activation commit for the replacement
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    GenerateSidechainActivationCommitment(block, proposal2.GetHash(), Params().GetConsensus());

    // Add the requirement to replace
    for (int i = 1; i <= SIDECHAIN_REPLACEMENT_PERIOD - 1; i++) {
        uint256 hashNew = GetRandHash();
        BOOST_CHECK(scdbTest.Update(i, hashNew, scdbTest.GetHashBlockLastSeen(), block.vtx.front()->vout));
    }

    // Check that the proposal has half of the replacement requirement
    vActivation = scdbTest.GetSidechainActivationStatus();

    // Check activation status
    // replacement should have been pruned from activation cache
    std::vector<SidechainActivationStatus> vActivationFinal;
    vActivationFinal = scdbTest.GetSidechainActivationStatus();
    BOOST_CHECK(vActivationFinal.empty());

    // Sidechain 0 should now be "replacement"
    // Check that "replacement" sidechain was activated
    std::vector<Sidechain> vSidechain = scdbTest.GetSidechains();
    BOOST_CHECK(vSidechain[0].title == "replacement");
}

BOOST_AUTO_TEST_CASE(replace_sidechain_fail)
{
    SidechainDB scdbTest;

    // Activate first sidechain

    // Creat sidechain proposal
    Sidechain proposal;
    proposal.nSidechain = 0;
    proposal.nVersion = 0;
    proposal.nVersion = 0;
    proposal.title = "test";
    proposal.description = "description";
    proposal.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");


    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);
    BOOST_CHECK(ActivateSidechain(scdbTest, proposal, 0, true));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // Create replacement sidechain proposal

    // Creat sidechain proposal
    Sidechain proposal2;
    proposal2.nSidechain = 0;
    proposal2.nVersion = 0;
    proposal2.nVersion = 0;
    proposal2.title = "replacement";
    proposal2.description = "description";
    proposal2.strKeyID = "80dca759b4ff2c9e9b65ec790703ad09fba844cd";

    std::vector<unsigned char> vchPubKey = ParseHex("76a91480dca759b4ff2c9e9b65ec790703ad09fba844cd88ac");
    proposal2.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());

    proposal2.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r";
    proposal2.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal2.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Create transaction output with sidechain proposal
    CTxOut out;
    out.scriptPubKey = proposal2.GetProposalScript();
    out.nValue = 50 * CENT;

    BOOST_CHECK(out.scriptPubKey.IsSidechainProposalCommit());

    uint256 hash1 = GetRandHash();
    BOOST_CHECK(scdbTest.Update(0, hash1, scdbTest.GetHashBlockLastSeen(), std::vector<CTxOut>{out}));

    std::vector<SidechainActivationStatus> vActivation;
    vActivation = scdbTest.GetSidechainActivationStatus();

    BOOST_CHECK((vActivation.size() == 1) && (vActivation.front().proposal.GetHash() == proposal2.GetHash()));

    // Generate a sidechain activation commit for the replacement
    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    GenerateSidechainActivationCommitment(block, proposal2.GetHash(), Params().GetConsensus());

    // Add half of the requirement to replace
    for (int i = 1; i <= SIDECHAIN_REPLACEMENT_PERIOD / 2; i++) {
        uint256 hashNew = GetRandHash();
        BOOST_CHECK(scdbTest.Update(i, hashNew, scdbTest.GetHashBlockLastSeen(), block.vtx.front()->vout));
    }

    // Generate blocks without activation commitments to make proposal fail

    out.scriptPubKey = OP_TRUE;
    out.nValue = 50 * CENT;

    for (int i = 1; i <= SIDECHAIN_ACTIVATION_MAX_FAILURES + 1; i++) {
        uint256 hash2 = GetRandHash();
        BOOST_CHECK(scdbTest.Update(i, hash2, scdbTest.GetHashBlockLastSeen(), std::vector<CTxOut>{out}));
    }

    // Check activation status
    // replacement should have been pruned from activation cache
    // replacement should not be active
    std::vector<SidechainActivationStatus> vActivationFinal;
    vActivationFinal = scdbTest.GetSidechainActivationStatus();
    BOOST_CHECK(vActivationFinal.empty());

    // Check that "replacement" sidechain was not activated
    // Sidechain 0 should still be "test"
    std::vector<Sidechain> vSidechain = scdbTest.GetSidechains();
    BOOST_CHECK(vSidechain[0].title == "test");
}

BOOST_AUTO_TEST_CASE(unique)
{
    // Test the IsSidechainUnique function

    SidechainDB scdbTest;

    // Activate first sidechain

    // Creat sidechain proposal
    Sidechain proposal;
    proposal.nSidechain = 0;
    proposal.nVersion = 0;
    proposal.title = "test";
    proposal.description = "description";
    proposal.strKeyID = "80dca759b4ff2c9e9b65ec790703ad09fba844cd";

    std::vector<unsigned char> vchPubKey = ParseHex("76a91480dca759b4ff2c9e9b65ec790703ad09fba844cd88ac");
    proposal.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());

    proposal.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r";
    proposal.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");


    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 0);
    BOOST_CHECK(ActivateSidechain(scdbTest, proposal, 0));
    BOOST_CHECK(scdbTest.GetActiveSidechainCount() == 1);

    // Create a duplicate sidechain to test

    Sidechain sidechain;
    sidechain.nSidechain = 0;
    sidechain.nVersion = 0;
    sidechain.title = "test";
    sidechain.description = "description";
    sidechain.strKeyID = "80dca759b4ff2c9e9b65ec790703ad09fba844cd";
    sidechain.scriptPubKey = CScript(vchPubKey.begin(), vchPubKey.end());
    sidechain.strPrivKey = "5Jf2vbdzdCccKApCrjmwL5EFc4f1cUm5Ah4L4LGimEuFyqYpa9r";
    sidechain.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    sidechain.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Duplicate sidechain should not be unique
    BOOST_CHECK(!scdbTest.IsSidechainUnique(sidechain));
}

BOOST_AUTO_TEST_CASE(per_block_activation_limit_pass)
{
    // Test that only one sidechain activation commit is allowed for each
    // sidechain number per block. In this test we will ACK two sidechains that
    // have different sidechain numbers, which should be allowed.
    SidechainDB scdbTest;

    Sidechain proposal1;
    proposal1.nSidechain = 0;
    proposal1.nVersion = 0;
    proposal1.title = "sidechain1";
    proposal1.description = "description";
    proposal1.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal1.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Generate new keys for the sidechain proposal
    uint256 hash1 = GetRandHash();
    CKey key1;
    key1.Set(hash1.begin(), hash1.end(), false);
    CBitcoinSecret vchSecret1(key1);
    CPubKey pubkey1 = key1.GetPubKey();
    CKeyID vchAddress1 = pubkey1.GetID();
    CScript script1 = CScript() << OP_DUP << OP_HASH160 << ToByteVector(vchAddress1) << OP_EQUALVERIFY << OP_CHECKSIG;

    proposal1.strKeyID = HexStr(vchAddress1);
    proposal1.scriptPubKey = script1;
    proposal1.strPrivKey = vchSecret1.ToString();

    // Proposal for a second sidechain
    Sidechain proposal2;
    proposal2.nSidechain = 1;
    proposal2.nVersion = 0;
    proposal2.title = "sidechain2";
    proposal2.description = "test";
    proposal2.hashID1 = GetRandHash();
    proposal2.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Generate new keys for the second sidechain proposal
    uint256 hash2 = GetRandHash();
    CKey key2;
    key2.Set(hash2.begin(), hash2.end(), false);
    CBitcoinSecret vchSecret2(key2);
    CPubKey pubkey2 = key2.GetPubKey();
    CKeyID vchAddress2 = pubkey2.GetID();
    CScript script2 = CScript() << OP_DUP << OP_HASH160 << ToByteVector(vchAddress2) << OP_EQUALVERIFY << OP_CHECKSIG;

    proposal2.strKeyID = HexStr(vchAddress2);
    proposal2.scriptPubKey = script2;
    proposal2.strPrivKey = vchSecret2.ToString();

    // Create transaction outputs with sidechain proposals

    CTxOut out1;
    out1.scriptPubKey = proposal1.GetProposalScript();
    out1.nValue = 50 * CENT;
    BOOST_CHECK(out1.scriptPubKey.IsSidechainProposalCommit());

    CTxOut out2;
    out2.scriptPubKey = proposal2.GetProposalScript();
    out2.nValue = 50 * CENT;
    BOOST_CHECK(out2.scriptPubKey.IsSidechainProposalCommit());

    // Add both proposals to blocks and get them into SCDB
    BOOST_CHECK(scdbTest.Update(0, GetRandHash(), scdbTest.GetHashBlockLastSeen(), std::vector<CTxOut>{out1}));
    BOOST_CHECK(scdbTest.Update(1, GetRandHash(), scdbTest.GetHashBlockLastSeen(), std::vector<CTxOut>{out2}));

    // Check that the proposals were added
    std::vector<SidechainActivationStatus> vActivation;
    vActivation = scdbTest.GetSidechainActivationStatus();
    BOOST_CHECK(vActivation.size() == 2);
    BOOST_CHECK(vActivation.size() && vActivation.front().proposal == proposal1);
    BOOST_CHECK(vActivation.size() && vActivation.back().proposal == proposal2);

    // Start ACKing the proposals

    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    GenerateSidechainActivationCommitment(block, proposal1.GetHash(), Params().GetConsensus());
    GenerateSidechainActivationCommitment(block, proposal2.GetHash(), Params().GetConsensus());

    // Add votes until the sidechains are activated
    int nHeight = 2;
    for (int i = 0; i < SIDECHAIN_ACTIVATION_PERIOD - 1; i++) {
        if (i == SIDECHAIN_ACTIVATION_PERIOD - 2) {
            // For the last block we only want to vote on the second proposal
            // as the first has already activated in the previous block
            CMutableTransaction mtxFinal = CMutableTransaction(*block.vtx[0]);
            mtxFinal.vout.clear();
            block.vtx[0] = MakeTransactionRef(std::move(mtx));
            GenerateSidechainActivationCommitment(block, proposal2.GetHash(), Params().GetConsensus());
        }
        BOOST_CHECK(scdbTest.Update(nHeight, GetRandHash(), scdbTest.GetHashBlockLastSeen(), block.vtx.front()->vout));
        nHeight++;
    }

    // Proposals should be removed now
    vActivation = scdbTest.GetSidechainActivationStatus();
    BOOST_CHECK(vActivation.empty());

    // Both sidechains should be active now
    std::vector<Sidechain> vSidechain = scdbTest.GetActiveSidechains();
    BOOST_CHECK(vSidechain.size() == 2);
}

BOOST_AUTO_TEST_CASE(per_block_activation_limit_fail)
{
    // Test that only one sidechain activation commit is allowed for each
    // sidechain number per block. In this test we will ACK two sidechains that
    // have the same sidechain numbers, which should be rejected.
    SidechainDB scdbTest;

    Sidechain proposal1;
    proposal1.nSidechain = 0;
    proposal1.nVersion = 0;
    proposal1.title = "sidechain1";
    proposal1.description = "description";
    proposal1.hashID1 = uint256S("b55d224f1fda033d930c92b1b40871f209387355557dd5e0d2b5dd9bb813c33f");
    proposal1.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Generate new keys for the sidechain proposal
    uint256 hash1 = GetRandHash();
    CKey key1;
    key1.Set(hash1.begin(), hash1.end(), false);
    CBitcoinSecret vchSecret1(key1);
    CPubKey pubkey1 = key1.GetPubKey();
    CKeyID vchAddress1 = pubkey1.GetID();
    CScript script1 = CScript() << OP_DUP << OP_HASH160 << ToByteVector(vchAddress1) << OP_EQUALVERIFY << OP_CHECKSIG;

    proposal1.strKeyID = HexStr(vchAddress1);
    proposal1.scriptPubKey = script1;
    proposal1.strPrivKey = vchSecret1.ToString();

    // Proposal for a second sidechain
    Sidechain proposal2;
    proposal2.nSidechain = 0;
    proposal2.nVersion = 0;
    proposal2.title = "sidechain2";
    proposal2.description = "test";
    proposal2.hashID1 = GetRandHash();
    proposal2.hashID2 = uint160S("31d98584f3c570961359c308619f5cf2e9178482");

    // Generate new keys for the second sidechain proposal
    uint256 hash2 = GetRandHash();
    CKey key2;
    key2.Set(hash2.begin(), hash2.end(), false);
    CBitcoinSecret vchSecret2(key2);
    CPubKey pubkey2 = key2.GetPubKey();
    CKeyID vchAddress2 = pubkey2.GetID();
    CScript script2 = CScript() << OP_DUP << OP_HASH160 << ToByteVector(vchAddress2) << OP_EQUALVERIFY << OP_CHECKSIG;

    proposal2.strKeyID = HexStr(vchAddress2);
    proposal2.scriptPubKey = script2;
    proposal2.strPrivKey = vchSecret2.ToString();

    // Create transaction outputs with sidechain proposals

    CTxOut out1;
    out1.scriptPubKey = proposal1.GetProposalScript();
    out1.nValue = 50 * CENT;
    BOOST_CHECK(out1.scriptPubKey.IsSidechainProposalCommit());

    CTxOut out2;
    out2.scriptPubKey = proposal2.GetProposalScript();
    out2.nValue = 50 * CENT;
    BOOST_CHECK(out2.scriptPubKey.IsSidechainProposalCommit());

    // Add both proposals to blocks and get them into SCDB
    BOOST_CHECK(scdbTest.Update(0, GetRandHash(), scdbTest.GetHashBlockLastSeen(), std::vector<CTxOut>{out1}));
    BOOST_CHECK(scdbTest.Update(1, GetRandHash(), scdbTest.GetHashBlockLastSeen(), std::vector<CTxOut>{out2}));

    // Check that the proposals were added
    std::vector<SidechainActivationStatus> vActivation;
    vActivation = scdbTest.GetSidechainActivationStatus();
    BOOST_CHECK(vActivation.size() == 2);
    BOOST_CHECK(vActivation.size() && vActivation.front().proposal == proposal1);
    BOOST_CHECK(vActivation.size() && vActivation.back().proposal == proposal2);

    // Start ACKing the proposals

    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));
    GenerateSidechainActivationCommitment(block, proposal1.GetHash(), Params().GetConsensus());
    GenerateSidechainActivationCommitment(block, proposal2.GetHash(), Params().GetConsensus());

    // Acking two sidechains in one block with the same sidechain number should
    // fail
    BOOST_CHECK(!scdbTest.Update(2, GetRandHash(), scdbTest.GetHashBlockLastSeen(), block.vtx.front()->vout));
}

BOOST_AUTO_TEST_SUITE_END()
