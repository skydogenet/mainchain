// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/merkletreedialog.h>
#include <qt/forms/ui_merkletreedialog.h>

#include <hash.h>
#include <consensus/merkle.h>
#include <streams.h>

#include <sstream>

static const char* strHelp =
"This window allows you to audit the \"hashMerkleRoot\" field. You can see each step of the process yourself.\n\n"
"         MerkleRoot = hashZ\n\n"
"                hashZ\n"
"               /    \\\n"
"              /      \\\n"
"           hashX       hashY |\n"
"           /   \\         \\\n"
"          /     \\         \\\n"
"         /       \\         \\\n"
"     hashF       hashG  |   hashH\n"
"    /   \\       /     \\      \\\n"
"hashA  hashB | hashC  hashD | hashE\n"
"\n\n"
"Notes:\n"
"1. hashF = Sha256D ( hashA, hashB )\n"
"* * Each node in the tree, is the hash of the two nodes beneath it.\n"
"2. hashY = Sha256D ( hashH, hashH )\n"
"* * In the operations above, Hash \"H\" is repeated on purpose. If there is an odd number of nodes at that level, the final node is hashed with itself.\n"
"3. Hashes A through E are TxIDs -- the hashes of each transaction.\n\n"
"Use the HashCalculator to check that the Sha256D hash of the first two TxIDs is the value one level above it. And so on ad infinitum.\n\n"
"Further Reading:\n"
"* https://en.bitcoinwiki.org/wiki/Merkle_tree\n"
"* https://www.investopedia.com/terms/m/merkle-tree.asp\n"
"* https://www.geeksforgeeks.org/introduction-to-merkle-tree/\n"

"\n"

"What is RCB?\n\n"

"Computers sometimes have a crazy way of reading from their computer memory, related to something called \"endianness\".\n"
"For whatever reason, Bitcoin merkle root hash calculations run like this:\n\n"

"Hashes:          ... | hash01 hash02 | ...\n"
"Reversed Bytes:  ... | 01shha 02shha | ...\n"
"Next Level:      ... | Sha256D(\"01shha02shha\") | ...\n\n"

"For convenience, we provide both the \"original bytes\" and the \"Reversed Concatenated\" bytes (RCB).\n"
"You can just paste the latter into our Sha256D Hash Calculator.\n\n"

"If you want to do everything yourself copy one TxID, reverse the hex using our hash calculator \"flip hex\" button and do the same to the\n"
"second TxID. Concatenate the reversed hashes and then paste that into the Sha256D section of the hash calculator to calculate one hash for\n"
"the next level of the tree.\n\n"

"Example:\n\n"

"                                                                                                   ***                          \n"
"hash1 bd 3a 49 8b ea ca 2b 11 8b 90 f3 72 c0 3d df 92 6c f1 67 c3 d9 7d b2 60 f4 be 32 e3 97 3a 4a c1 , hash2 7c 1a ... 59 48 27\n"
"+++                                                                                          ^^    ^^         ^^              ^^\n"
"                                                                                              |     |          |               |\n"
"       ---------------------------------------------------------------------------------------|-----           |               |\n"
"      |                                                                                       |                |               |\n"
"      |    -----------------------------------------------------------------------------------                 |               |\n"
"      |   |                                                          ***                                       |               |\n"
"                                                                                                               |               |\n"
"     c14a3a97e332bef460b27dd9c367f16c92df3dc072f3908b112bcaea8b493abd274859...1a7c                             |               |\n"
"     ^^  ^^                                                          ^^         ^^                             |               |\n"
"     +++                                                              |          |                             |               |\n"
"                                                                      |           -----------------------------                |\n"
"                                                                      |                                                        |\n"
"                                                                       -------------------------------------------------------- \n"
"\n\n"
"For reference, we also provide the wtxid hashes and segwit merkleroot (which is now the \"real\" one)";


MerkleTreeDialog::MerkleTreeDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MerkleTreeDialog)
{
    ui->setupUi(this);
}

MerkleTreeDialog::~MerkleTreeDialog()
{
    delete ui;
}

void MerkleTreeDialog::SetTrees(const std::vector<uint256>& vLeaf, const std::vector<uint256>& vSegwitLeaf)
{
    ui->textBrowserTree->setText(QString::fromStdString(MerkleTreeString(vLeaf, ui->checkBoxRCB->isChecked())));
    ui->textBrowserWTree->setText(QString::fromStdString(WitnessTreeString(vSegwitLeaf, ui->checkBoxRCB->isChecked())));
    ui->textBrowserHelp->setText(QString::fromStdString(strHelp));

    vLeafCache = vLeaf;
    vSegwitLeafCache = vSegwitLeaf;
}

void MerkleTreeDialog::on_checkBoxRCB_stateChanged(int checked)
{
    ui->textBrowserTree->setText(QString::fromStdString(MerkleTreeString(vLeafCache, ui->checkBoxRCB->isChecked())));
    ui->textBrowserWTree->setText(QString::fromStdString(WitnessTreeString(vSegwitLeafCache, ui->checkBoxRCB->isChecked())));
}

std::vector<std::vector<uint256>> MerkleTree(const std::vector<uint256>& vLeaf)
{
    if (vLeaf.size() == 0)
        return {};

    // x = level in tree, y = hash
    // Level 0 is the leaves, and the last level is merkle root
    std::vector<std::vector<uint256>> vTree;

    // Generate a merkle tree

    // Copy leaves (TxIds) and add first non-leaf level
    vTree.resize(2);
    vTree[0] = vLeaf;

    // Index in the current level
    size_t i = 0;

    // Current level of the tree
    size_t nLevel = 0;

    // Loop through each level of the tree combining every 2 hashes (starting
    // with txids on level 0) until the merkle root is alone on the last level.
    while (true && vLeaf.size() > 1) {
        // Check if we reached the end of this level
        if (i >= vTree[nLevel].size()) {
            // Does the next level have anything for us to work on?
            if (vTree[nLevel + 1].size() <= 1)
                break;

            i = 0;
            nLevel++;

            // Add a new level to the tree
            vTree.push_back(std::vector<uint256>());
        }

        // Collect next 2 hashes which will be combined
        uint256 hash1 = vTree[nLevel][i];
        uint256 hash2 = i + 1 < vTree[nLevel].size() ? vTree[nLevel][i + 1] : hash1;

        // Write hash1 and hash2 to buffer and finalize SHA256D product
        uint256 product;
        CHash256().Write(hash1.begin(), 32).Write(hash2.begin(), 32).Finalize(product.begin());

        vTree[nLevel + 1].push_back(product);

        // Move on to the next pair
        i+= 2;
    }

    // Special case for block with only coinbase transaction
    if (vLeaf.size() == 1) {
        vTree.clear();
        vTree.resize(1);
        vTree.front().push_back(vLeaf.front());
    }

    return vTree;
}

std::vector<std::vector<std::string>> RCBTree(const std::vector<uint256>& vLeaf)
{
    // Create Merkle Tree from TxIDs
    std::vector<std::vector<uint256>> vTree = MerkleTree(vLeaf);

    if (vTree.size() <= 1)
        return std::vector<std::vector<std::string>>();

    // Make all levels of the tree even
    for (size_t x = 0; x < vTree.size(); x++) {
        if (vTree[x].size() % 2)
            vTree[x].push_back(vTree[x].back());
    }

    std::vector<std::vector<std::string>> vTreeString;
    vTreeString.resize(vTree.size());

    // Format results
    size_t nLevel = vTree.size() - 1;
    for (auto ritx = vTree.rbegin(); ritx != vTree.rend(); ritx++) {
        if (ritx->size() < 2) {
            return std::vector<std::vector<std::string>>();
        }

        // Loop through the level, reversing and concatenating every 2 hashes
        for (auto it = ritx->begin(); it != ritx->end(); it += 2) {
            uint256 hash1 = *it;
            uint256 hash2 = *(it + 1);

            bool fLast = hash2 == ritx->back();

            std::reverse(hash1.begin(), hash1.end());
            std::reverse(hash2.begin(), hash2.end());

            std::string str = "";
            if (fLast)
                str = hash1.ToString() + hash2.ToString() + "\n";
            else
                str = hash1.ToString() + hash2.ToString() + ",  ";

            vTreeString[nLevel].push_back(str);
        }
        nLevel--;
    }
    return vTreeString;
}

std::string MerkleTreeString(const std::vector<uint256>& vLeaf, bool fRCB)
{
    // Create Merkle Tree from TxIDs
    std::vector<std::vector<uint256>> vTree = MerkleTree(vLeaf);

    // Create RCB string tree
    std::vector<std::vector<std::string>> vRCBTree;
    if (fRCB)
        vRCBTree = RCBTree(vLeaf);

    if (vTree.empty())
        return "";

    // Format results

    std::stringstream ss;

    ss << "Merkle Tree for block header hashMerkleRoot:\n\n";

    size_t nTreeLevel = vTree.size() - 1;
    for (auto ritx = vTree.rbegin(); ritx != vTree.rend(); ritx++) {
        ss << "Level " << nTreeLevel;

        if (nTreeLevel == vTree.size() - 1)
            ss << " Merkle Root:\n";
        else
        if (nTreeLevel == 0)
            ss << " (TxID):\n";
        else
            ss << " :\n";

        ss << "     ";

        // Add hashes with a ',' between every group of 2
        uint8_t nNode = 0;
        for (const uint256& hash : *ritx) {
            nNode++;

            if (nNode == 2 && hash != ritx->back()) {
                ss << hash.ToString() << ", ";
            } else {
                ss << hash.ToString() << " ";
            }

            if (nNode == 2)
                nNode = 0;
        }

        // Now add the RCB for this level
        if (fRCB && nTreeLevel != vTree.size() - 1) {
            ss << "\nRCB: ";
            for (const std::string& str : vRCBTree[nTreeLevel]) {
                ss << str;
            }
            ss << "\n";
        } else {
            ss << "\n\n";
        }

        nTreeLevel--;
    }
    return ss.str();
}

std::string WitnessTreeString(const std::vector<uint256>& vSegwitLeaf, bool fRCB)
{
    // Create Segwit merkle tree from NO_WITNESS TxIDs
    std::vector<std::vector<uint256>> vSegwitTree = MerkleTree(vSegwitLeaf);

    // Create RCB string tree
    std::vector<std::vector<std::string>> vRCBTree;
    if (fRCB)
        vRCBTree = RCBTree(vSegwitLeaf);

    if (vSegwitTree.empty())
        return "";

    // Format results

    std::stringstream ss;

    ss << "Merkle Tree for Segwit coinbase commitment merkle root hash:\n\n";

    size_t nTreeLevel = vSegwitTree.size() - 1;
    for (auto ritx = vSegwitTree.rbegin(); ritx != vSegwitTree.rend(); ritx++) {
        ss << "Level " << nTreeLevel;

        if (nTreeLevel == vSegwitTree.size() - 1)
            ss << " Segwit Merkle Root:\n";
        else
        if (nTreeLevel == 0)
            ss << " (Segwit TxID):\n";
        else
            ss << " :\n";

        ss << "     ";

        // Add hashes with a ',' between every group of 2
        uint8_t nNode = 0;
        for (const uint256& hash : *ritx) {
            nNode++;

            if (nNode == 2 && hash != ritx->back()) {
                ss << hash.ToString() << ", ";
            } else {
                ss << hash.ToString() << " ";
            }

            if (nNode == 2)
                nNode = 0;
        }

        // Now add the RCB for this level
        if (fRCB && nTreeLevel != vSegwitTree.size() - 1) {
            ss << "\nRCB: ";
            for (const std::string& str : vRCBTree[nTreeLevel]) {
                ss << str;
            }
            ss << "\n";
        } else {
            ss << "\n\n";
        }

        nTreeLevel--;
    }
    return ss.str();
}
