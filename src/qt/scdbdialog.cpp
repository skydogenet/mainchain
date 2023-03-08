// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/scdbdialog.h>
#include <qt/forms/ui_scdbdialog.h>

#include <qt/clientmodel.h>
#include <qt/platformstyle.h>

#include <chain.h>
#include <chainparams.h>
#include <sidechain.h>
#include <sidechaindb.h>
#include <txdb.h>
#include <validation.h>

SCDBDialog::SCDBDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SCDBDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);
}

SCDBDialog::~SCDBDialog()
{
    delete ui;
}

void SCDBDialog::UpdateOnShow()
{
    UpdateVoteTree();
    UpdateSCDBText();
    UpdateHistoryTree();
}

void SCDBDialog::UpdateVoteTree()
{
    // Update vote tree

    ui->treeWidgetVote->setUpdatesEnabled(false);
    ui->treeWidgetVote->clear();

    int index = 0;
    std::vector<Sidechain> vSidechain = scdb.GetActiveSidechains();
    std::vector<std::string> vVote = scdb.GetVotes();
    for (size_t x = 0; x < vSidechain.size(); x++) {
        std::vector<SidechainWithdrawalState> vWithdrawal;
        vWithdrawal = scdb.GetState(vSidechain[x].nSidechain);

        QTreeWidgetItem *topItem = new QTreeWidgetItem();
        topItem->setText(0, "SC #" + QString::number(vSidechain[x].nSidechain) + " " + QString::fromStdString(vSidechain[x].title));
        ui->treeWidgetVote->insertTopLevelItem(x, topItem);

        if (!vWithdrawal.size()) {
            index++;
            continue;
        }

        // Add abstain checkbox for sidechain
        QTreeWidgetItem *subItemAbstain = new QTreeWidgetItem();
        subItemAbstain->setText(0, "Abstain");
        subItemAbstain->setCheckState(0, Qt::Unchecked);
        subItemAbstain->setData(0, NumRole, QString::number(x));
        subItemAbstain->setData(0, HashRole, "");
        topItem->addChild(subItemAbstain);

        // Add alaram checkbox for sidechain
        QTreeWidgetItem *subItemAlarm = new QTreeWidgetItem();
        subItemAlarm->setText(0, "Alarm");
        subItemAlarm->setCheckState(0, Qt::Unchecked);
        subItemAlarm->setData(0, NumRole, QString::number(x));
        subItemAlarm->setData(0, HashRole, "");
        topItem->addChild(subItemAlarm);

        // Add upvote checkbox for each sidechain withdrawal
        bool fUpvoteFound = false;
        for (size_t y = 0; y < vWithdrawal.size(); y++) {
            bool fUpvote = false;

            // Check if this withdrawal's upvote box should be checked
            if (vVote[vSidechain[x].nSidechain] == vWithdrawal[y].hash.ToString()) {
                fUpvote = true;
                fUpvoteFound = true;
            }

            QTreeWidgetItem *subItemWT = new QTreeWidgetItem();
            subItemWT->setText(0, QString::fromStdString(vWithdrawal[y].hash.ToString()));
            subItemWT->setCheckState(0, fUpvote ? Qt::Checked : Qt::Unchecked);
            subItemWT->setData(0, NumRole, vWithdrawal[y].nSidechain);
            subItemWT->setData(0, HashRole, QString::fromStdString(vWithdrawal[y].hash.ToString()));

            QTreeWidgetItem *subItemBlocks = new QTreeWidgetItem();
            subItemBlocks->setText(0, "Blocks left: " + QString::number(vWithdrawal[y].nBlocksLeft));
            subItemWT->addChild(subItemBlocks);

            QTreeWidgetItem *subItemScore = new QTreeWidgetItem();
            subItemScore->setText(0, "Work score: " + QString::number(vWithdrawal[y].nWorkScore));
            subItemWT->addChild(subItemScore);

            topItem->addChild(subItemWT);
        }

        // Check abstain or alarm for this sidechain if no upvote was found
        if (!fUpvoteFound && vVote[vSidechain[x].nSidechain].front() == SCDB_DOWNVOTE)
            subItemAlarm->setCheckState(0, Qt::Checked);
        else
        if (!fUpvoteFound)
            subItemAbstain->setCheckState(0, Qt::Checked);

        index++;
    }
    ui->treeWidgetVote->collapseAll();
    ui->treeWidgetVote->expandToDepth(0);
    ui->treeWidgetVote->setColumnWidth(0, 600);
    ui->treeWidgetVote->setUpdatesEnabled(true);
}

void SCDBDialog::UpdateSCDBText()
{
    ui->textBrowserSCDB->clear();
    std::vector<std::string> vVote = scdb.GetVotes();

    ui->textBrowserSCDB->insertPlainText("SCDB update bytes / M4 for vote settings:\n");

    if (!scdb.HasState()) {
        ui->textBrowserSCDB->insertPlainText("Not required.\n\n");
        return;
    }

    // Generate & display update bytes / M4

    CBlock block;
    CMutableTransaction mtx;
    mtx.vin.resize(1);
    mtx.vin[0].prevout.SetNull();
    block.vtx.push_back(MakeTransactionRef(std::move(mtx)));

    std::vector<std::vector<SidechainWithdrawalState>> vOldScores;
    for (const Sidechain& s : scdb.GetActiveSidechains()) {
        std::vector<SidechainWithdrawalState> vWithdrawal;
        vWithdrawal = scdb.GetState(s.nSidechain);
        if (vWithdrawal.size())
            vOldScores.push_back(vWithdrawal);
    }

    CScript script;
    if (!GenerateSCDBByteCommitment(block, script, vOldScores, vVote)) {
        ui->textBrowserSCDB->insertPlainText("Failed to generate SCDB Bytes!\n\n");
        return;
    }

    // Display hex string of update bytes
    std::string str = HexStr(script.begin() + 6, script.end());
    ui->textBrowserSCDB->insertPlainText(QString::fromStdString(str) + "\n\n");

    // Display interpretation of update bytes
    CScript bytes = CScript(script.begin() + 6, script.end());
    size_t nScoreIndex = 0;
    for (size_t i = 0; i < bytes.size(); i += 2) {
        if (nScoreIndex >= vOldScores.size())
            return;

        // Copy sidechain number from first withdrawal at score index
        size_t nSidechain = vOldScores[nScoreIndex][0].nSidechain;

        std::string strBytes = HexStr(bytes.begin() + i, bytes.begin() + i + 2);
        std::string strVote = "Sidechain #" + std::to_string(nSidechain) + "\n";

        if (bytes[i] == 0xFF && bytes[i + 1] == 0xFF) {
            strVote += "Abstain from all withdrawals\n";
        }
        else
        if (bytes[i] == 0xFF && bytes[i + 1] == 0xFE) {
            strVote += "Downvote all withdrawals\n";
        }
        else {
            // Upvote index
            uint16_t n = bytes[i] | bytes[i + 1] << 8;

            if (n >= vOldScores[nScoreIndex].size())
                return;

            strVote += "Upvote withdrawal #" + std::to_string(n) + ": " + vOldScores[nScoreIndex][n].hash.ToString() + "\n";
        }

        ui->textBrowserSCDB->insertPlainText(QString::fromStdString(strBytes + "\n"));
        ui->textBrowserSCDB->insertPlainText(QString::fromStdString(strVote + "\n"));

        nScoreIndex++;
    }
}

void SCDBDialog::UpdateHistoryTree()
{
    // Update history tree

    ui->treeWidgetHistory->setUpdatesEnabled(false);
    ui->treeWidgetHistory->clear();

    int nHeight = chainActive.Height();
    int nBlocksToDisplay = 6;
    if (nHeight < nBlocksToDisplay)
        nBlocksToDisplay = nHeight;

    for (int i = 0; i < nBlocksToDisplay; i++) {
        CBlockIndex *pindex = chainActive[nHeight - i];

        if (pindex->GetBlockHash() == Params().GetConsensus().hashGenesisBlock) {
            QTreeWidgetItem *subItem = new QTreeWidgetItem();
            subItem->setText(0, "Genesis block has no score data");
            AddHistoryTreeItem(i, nHeight - i, subItem);
            continue;
        }

        SidechainBlockData data;
        if (!psidechaintree->GetBlockData(pindex->GetBlockHash(), data)) {
            QTreeWidgetItem *subItem = new QTreeWidgetItem();
            subItem->setText(0, "No score data for this block");
            AddHistoryTreeItem(i, nHeight - i, subItem);
            continue;
        }

        // Loop through state here and add sub items for sc# & score change
        int nSidechain = 0;
        for (const std::vector<SidechainWithdrawalState>& vScore : data.vWithdrawalStatus) {
            if (vScore.empty()) {
                nSidechain++;
                continue;
            }

            // Create sidechain item
            QTreeWidgetItem *subItemSC = new QTreeWidgetItem();

            // Load prev block data to check old score
            SidechainBlockData prevData;
            if (pindex->pprev)
                psidechaintree->GetBlockData(pindex->pprev->GetBlockHash(), prevData);

            // Create sidechain children items
            for (const SidechainWithdrawalState& s : vScore) {
                // Look up old work score
                uint16_t nPrevScore = 0;
                if (prevData.vWithdrawalStatus.size() > s.nSidechain) {
                    for (const SidechainWithdrawalState& prevState : prevData.vWithdrawalStatus[s.nSidechain]) {
                        if (prevState.hash == s.hash)
                            nPrevScore = prevState.nWorkScore;
                    }
                }

                QTreeWidgetItem *subItemScore = new QTreeWidgetItem();
                QString strScore = " (Abstain)";
                if (nPrevScore < s.nWorkScore)
                    strScore = " (Upvote / ACK)";
                else
                if (nPrevScore > s.nWorkScore)
                    strScore = " (Downvote / NACK)";

                subItemScore->setText(0, "Work score: " + QString::number(nPrevScore) + " -> " + QString::number(s.nWorkScore) + strScore);
                subItemSC->addChild(subItemScore);

                QTreeWidgetItem *subItemBlocks = new QTreeWidgetItem();
                subItemBlocks->setText(0, "Blocks remaining: " + QString::number(s.nBlocksLeft + 1) + " -> " + QString::number(s.nBlocksLeft));
                subItemSC->addChild(subItemBlocks);

                QTreeWidgetItem *subItemHash = new QTreeWidgetItem();
                subItemHash->setText(0, "Withdrawal bundle hash:\n" + QString::fromStdString(s.hash.ToString()));
                subItemSC->addChild(subItemHash);
            }

            // Add SC item parent to tree
            subItemSC->setText(0, "Sidechain #" + QString::number(nSidechain) + " scores");
            AddHistoryTreeItem(i, nHeight - i, subItemSC);

            nSidechain++;
        }
    }

    ui->treeWidgetHistory->collapseAll();
    ui->treeWidgetHistory->resizeColumnToContents(0);
    ui->treeWidgetHistory->setUpdatesEnabled(true);
}

void SCDBDialog::AddHistoryTreeItem(int index, const int nHeight, QTreeWidgetItem *item)
{
    if (!item || index < 0)
        return;

    QTreeWidgetItem *topItem = ui->treeWidgetHistory->topLevelItem(index);
    if (!topItem) {
        topItem = new QTreeWidgetItem(ui->treeWidgetHistory);
        topItem->setText(0, "Block #" + QString::number(nHeight));
        ui->treeWidgetHistory->insertTopLevelItem(index, topItem);
    }

    if (!topItem)
        return;

    topItem->addChild(item);
}

void SCDBDialog::numBlocksChanged()
{
    if (this->isVisible())
        UpdateOnShow();
}

void SCDBDialog::on_treeWidgetVote_itemChanged(QTreeWidgetItem *item, int column)
{
    QTreeWidgetItem* parent = item->parent();
    if (!parent)
        return;

    ui->treeWidgetVote->setUpdatesEnabled(false);

    bool fChecked = (item->checkState(0) == Qt::Checked);
    int nChildren = parent->childCount();

    if (nChildren < 2)
        return;

    if (fChecked) {
        // Uncheck other boxes when a new one is checked
        for (int i = 0; i < nChildren; i++) {
            QTreeWidgetItem *child = parent->child(i);
            if (fChecked && child != item)
                child->setCheckState(0, Qt::Unchecked);
        }
    } else {
        bool fCheckFound = false;
        for (int i = 0; i < nChildren; i++) {
            QTreeWidgetItem *child = parent->child(i);
            if (child->checkState(0) == Qt::Checked) {
                fCheckFound = true;
                break;
            }
        }

        // Switch back to abstain if nothing is checked
        if (!fCheckFound)
            parent->child(0)->setCheckState(0, Qt::Checked);
    }

    // Update users custom vote settings
    std::vector<std::string> vVote = scdb.GetVotes();

    unsigned int nSidechain = item->data(0, NumRole).toUInt();
    if (nSidechain > SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        return;

    if (parent->child(0)->checkState(0) == Qt::Checked) {
        vVote[nSidechain] = SCDB_ABSTAIN;
    }
    else
    if (parent->child(1)->checkState(0) == Qt::Checked) {
        vVote[nSidechain] = SCDB_DOWNVOTE;
    }
    else
    {
        vVote[nSidechain] = item->data(0, HashRole).toString().toStdString();
    }

    scdb.CacheCustomVotes(vVote);

    ui->treeWidgetVote->setUpdatesEnabled(true);

    UpdateSCDBText();
}

void SCDBDialog::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        connect(model, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)),
                this, SLOT(numBlocksChanged()));
    }
}
