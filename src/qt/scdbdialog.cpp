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
    // All three helpers read the global scdb, which ConnectBlock move-assigns
    // under cs_main, so the lock belongs here rather than at each call site -
    // numBlocksChanged() already held it, but ShowSCDBDialog() did not, which
    // left the same reads guarded on one path and unguarded on the other.
    //
    // Non-blocking on purpose: these run on the GUI thread and rebuild whole
    // tree widgets, so waiting on a contended cs_main would freeze the
    // interface for as long as a block takes to connect. On a miss the dialog
    // keeps its current contents and numBlocksChanged() refreshes it on the
    // next block. cs_main is recursive, so this still succeeds immediately on
    // the numBlocksChanged() path, which already holds it.
    TRY_LOCK(cs_main, lockMain);
    if (!lockMain)
        return;

    UpdateVoteTree();
    UpdateSCDBText();
    UpdateHistoryTree();
}

void SCDBDialog::UpdateVoteTree()
{
    // Caller must hold cs_main - reads the global scdb, which ConnectBlock
    // move-assigns. Reached only through UpdateOnShow(), which takes it.
    AssertLockHeld(cs_main);

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
        // The slot number, not the position in the active list. The withdrawal
        // rows below and the vote lookup above both use nSidechain, so writing
        // the index here sent the operator's Abstain and Alarm choices to
        // whichever slot happened to sit at that position - silently, with the
        // checkbox reverting on the next block and the real slot still
        // abstaining.
        subItemAbstain->setData(0, NumRole, QString::number(vSidechain[x].nSidechain));
        subItemAbstain->setData(0, HashRole, "");
        topItem->addChild(subItemAbstain);

        // Add alaram checkbox for sidechain
        QTreeWidgetItem *subItemAlarm = new QTreeWidgetItem();
        subItemAlarm->setText(0, "Alarm");
        subItemAlarm->setCheckState(0, Qt::Unchecked);
        subItemAlarm->setData(0, NumRole, QString::number(vSidechain[x].nSidechain));
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
    // Caller must hold cs_main - reads the global scdb. Two call sites:
    // UpdateOnShow() (TRY_LOCK) and on_treeWidgetVote_itemChanged() (LOCK).
    AssertLockHeld(cs_main);

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
    // Caller must hold cs_main. This one reads no scdb state, but it walks
    // chainActive and dereferences the CBlockIndex it returns, which a reorg
    // can invalidate under it - the same contract for a different reason.
    // Reached only through UpdateOnShow(), which takes the lock.
    AssertLockHeld(cs_main);

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
                uint32_t nPrevScore = 0;   // tracks nWorkScore
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
    if (!this->isVisible())
        return;

    // Skip refresh if cs_main is contended during sync; the next block signal will retry when it's free
    TRY_LOCK(cs_main, lockMain);
    if (!lockMain)
        return;

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

    // Update users custom vote settings.
    //
    // Block connection copies the SCDB, mutates the copy and publishes it back
    // wholesale, so this read-modify-write needs cs_main or the vote can be
    // silently reverted moments after it is set.
    LOCK(cs_main);

    std::vector<std::string> vVote = scdb.GetVotes();

    unsigned int nSidechain = item->data(0, NumRole).toUInt();
    // Slots are numbered 0..SIDECHAIN_ACTIVATION_MAX_ACTIVE-1; ">" would let the
    // count itself through and index one past the end of the vote vector.
    if (nSidechain >= SIDECHAIN_ACTIVATION_MAX_ACTIVE || nSidechain >= vVote.size())
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
