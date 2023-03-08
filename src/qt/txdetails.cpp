// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/txdetails.h>
#include <qt/forms/ui_txdetails.h>

#include <core_io.h>
#include <primitives/transaction.h>

#include <QApplication>
#include <QClipboard>
#include <QMessageBox>

enum TopLevelIndex {
    INDEX_P2SH = 0,
    INDEX_P2WSH,
    INDEX_WITNESS_PROGRAM,
    INDEX_WITNESS_COMMIT,
    INDEX_CRITICAL_HASH,
    INDEX_WITHDRAWAL_HASH,
    INDEX_SC_PROPOSAL,
    INDEX_SC_ACK,
    INDEX_SCDB_UPDATE,
    INDEX_UNKNOWN_OPRETURN,
};

TxDetails::TxDetails(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::TxDetails)
{
    ui->setupUi(this);

    strHex = "";
    strTx = "";
}

TxDetails::~TxDetails()
{
    delete ui;
}

void  TxDetails::SetTransaction(const CMutableTransaction& mtx)
{
    CTransaction tx = CTransaction(mtx);

    // Get & set the hex
    strHex = EncodeHexTx(mtx);

    // Get & set the JSON
    strTx = tx.ToString();

    // Display
    ui->textBrowserTx->setText(QString::fromStdString(strTx));
    ui->textBrowserHex->setText(QString::fromStdString(strHex));

    ui->labelHash->setText(QString::fromStdString(tx.GetHash().ToString()));
    ui->labelNumIn->setText(QString::number(mtx.vin.size()));
    ui->labelNumOut->setText(QString::number(mtx.vout.size()));
    ui->labelLockTime->setText(QString::number(mtx.nLockTime));
    ui->labelValueOut->setText(QString::number(tx.GetValueOut()));

    bool fBMMRequest = tx.criticalData.IsBMMRequest();

    // Set note
    if (tx.IsCoinBase()) {
        ui->labelNote->setText("This is a coinbase transaction.");
    }
    else
    if (!tx.criticalData.IsNull()) {
        if (fBMMRequest) {
            ui->labelNote->setText("This is a BMM request.");
        } else {
            ui->labelNote->setText("This is a critical data request.");
        }
    }

    // TODO more things to display?
    // - sig op count
    // - script to asm str
    // - size in bytes

    // Look for outputs that we recognize the type of or can decode

    // Cache of values decoded from outputs
    // Witness program
    int nWitVersion = -1;
    std::vector<unsigned char> vWitProgram;
    // Withdrawal hash commit
    uint256 hashWithdrawal = uint256();
    uint8_t nSidechain = 0;
    // Sidechain activation commit
    uint256 hashSidechain = uint256();
    // Critical hash commit
    uint256 hashCritical = uint256();
    // Critical data bytes
    std::vector<unsigned char> vBytes;

    ui->treeWidgetDecoded->clear();
    // TODO A lot of these output types can only be in the coinbase so we
    // shouldn't check for them in other transactions.
    for (size_t i = 0; i < tx.vout.size(); i++) {
        // TODO move these

        nWitVersion = -1;
        vWitProgram.clear();

        hashWithdrawal.SetNull();

        nSidechain = 0;
        hashSidechain.SetNull();

        hashCritical.SetNull();

        const CScript scriptPubKey = tx.vout[i].scriptPubKey;
        if (scriptPubKey.empty())
            continue;

        if (scriptPubKey.IsPayToScriptHash()) {
            // Create a p2sh item
            QTreeWidgetItem *subItem = new QTreeWidgetItem();
            subItem->setText(0, "txout #" + QString::number(i));
            subItem->setText(1, "P2SH: " +
                        QString::fromStdString(ScriptToAsmStr(scriptPubKey)));
            AddTreeItem(INDEX_P2SH, subItem);
        }
        else
        if (scriptPubKey.IsPayToWitnessScriptHash()) {
            // Create a p2wsh item
            QTreeWidgetItem *subItem = new QTreeWidgetItem();
            subItem->setText(0, "txout #" + QString::number(i));
            subItem->setText(1, "P2WSH: " +
                        QString::fromStdString(ScriptToAsmStr(scriptPubKey)));
            AddTreeItem(INDEX_P2WSH, subItem);
        }
        else
        if (scriptPubKey.IsWitnessProgram(nWitVersion, vWitProgram)) {
            // Create a witness program item
            QTreeWidgetItem *subItem = new QTreeWidgetItem();
            subItem->setText(0, "txout #" + QString::number(i));
            subItem->setText(1, "Witness Program: " +
                        QString::fromStdString(ScriptToAsmStr(scriptPubKey)));
            AddTreeItem(INDEX_WITNESS_PROGRAM, subItem);
        }
        else
        if (scriptPubKey.IsCriticalHashCommit(hashCritical, vBytes)) {
            // Create a critical hash commit item
            QTreeWidgetItem *subItem = new QTreeWidgetItem();
            subItem->setText(0, "txout #" + QString::number(i));
            // TODO detect if this is a BMM commit or any other critical hash
            // commit. Nobody is using it for anything else right now though.
            subItem->setText(1, "BMM h* Commit: " +
                    QString::fromStdString(hashCritical.ToString()));
            AddTreeItem(INDEX_CRITICAL_HASH, subItem);
        }
        else
        if (scriptPubKey.IsWithdrawalHashCommit(hashWithdrawal, nSidechain)) {
            // Create a Withdrawal hash commit item
            QTreeWidgetItem *subItem = new QTreeWidgetItem();
            subItem->setText(0, "txout #" + QString::number(i));
            subItem->setText(1, "New Withdrawal Hash Commit for SC# " + QString::number(nSidechain)
                    + " : " + QString::fromStdString(hashWithdrawal.ToString()));
            AddTreeItem(INDEX_WITHDRAWAL_HASH, subItem);
        }
        else
        if (scriptPubKey.IsSidechainProposalCommit()) {

            // Create a sc proposal commit item
            QTreeWidgetItem *subItem = new QTreeWidgetItem();
            subItem->setText(0, "txout #" + QString::number(i));
            subItem->setText(1, "Sidechain Proposal");
            AddTreeItem(INDEX_SC_PROPOSAL, subItem);
        }
        else
        if (scriptPubKey.IsSidechainActivationCommit(hashSidechain)) {

            // Create a sc activation commit item
            QTreeWidgetItem *subItem = new QTreeWidgetItem();
            subItem->setText(0, "txout #" + QString::number(i));
            subItem->setText(1, "Sidechain Activation Commit: " +
                    QString::fromStdString(hashSidechain.ToString()));
            AddTreeItem(INDEX_SC_ACK, subItem);
        }
        else
        if (scriptPubKey.IsSCDBBytes()) {
            // Create a SCDB update script item
            QTreeWidgetItem *subItem = new QTreeWidgetItem();
            subItem->setText(0, "txout #" + QString::number(i));
            subItem->setText(1, "SCDB Update Script: " +
                        QString::fromStdString(ScriptToAsmStr(scriptPubKey)));
            AddTreeItem(INDEX_SCDB_UPDATE, subItem);
        }
        else
        if (scriptPubKey.front() == OP_RETURN && scriptPubKey.size() == 38) {
            // Check for witness commitment. There is no IsWitnessCommit script
            // function so we have to check ourselves here:
            if (scriptPubKey[1] == 0x24 &&
                    scriptPubKey[2] == 0xaa &&
                    scriptPubKey[3] == 0x21 &&
                    scriptPubKey[4] == 0xa9 &&
                    scriptPubKey[5] == 0xed) {

                // Create a witness commit item
                QTreeWidgetItem *subItem = new QTreeWidgetItem();
                subItem->setText(0, "txout #" + QString::number(i));
                subItem->setText(1, "Witness Commitment: " +
                        QString::fromStdString(ScriptToAsmStr(scriptPubKey)));
                AddTreeItem(INDEX_WITNESS_COMMIT, subItem);
            }
        }
    }
    ui->treeWidgetDecoded->expandAll();
    ui->treeWidgetDecoded->resizeColumnToContents(0);
    ui->treeWidgetDecoded->resizeColumnToContents(1);
}

void TxDetails::AddTreeItem(int index, QTreeWidgetItem *item)
{
    if (!item)
        return;

    if (index < 0 || index > INDEX_UNKNOWN_OPRETURN)
        return;

    QTreeWidgetItem *topItem = ui->treeWidgetDecoded->topLevelItem(index);
    if (!topItem) {
        topItem = new QTreeWidgetItem(ui->treeWidgetDecoded);
        if (index == INDEX_P2SH)
            topItem->setText(0, "P2SH");
        else
        if (index == INDEX_P2WSH)
            topItem->setText(0, "P2WSH");
        else
        if (index == INDEX_WITNESS_PROGRAM)
            topItem->setText(0, "Witness Program");
        else
        if (index == INDEX_WITNESS_COMMIT)
            topItem->setText(0, "Witness Commit");
        else
        if (index == INDEX_CRITICAL_HASH)
            topItem->setText(0, "BMM / Critical Hash");
        else
        if (index == INDEX_WITHDRAWAL_HASH)
            topItem->setText(0, "New Withdrawal Hash");
        else
        if (index == INDEX_SC_PROPOSAL)
            topItem->setText(0, "Sidechain Proposal");
        else
        if (index == INDEX_SC_ACK)
            topItem->setText(0, "Sidechain Activation Commit");
        else
        if (index == INDEX_SCDB_UPDATE)
            topItem->setText(0, "SCDB Update Script");
        else
        if (index == INDEX_UNKNOWN_OPRETURN)
            topItem->setText(0, "Unknown OP_RETURN");

        ui->treeWidgetDecoded->insertTopLevelItem(index, topItem);
    }

    if (!topItem)
        return;

    topItem->addChild(item);
}
