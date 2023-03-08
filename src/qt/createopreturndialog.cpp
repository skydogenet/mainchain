// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/createopreturndialog.h>
#include <qt/forms/ui_createopreturndialog.h>

#include <amount.h>
#include <wallet/wallet.h>
#include <txdb.h>
#include <validation.h>

#include <qt/skydogeunits.h>
#include <qt/platformstyle.h>

#include <QMessageBox>

CreateOPReturnDialog::CreateOPReturnDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CreateOPReturnDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    ui->feeAmount->setValue(0);

    ui->pushButtonCreate->setIcon(platformStyle->SingleColorIcon(":/icons/add"));
}

CreateOPReturnDialog::~CreateOPReturnDialog()
{
    delete ui;
}

void CreateOPReturnDialog::on_pushButtonCreate_clicked()
{
    QMessageBox messageBox;

    const CAmount& nFee = ui->feeAmount->value();
    std::string strText = ui->plainTextEdit->toPlainText().toStdString();

    // Format strings for confirmation dialog
    QString strFee = BitcoinUnits::formatWithUnit(BitcoinUnit::SKYDOGE, nFee, false, BitcoinUnits::separatorAlways);

    // Show confirmation dialog
    int nRes = QMessageBox::question(this, tr("Confirm OP_RETURN transaction"),
        tr("Are you sure you want to spend %1 for this transaction?").arg(strFee),
        QMessageBox::Ok, QMessageBox::Cancel);

    if (nRes == QMessageBox::Cancel)
        return;

#ifdef ENABLE_WALLET
    if (vpwallets.empty()) {
        messageBox.setWindowTitle("Wallet Error!");
        messageBox.setText("No active wallets to create the transaction.");
        messageBox.exec();
        return;
    }

    if (vpwallets[0]->IsLocked()) {
        // Locked wallet message box
        messageBox.setWindowTitle("Wallet locked!");
        messageBox.setText("Wallet must be unlocked to create transactions.");
        messageBox.exec();
        return;
    }

    // Block until the wallet has been updated with the latest chain tip
    vpwallets[0]->BlockUntilSyncedToCurrentChain();

    // Get hex bytes of data
    std::string strHex = HexStr(strText.begin(), strText.end());
    std::vector<unsigned char> vBytes = ParseHex(strHex);

    // Create OP_RETURN script
    CScript script;
    script.resize(vBytes.size() + 1);
    script[0] = OP_RETURN;
    memcpy(&script[1], vBytes.data(), vBytes.size());

    CTransactionRef tx;
    std::string strFail = "";
    if (!vpwallets[0]->CreateOPReturnTransaction(tx, strFail, nFee, script))
    {
        messageBox.setWindowTitle("Creating transaction failed!");
        QString createError = "Error creating transaction!\n\n";
        createError += QString::fromStdString(strFail);
        messageBox.setText(createError);
        messageBox.exec();
        return;
    }

    // Success message box
    messageBox.setWindowTitle("Transaction created!");
    QString result = "txid: " + QString::fromStdString(tx->GetHash().ToString());
    result += "\n";
    messageBox.setText(result);
    messageBox.exec();
#endif
}
