// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/coinsplitconfirmationdialog.h>
#include <qt/forms/ui_coinsplitconfirmationdialog.h>

#include <QMessageBox>

#include <qt/skydogeunits.h>

#include <base58.h>
#include <consensus/validation.h>
#include <net.h>
#include <primitives/transaction.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>
#include <utilmoneystr.h>
#include <validation.h>

CoinSplitConfirmationDialog::CoinSplitConfirmationDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CoinSplitConfirmationDialog)
{
    ui->setupUi(this);

    Reset();
}

CoinSplitConfirmationDialog::~CoinSplitConfirmationDialog()
{
    delete ui;
}

void CoinSplitConfirmationDialog::SetInfo(const CAmount& amountIn, QString txidIn, QString addressIn, int indexIn)
{
    // Get a new key to move funds to
    {
#ifdef ENABLE_WALLET
    QMessageBox messageBox;
    if (vpwallets.empty()) {
        messageBox.setWindowTitle("Wallet Error!");
        messageBox.setText("Active wallet required to split coins.");
        messageBox.exec();
        return;
    }

    if (vpwallets[0]->IsLocked()) {
        // Locked wallet message box
        messageBox.setWindowTitle("Wallet locked!");
        messageBox.setText("Wallet must be unlocked to split coins.");
        messageBox.exec();
        return;
    }

    // Get new address
    if (vpwallets.empty())
        return;

    LOCK2(cs_main, vpwallets[0]->cs_wallet);
    vpwallets[0]->TopUpKeyPool();

    CPubKey newKey;
    if (vpwallets[0]->GetKeyFromPool(newKey)) {
        CKeyID keyID = newKey.GetID();

        CTxDestination address(keyID);
        strNewAddress = EncodeDestination(address);

        ui->labelNewAddress->setText(QString::fromStdString(strNewAddress));
    }
#endif
    }

    amount = amountIn;
    txid = uint256S(txidIn.toStdString());
    index = indexIn;

    ui->labelTXID->setText(txidIn);

    QString strAmount = BitcoinUnits::formatWithUnit(BitcoinUnit::SKYDOGE, amountIn, false, BitcoinUnits::separatorAlways);

    ui->labelAmount->setText(strAmount);
    ui->labelAddress->setText(addressIn);
    ui->labelIndex->setText(QString::number(indexIn));
}

void CoinSplitConfirmationDialog::on_buttonBox_accepted()
{
    QMessageBox messageBox;
    messageBox.setWindowTitle("Coin split error!");

    CTxDestination dest = DecodeDestination(strNewAddress);

    if (!IsValidDestination(dest)) {
        messageBox.setText("Invalid destination for split coins!");
        messageBox.exec();
        return;
    }

    // Try to split the coins
#ifdef ENABLE_WALLET
    LOCK2(cs_main, vpwallets[0]->cs_wallet);

    CWalletTx wtx;

    CReserveKey reservekey(vpwallets[0]);
    CAmount nFeeRequired;
    int nChangePosRet = -1;
    std::string strError = "";
    CCoinControl cc;
    cc.Select(COutPoint(txid, index));
    std::vector<CRecipient> vecSend;
    CRecipient recipient = {GetScriptForDestination(dest), amount, true};
    vecSend.push_back(recipient);
    if (!vpwallets[0]->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError, cc, true, TX_REPLAY_VERSION)) {
        QString message = "Failed to create coin split transaction!\n";
        message += "Error: ";
        message += QString::fromStdString(strError);
        message += "\n";
        messageBox.setText(message);
        messageBox.exec();
        return;
    }

    CValidationState state;
    if (!vpwallets[0]->CommitTransaction(wtx, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", state.GetRejectReason());

        QString message = "Failed to commit coin split transaction!\n";
        message += QString::fromStdString(strError);
        message += "\n";
        messageBox.setText(message);
        messageBox.exec();
        return;
    }

#endif

    messageBox.setWindowTitle("Coin split successfully!");
    QString message = "Your coin has been split and replay protected.\n";
    message += "txid: ";
    message += QString::fromStdString(wtx.GetHash().ToString());
    message += "\n";
    messageBox.setText(message);
    messageBox.exec();

    fConfirmed = true;

    this->close();
}

void CoinSplitConfirmationDialog::on_buttonBox_rejected()
{
    this->close();
}

bool CoinSplitConfirmationDialog::GetConfirmed()
{
    // Return the confirmation status and reset dialog
    if (fConfirmed) {
        Reset();
        return true;
    } else {
        Reset();
        return false;
    }
}

void CoinSplitConfirmationDialog::Reset()
{
    // Reset the dialog's confirmation status
    fConfirmed = false;
}
