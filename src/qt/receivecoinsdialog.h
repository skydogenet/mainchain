// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_RECEIVECOINSDIALOG_H
#define BITCOIN_QT_RECEIVECOINSDIALOG_H

#include <qt/guiutil.h>

class PaymentRequestDialog;
class PlatformStyle;
class WalletModel;

namespace Ui {
    class ReceiveCoinsDialog;
}

/** Dialog for requesting payment of bitcoins */
class ReceiveCoinsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit ReceiveCoinsDialog(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~ReceiveCoinsDialog();

    void setModel(WalletModel *model);

private:
    Ui::ReceiveCoinsDialog *ui;
    WalletModel *model;
    const PlatformStyle *platformStyle;

    PaymentRequestDialog* requestDialog = nullptr;

    void generateQR(std::string data);
    void generateAddress();

private Q_SLOTS:

    void on_pushButtonCopy_clicked();
    void on_pushButtonNew_clicked();
    void on_pushButtonPaymentRequest_clicked();
};

#endif // BITCOIN_QT_RECEIVECOINSDIALOG_H
