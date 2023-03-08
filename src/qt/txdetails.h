// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TXDETAILS_H
#define BITCOIN_TXDETAILS_H

#include <QDialog>

#include <string>

class CMutableTransaction;

QT_BEGIN_NAMESPACE
class QTreeWidgetItem;
QT_END_NAMESPACE

namespace Ui {
class TxDetails;
}

class TxDetails : public QDialog
{
    Q_OBJECT

public:
    explicit TxDetails(QWidget *parent = 0);
    ~TxDetails();

    void SetTransaction(const CMutableTransaction& mtx);

private:
    Ui::TxDetails *ui;
    std::string strHex;
    std::string strTx;

    void AddTreeItem(int index, QTreeWidgetItem *item);
};

#endif // BITCOIN_TXDETAILS_H
