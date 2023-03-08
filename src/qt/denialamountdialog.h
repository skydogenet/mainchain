// Copyright (c) 2022- The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DENIALAMOUNTDIALOG_H
#define DENIALAMOUNTDIALOG_H

#include <QDialog>

#include <amount.h>

namespace Ui {
class DenialAmountDialog;
}

class DenialAmountDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DenialAmountDialog(QWidget *parent = nullptr);
    ~DenialAmountDialog();

    CAmount GetAmount();

private Q_SLOTS:
    void on_pushButtonCreate_clicked();

private:
    Ui::DenialAmountDialog *ui;

    bool ValidateAmount();

    CAmount amount;
};

#endif // DENIALAMOUNTDIALOG_H
