// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PAPERWALLETDIALOG_H
#define PAPERWALLETDIALOG_H

#include <QDialog>

class PlatformStyle;

namespace Ui {
class PaperWalletDialog;
}

class PaperWalletDialog : public QDialog
{
    Q_OBJECT

public:
    explicit PaperWalletDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~PaperWalletDialog();

private:
    Ui::PaperWalletDialog *ui;

    const PlatformStyle *platformStyle;
};

#endif // PAPERWALLETDIALOG_H
