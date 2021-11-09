// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SIDECHAINWITHDRAWALDIALOG_H
#define SIDECHAINWITHDRAWALDIALOG_H

#include <QDialog>

class PlatformStyle;
class SidechainWithdrawalVoteTableModel;

namespace Ui {
class SidechainWithdrawalDialog;
}

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

class SidechainWithdrawalDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SidechainWithdrawalDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~SidechainWithdrawalDialog();

public Q_SLOTS:
    void on_pushButtonUpvote_clicked();

    void on_pushButtonDownvote_clicked();

    void on_pushButtonAbstain_clicked();

    void on_pushButtonHelp_clicked();

    void on_comboBoxDefaultVote_currentIndexChanged(const int i);

    void Update();

private:
    Ui::SidechainWithdrawalDialog *ui;

    SidechainWithdrawalVoteTableModel *withdrawalVoteModel = nullptr;

    const PlatformStyle *platformStyle;

    QTimer *pollTimer;

};

#endif // SIDECHAINWITHDRAWALDIALOG_H
