// Copyright (c) 2020-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MININGDIALOG_H
#define MININGDIALOG_H

#include <QDialog>

class PlatformStyle;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

namespace Ui {
class MiningDialog;
}

class MiningDialog : public QDialog
{
    Q_OBJECT

public:
    explicit MiningDialog(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~MiningDialog();

public Q_SLOTS:
    void on_pushButtonStartMining_clicked();
    void on_pushButtonStopMining_clicked();
    void on_pushButtonAddRemove_clicked();
    void on_pushButtonWithdrawalVote_clicked();
    void on_checkBoxAbandonFailedBMM_toggled(bool fChecked);

private Q_SLOTS:
    void Update();
    void UpdateMiningOutput();
    void AbandonFailedBMM();

Q_SIGNALS:
    void ActivationDialogRequested();
    void WithdrawalDialogRequested();

private:
    Ui::MiningDialog *ui;

    QTimer* pollTimer;
    QTimer* miningOutputTimer;
    QTimer* abandonBMMTimer;

    const PlatformStyle *platformStyle;
};

#endif // MININGDIALOG_H
