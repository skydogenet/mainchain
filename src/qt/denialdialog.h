// Copyright (c) 2022- The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DENIALDIALOG_H
#define DENIALDIALOG_H

#include <QDialog>

#include <amount.h>
#include <uint256.h>

#include <set>
#include <vector>

class ClientModel;
class COutput;
class CTransaction;
class CWalletTx;
class PlatformStyle;
class ScheduledTransactionTableModel;

struct ScheduledTransaction;

QT_BEGIN_NAMESPACE
class QMenu;
class QPushButton;
class QTimer;
QT_END_NAMESPACE

enum DenialRoles
{
    UserRole = Qt::UserRole,
    TXIDRole,
    iRole
};

namespace Ui {
class DenialDialog;
}

class DenialDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DenialDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~DenialDialog();

    void setClientModel(ClientModel *model);
    void UpdateOnShow();

private Q_SLOTS:
    void on_pushButtonDenyAll_clicked();
    void on_pushButtonCreateAmount_clicked();
    void on_pushButtonSweep_clicked();
    void on_pushButtonMore_clicked();
    void on_checkBoxAll_toggled(bool fChecked);
    void updateCoins();
    void on_tableWidgetCoins_doubleClicked(const QModelIndex& i);
    void broadcastScheduledTransactions();
    void contextualMenu(const QPoint &);
    void on_denyAction_clicked();
    void automaticDenial();
    void animateAutomationIcon();

private:
    Ui::DenialDialog *ui;

    std::vector<COutput> vCoin;

    ClientModel *clientModel = nullptr;

    const PlatformStyle *platformStyle = nullptr;

    QMenu *contextMenu = nullptr;

    QTimer *scheduledTxTimer = nullptr;
    QTimer *automaticTimer = nullptr;
    QTimer *automaticAnimationTimer = nullptr;

    uint8_t nAnimation;

    bool fMoreShown;

    unsigned int nAutoMinutes;
    unsigned int nDenialGoal;

    ScheduledTransactionTableModel *scheduledModel;

    void SortByDenial(std::vector<COutput>& vCoin);
    void Deny(const QModelIndex& index);

    bool fCheckAll;

Q_SIGNALS:
    void requestedSendAllCoins();
};

#endif // DENIALDIALOG_H
