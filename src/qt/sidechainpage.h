// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SIDECHAINPAGE_H
#define SIDECHAINPAGE_H

#include <QString>
#include <QWidget>

#include <amount.h>
#include <sidechain.h>
#include <uint256.h>

#include <string>

class CBlock;
class PlatformStyle;
class SidechainDepositConfirmationDialog;
class SidechainWithdrawalTableModel;
class SidechainActivationDialog;
class SCDBDialog;
class WalletModel;
class ClientModel;

QT_BEGIN_NAMESPACE
class QTimer;
class QListWidgetItem;
QT_END_NAMESPACE

namespace Ui {
class SidechainPage;
}

// Recent deposit table columns
enum
{
    COLUMN_SIDECHAIN = 0,
    COLUMN_AMOUNT,
    COLUMN_CONFIRMATIONS,
    COLUMN_STATUS,
};

struct RecentDepositTableObject
{
    unsigned int nSidechain;
    CAmount amount;
    uint256 txid;
};

class SidechainPage : public QWidget
{
    Q_OBJECT

public:
    explicit SidechainPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~SidechainPage();

    void setClientModel(ClientModel *model);
    void setWalletModel(WalletModel *model);
    void setWithdrawalModel(SidechainWithdrawalTableModel *model);

public Q_SLOTS:
    void setBalance(const CAmount& balance, const CAmount& unconfirmedBalance,
                    const CAmount& immatureBalance, const CAmount& watchOnlyBalance,
                    const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance);
    void on_pushButtonDeposit_clicked();
    void on_pushButtonPaste_clicked();
    void on_pushButtonClear_clicked();
    void on_listWidgetSidechains_currentRowChanged(int nRow);
    void on_listWidgetSidechains_doubleClicked(const QModelIndex& index);
    void on_tableViewWT_doubleClicked(const QModelIndex& index);
    void on_pushButtonAddRemove_clicked();
    void on_pushButtonWithdrawalVote_clicked();
    void on_pushButtonWTDoubleClickHelp_clicked();
    void on_pushButtonRecentDepositHelp_clicked();
    void gotoWTPage();
    void numBlocksChanged();
    void ShowActivationDialog();
    void ShowSCDBDialog();
    void UpdateRecentDeposits();

private Q_SLOTS:
    void AnimateAddRemoveIcon();

private:
    Ui::SidechainPage *ui;

    ClientModel *clientModel = nullptr;
    WalletModel *walletModel = nullptr;

    SidechainDepositConfirmationDialog *depositConfirmationDialog = nullptr;
    SidechainWithdrawalTableModel *withdrawalModel = nullptr;
    SidechainActivationDialog *activationDialog = nullptr;
    SCDBDialog *scdbDialog = nullptr;

    const PlatformStyle *platformStyle = nullptr;

    QTimer *addRemoveAnimationTimer = nullptr;

    // Deposits created by the user during this session (memory only)
    std::vector<RecentDepositTableObject> vRecentDepositCache;

    // The sidechain that is currently highlighted
    uint8_t nSelectedSidechain;

    void SetupSidechainList(const std::vector<Sidechain>& vSidechain);
    bool validateDepositAmount();
    bool validateFeeAmount();

    // true = +, false = -
    bool fAnimationStatus = false;
};

// Format sidechain title for sidechain list.
// Sidechain number : sidechain title
QString FormatSidechainTitle(const QString& strSidechain, int nSidechain);

#endif // SIDECHAINPAGE_H
