// Copyright (c) 2011-2017 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_OVERVIEWPAGE_H
#define BITCOIN_QT_OVERVIEWPAGE_H

#include <amount.h>

#include <QWidget>
#include <memory>

class BlockIndexDetailsDialog;
class ClientModel;
class CreateNewsDialog;
class LatestBlockTableModel;
class ManageNewsDialog;
class MemPoolTableModel;
class NewsTableModel;
class PlatformStyle;
class SidechainWithdrawalTableModel;
class TransactionFilterProxy;
class TxViewDelegate;
class WalletModel;
class WTPrimeViewDelegate;

namespace Ui {
    class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QDateTime;
class QMenu;
class QModelIndex;
class QTimer;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewPage(const PlatformStyle *platformStyle, QWidget *parent = 0);
    ~OverviewPage();

    void setClientModel(ClientModel *clientModel);
    void setWalletModel(WalletModel *walletModel);
    void setMemPoolModel(MemPoolTableModel *model);
    void showOutOfSyncWarning(bool fShow);

public Q_SLOTS:
    void setBalance(const CAmount& balance, const CAmount& unconfirmedBalance, const CAmount& immatureBalance,
                    const CAmount& watchOnlyBalance, const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance);

Q_SIGNALS:
    void outOfSyncWarningClicked();

private:
    Ui::OverviewPage *ui;
    BlockIndexDetailsDialog* blockIndexDialog = nullptr;
    ClientModel *clientModel;
    CreateNewsDialog *createNewsDialog = nullptr;
    LatestBlockTableModel *latestBlockModel = nullptr;
    MemPoolTableModel *memPoolModel = nullptr;
    ManageNewsDialog *manageNewsDialog = nullptr;
    NewsTableModel *newsModel1 = nullptr;
    NewsTableModel *newsModel2 = nullptr;
    WalletModel *walletModel;
    CAmount currentBalance;
    CAmount currentUnconfirmedBalance;
    CAmount currentImmatureBalance;
    CAmount currentWatchOnlyBalance;
    CAmount currentWatchUnconfBalance;
    CAmount currentWatchImmatureBalance;
    QMenu *contextMenuNews1;
    QMenu *contextMenuNews2;
    QMenu *contextMenuMempool;
    QMenu *contextMenuBlocks;

private Q_SLOTS:
    void updateDisplayUnit();
    void updateAlerts(const QString &warnings);
    void updateWatchOnlyLabels(bool showWatchOnly);
    void handleOutOfSyncWarningClicks();
    void on_pushButtonCreateNews_clicked();
    void on_pushButtonManageNews_clicked();
    void on_tableViewBlocks_doubleClicked(const QModelIndex& index);
    void on_tableViewMempool_doubleClicked(const QModelIndex& index);
    void on_tableViewNews1_doubleClicked(const QModelIndex& index);
    void on_comboBoxNewsType1_currentIndexChanged(int index);
    void on_tableViewNews2_doubleClicked(const QModelIndex& index);
    void on_comboBoxNewsType2_currentIndexChanged(int index);
    void contextualMenuNews1(const QPoint &);
    void contextualMenuNews2(const QPoint &);
    void contextualMenuMempool(const QPoint &);
    void contextualMenuBlocks(const QPoint &);
    void updateNewsTypes();

    void showDetailsNews1();
    void showDetailsNews2();
    void showDetailsMempool();
    void showDetailsBlock();
};

#endif // BITCOIN_QT_OVERVIEWPAGE_H
