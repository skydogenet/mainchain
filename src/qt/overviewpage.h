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
class NewsTypesTableModel;
class OPReturnDialog;
class PlatformStyle;
class SidechainWithdrawalTableModel;
class TransactionFilterProxy;
class TxViewDelegate;
class WalletModel;

namespace Ui {
    class OverviewPage;
}

QT_BEGIN_NAMESPACE
class QDateTime;
class QMenu;
class QModelIndex;
class QSortFilterProxyModel;
class QTimer;
QT_END_NAMESPACE

/** Overview ("home") page widget */
class OverviewPage : public QWidget
{
    Q_OBJECT

public:
    explicit OverviewPage(const PlatformStyle *platformStyleIn, QWidget *parent = 0);
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
    ClientModel *clientModel = nullptr;
    CreateNewsDialog *createNewsDialog = nullptr;
    LatestBlockTableModel *latestBlockModel = nullptr;
    MemPoolTableModel *memPoolModel = nullptr;
    ManageNewsDialog *manageNewsDialog = nullptr;
    NewsTableModel *newsModel1 = nullptr;
    NewsTableModel *newsModel2 = nullptr;
    NewsTypesTableModel *newsTypesTableModel = nullptr;
    OPReturnDialog *opReturnDialog = nullptr;
    WalletModel *walletModel = nullptr;
    CAmount currentBalance;
    CAmount currentUnconfirmedBalance;
    CAmount currentImmatureBalance;
    CAmount currentWatchOnlyBalance;
    CAmount currentWatchUnconfBalance;
    CAmount currentWatchImmatureBalance;
    QMenu *contextMenuNews1 = nullptr;
    QMenu *contextMenuNews2 = nullptr;
    QMenu *contextMenuMempool = nullptr;
    QMenu *contextMenuBlocks = nullptr;
    QSortFilterProxyModel *proxyModelNews1 = nullptr;
    QSortFilterProxyModel *proxyModelNews2 = nullptr;
    const PlatformStyle *platformStyle;

private Q_SLOTS:
    void updateDisplayUnit();
    void updateAlerts(const QString &warnings);
    void updateWatchOnlyLabels(bool showWatchOnly);
    void handleOutOfSyncWarningClicks();
    void on_pushButtonCreateNews_clicked();
    void on_pushButtonManageNews_clicked();
    void on_pushButtonGraffiti_clicked();
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
    void copyNews1();
    void copyNews2();
    void copyNewsHex1();
    void copyNewsHex2();
    void showDetailsMempool();
    void showDetailsBlock();
};

#endif // BITCOIN_QT_OVERVIEWPAGE_H
