// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_TRANSACTIONVIEW_H
#define BITCOIN_QT_TRANSACTIONVIEW_H

#include <qt/guiutil.h>

#include <QWidget>
#include <QKeyEvent>

class ClientModel;
class PlatformStyle;
class TransactionFilterProxy;
class TransactionReplayDialog;
class WalletModel;

QT_BEGIN_NAMESPACE
class QComboBox;
class QDateTimeEdit;
class QFrame;
class QLineEdit;
class QMenu;
class QModelIndex;
class QPushButton;
class QSignalMapper;
class QTableView;
QT_END_NAMESPACE

/** Widget showing the transaction list for a wallet, including a filter row.
    Using the filter row, the user can view or export a subset of the transactions.
  */
class TransactionView : public QWidget
{
    Q_OBJECT

public:
    explicit TransactionView(const PlatformStyle *platformStyle, QWidget *parent = 0);

    void setModel(WalletModel *model);
    void setClientModel(ClientModel *model);

    enum ColumnWidths {
        CONF_COLUMN_WIDTH = 60,
        DATE_COLUMN_WIDTH = 120,
        TXID_COLUMN_WIDTH = 500,
        AMOUNT_COLUMN_WIDTH = 120,
        WATCHONLY_COLUMN_WIDTH = 23,

        MINIMUM_COLUMN_WIDTH = 23
    };

private:
    WalletModel *model;
    ClientModel *clientModel;
    TransactionFilterProxy *transactionProxyModel;
    QTableView *transactionView;
    TransactionReplayDialog *replayDialog;

    QLineEdit *search_widget;
    QPushButton *replayButton;
    QPushButton *exportButton;
    QComboBox *watchOnlyWidget;

    QMenu *contextMenu;
    QSignalMapper *mapperThirdPartyTxUrls;

    QFrame *dateRangeWidget;
    QDateTimeEdit *dateFrom;
    QDateTimeEdit *dateTo;
    QAction *abandonAction;
    QAction *bumpFeeAction;

    QWidget *createDateRangeWidget();

    bool eventFilter(QObject *obj, QEvent *event);

private Q_SLOTS:
    void contextualMenu(const QPoint &);
    void dateRangeChanged();
    void showDetails();
    void showCoinSplitDialog();
    void copyAmount();
    void copyTxID();
    void copyTxHex();
    void copyTxPlainText();
    void openThirdPartyTxUrl(QString url);
    void updateWatchOnlyColumn(bool fHaveWatchOnly);
    void abandonTx();
    void bumpFee();

Q_SIGNALS:
    void doubleClicked(const QModelIndex&);

    /**  Fired when a message should be reported to the user */
    void message(const QString &title, const QString &message, unsigned int style);

public Q_SLOTS:
    void chooseWatchonly(int idx);
    void changedSearch();
    void exportClicked();
    void replayClicked();
    void focusTransaction(const QModelIndex&);

};

#endif // BITCOIN_QT_TRANSACTIONVIEW_H
