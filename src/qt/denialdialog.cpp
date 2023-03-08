// Copyright (c) 2022- The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/denialdialog.h>
#include <qt/forms/ui_denialdialog.h>

#include <qt/clientmodel.h>
#include <qt/denialamountdialog.h>
#include <qt/denialscheduledialog.h>
#include <qt/denyallconfirmationdialog.h>
#include <qt/skydogeunits.h>
#include <qt/platformstyle.h>
#include <qt/scheduledtransactiontablemodel.h>

#include <QCheckBox>
#include <QDateTime>
#include <QMenu>
#include <QMessageBox>
#include <QScrollBar>
#include <QString>
#include <QTimer>

#include <net.h>
#include <primitives/transaction.h>
#include <random.h>
#include <validation.h>
#include <wallet/wallet.h>
#include <consensus/validation.h>

enum
{
    COLUMN_CHECKBOX = 0,
    COLUMN_TXID,
    COLUMN_AMOUNT,
    COLUMN_DENIAL,

};

static const int AUTOMATIC_REFRESH_MS = 10 * 60 * 1000; // 10 minutes

DenialDialog::DenialDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DenialDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    nAutoMinutes = 0;
    nDenialGoal = 0;

    // Setup coin table
    ui->tableWidgetCoins->setColumnCount(4);
    ui->tableWidgetCoins->setHorizontalHeaderLabels(
                QStringList() << "" << "TxID" << "Amount (BTC)" << "# Hops (times sent to self)");
    ui->tableWidgetCoins->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);

    // Resize cells (in a backwards compatible way)
#if QT_VERSION < 0x050000
    ui->tableWidgetCoins->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
#else
    ui->tableWidgetCoins->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
#endif

    ui->tableWidgetCoins->horizontalHeader()->setStretchLastSection(false);
    ui->tableWidgetCoins->verticalHeader()->setVisible(false);

    // Check for transactions to broadcast every 60 seconds
    scheduledTxTimer = new QTimer(this);
    connect(scheduledTxTimer, SIGNAL(timeout()), this, SLOT(broadcastScheduledTransactions()));
    scheduledTxTimer->start(60 * 1000);

    // Setup automatic denial timer
    automaticTimer = new QTimer(this);
    connect(automaticTimer, SIGNAL(timeout()), this, SLOT(automaticDenial()));

    // Setup automatic mode icon animation timer
    automaticAnimationTimer = new QTimer(this);
    connect(automaticAnimationTimer, SIGNAL(timeout()), this, SLOT(animateAutomationIcon()));

    nAnimation = 0;

    // Select rows
    ui->tableWidgetCoins->setSelectionBehavior(QAbstractItemView::SelectRows);

    // Apply custom context menu
    ui->tableWidgetCoins->setContextMenuPolicy(Qt::CustomContextMenu);

    QAction *denyAction = new QAction(tr("Deny coin"), this);

    contextMenu = new QMenu(this);
    contextMenu->setObjectName("contextMenuDenial");
    contextMenu->addAction(denyAction);

    // Connect context menus
    connect(ui->tableWidgetCoins, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
    connect(denyAction, SIGNAL(triggered()), this, SLOT(on_denyAction_clicked()));

    ui->labelAutoStatus->setText("");
    ui->pushButtonAnimation->setIcon(platformStyle->SingleColorIcon(":/icons/dots0"));
    ui->pushButtonAnimation->setVisible(false);
    ui->labelAutoStatus->setVisible(false);

    // Setup scheduled transaction table

    scheduledModel = new ScheduledTransactionTableModel(this);
    ui->scheduledTransactionView->setModel(scheduledModel);

#if QT_VERSION < 0x050000
    ui->scheduledTransactionView->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
    ui->scheduledTransactionView->verticalHeader()->setResizeMode(QHeaderView::ResizeToContents);
#else
    ui->scheduledTransactionView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    ui->scheduledTransactionView->verticalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
#endif

    // Hide vertical header
    ui->scheduledTransactionView->verticalHeader()->setVisible(false);
    // Left align the horizontal header text
    ui->scheduledTransactionView->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    // Set horizontal scroll speed to per 3 pixels
    ui->scheduledTransactionView->horizontalHeader()->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->scheduledTransactionView->horizontalHeader()->horizontalScrollBar()->setSingleStep(3); // 3 Pixels
    // Select entire row
    ui->scheduledTransactionView->setSelectionBehavior(QAbstractItemView::SelectRows);
    // Select only one row
    ui->scheduledTransactionView->setSelectionMode(QAbstractItemView::SingleSelection);
    // Disable word wrap
    ui->scheduledTransactionView->setWordWrap(false);

    ui->frameMore->setVisible(false);
    fMoreShown = false;

    ui->pushButtonMore->setStyleSheet("text-align:left");
}

DenialDialog::~DenialDialog()
{
    delete ui;
}

void DenialDialog::automaticDenial()
{
    QMessageBox messageBox;
    messageBox.setWindowTitle("Automatic denial failed!");

    // Decide which coin to deny and schedule denial
    for (size_t i = 0; i < vCoin.size(); i++) {
        // Skip if denial score is already what we wanted
        if (vCoin[i].tx->nDenial >= nDenialGoal)
            continue;

        // Skip if not checked

        if ((int) i >= ui->tableWidgetCoins->rowCount())
            return;

        bool fChecked = ui->tableWidgetCoins->item(i, COLUMN_CHECKBOX)->checkState() == Qt::Checked;
        if (!fChecked)
            continue;

        // Schedule denial of coin

        CWalletTx wtx;
        std::string strFail = "";
        if (!vpwallets[0]->DenyCoin(wtx, strFail, vCoin[i], false /* fBroadcast */)) {
            messageBox.setText(QString::fromStdString(strFail));
            messageBox.exec();
        }

        // Add a random number of seconds to current time
        QDateTime dateTime = QDateTime::currentDateTime().addSecs(GetRand(nAutoMinutes * 60));

        std::string strTime = dateTime.toString(QString::fromStdString(SCHEDULED_TX_TIME_FORMAT)).toStdString();
        if (!vpwallets[0]->ScheduleTransaction(wtx.GetHash(), strTime)) {
            messageBox.setText("Failed to schedule transaction!\n");
            messageBox.exec();
        }

        updateCoins();
        break;
    }

    // Change automatic timer to new random time
    automaticTimer->start(GetRand(AUTOMATIC_REFRESH_MS));
}

void DenialDialog::animateAutomationIcon()
{
    QString strIcon = ":/icons/dots" + QString::number(nAnimation);
    ui->pushButtonAnimation->setIcon(platformStyle->SingleColorIcon(strIcon));

    if (nAnimation >= 5)
        nAnimation = 0;
    else
        nAnimation++;

    int nMS = automaticTimer->remainingTime();
    QDateTime dateTime = QDateTime::currentDateTime().addMSecs(nMS);

    ui->labelAutoStatus->setText("Next operation:\n" + dateTime.toString("ddd MMM d h:mm a"));
}

void DenialDialog::on_pushButtonDenyAll_clicked()
{
    QMessageBox messageBox;
    messageBox.setWindowTitle("Denial failed!");

    if (vpwallets.empty() || vpwallets[0]->IsLocked()) {
        messageBox.setText("You must have an active & unlocked wallet to deny things!\n");
        messageBox.exec();
        return;
    }

    DenyAllConfirmationDialog confDialog;
    confDialog.exec();

    bool fConfirmed = confDialog.GetConfirmed();
    nDenialGoal = confDialog.GetSkipScore();
    nAutoMinutes = confDialog.GetDelayMinutes();

    if (!fConfirmed)
        return;

    // Start automatic denial timer with random refresh time
    automaticTimer->start(GetRand(AUTOMATIC_REFRESH_MS));

    automaticAnimationTimer->start(1000);
    ui->labelAutoStatus->setText("Automation enabled!");
    ui->pushButtonAnimation->setVisible(true);
    ui->labelAutoStatus->setVisible(true);

    messageBox.setWindowTitle("Automatic denial started!");
    QString result = "Denial transactions will be created scheduled for broadcast!";
    messageBox.setText(result);
    messageBox.exec();
}

void DenialDialog::on_pushButtonCreateAmount_clicked()
{
    if (vpwallets.empty())
        return;

    if (vpwallets[0]->IsLocked())
        return;

    vpwallets[0]->BlockUntilSyncedToCurrentChain();

    QMessageBox messageBox;
    messageBox.setWindowTitle("Denial failed!");

    DenialAmountDialog dialog;
    dialog.exec();

    CAmount amount = dialog.GetAmount();

    if (!amount)
        return;

    // Find coins to cover the amount we want
    std::vector<COutput> vCoinSelected;
    CAmount amountFound = CAmount(0);
    for (const COutput& coin : vCoin) {
        vCoinSelected.push_back(coin);
        amountFound += coin.tx->tx->vout[coin.i].nValue;
        if (amountFound >= amount)
            break;
    }

    if (amountFound < amount) {
        messageBox.setText("Failed to collect enough coins to create amount!\n");
        messageBox.exec();
    }

    // Create address to receive the amount
    CTxDestination dest;
    {
        LOCK2(cs_main, vpwallets[0]->cs_wallet);

        OutputType output_type = OUTPUT_TYPE_LEGACY;
        vpwallets[0]->TopUpKeyPool();

        // Generate a new key that is added to wallet
        CPubKey newKey;
        if (!vpwallets[0]->GetKeyFromPool(newKey)) {
            messageBox.setText("Failed to generate new key!\n");
            messageBox.exec();
        }
        vpwallets[0]->LearnRelatedScripts(newKey, output_type);
        dest = GetDestinationForKey(newKey, output_type);
    }

    // Create denial transactions to create total amount
    CAmount amountRemaining = amount;
    CAmount amountChange = CAmount (0);
    for (const COutput& coin : vCoinSelected) {
        CWalletTx wtx;
        std::string strFail = "";

        CAmount amountCoin = coin.tx->tx->vout[coin.i].nValue;
        CAmount amountOut = amountCoin;

        if (amountRemaining >= amountCoin) {
            amountRemaining -= amountCoin;
            amountOut = amountCoin;
        } else {
            amountOut = amountRemaining;
            amountRemaining = CAmount(0);
            amountChange += amountCoin - amountOut;
        }

        // Create transaction but don't broadcast yet
        if (!vpwallets[0]->DenyCoin(wtx, strFail, coin, false /* fBroadcast */, amountOut, dest)) {
            messageBox.setText(QString::fromStdString(strFail));
            messageBox.exec();
            return;
        }

        // TODO randomize time
        QDateTime currentDateTime = QDateTime::currentDateTime();
        QDateTime dateTime = currentDateTime;

        // Schedule for later
        std::string strTime = dateTime.toString(QString::fromStdString(SCHEDULED_TX_TIME_FORMAT)).toStdString();
        if (!vpwallets[0]->ScheduleTransaction(wtx.GetHash(), strTime)) {
            messageBox.setText("Failed to schedule transaction!\n");
            messageBox.exec();
            return;
        }
    }
    updateCoins();
}

void DenialDialog::on_pushButtonSweep_clicked()
{
    Q_EMIT requestedSendAllCoins();
}

void DenialDialog::on_pushButtonMore_clicked()
{
    if (fMoreShown) {
        ui->frameMore->setVisible(false);
        ui->pushButtonMore->setText("More");
    }
    else {
        ui->frameMore->setVisible(true);
        ui->pushButtonMore->setText("Less");
   }

    fMoreShown = !fMoreShown;
}

void DenialDialog::on_checkBoxAll_toggled(bool fChecked)
{
    ui->tableWidgetCoins->setUpdatesEnabled(false);
    ui->tableWidgetCoins->blockSignals(true);
    for (int i = 0; i < ui->tableWidgetCoins->rowCount(); i++) {
        QTableWidgetItem *itemCheck = ui->tableWidgetCoins->item(i, COLUMN_CHECKBOX);

        if (!(itemCheck->flags() & Qt::ItemIsEnabled))
            continue;

        if (fChecked)
            itemCheck->setCheckState(Qt::Checked);
        else
            itemCheck->setCheckState(Qt::Unchecked);
    }
    ui->tableWidgetCoins->blockSignals(false);
    ui->tableWidgetCoins->setUpdatesEnabled(true);
}

void DenialDialog::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        connect(model, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)),
                this, SLOT(updateCoins()));

        scheduledModel->setClientModel(model);
    }
}

void DenialDialog::updateCoins()
{
    if (vpwallets.empty() || vpwallets[0]->IsLocked())
        return;

    ui->tableWidgetCoins->setUpdatesEnabled(false);

    // Before we reset the table, keep track of check state
    std::map<QString, int> mapCheck;
    for (int i = 0; i < ui->tableWidgetCoins->rowCount(); i++) {
        // If the coin at this row is checked, add to map
        QTableWidgetItem *itemCheck = ui->tableWidgetCoins->item(i, COLUMN_CHECKBOX);
        bool fChecked = ui->tableWidgetCoins->item(i, COLUMN_CHECKBOX)->checkState() == Qt::Checked;
        if (fChecked)
            mapCheck[itemCheck->data(TXIDRole).toString()] = itemCheck->data(iRole).toInt();
    }

    // Get available coins & update our cache
    vCoin.clear();
    {
        LOCK2(cs_main, vpwallets[0]->cs_wallet);
        vpwallets[0]->AvailableCoins(vCoin);
    }

    // Sort coins by denial score
    SortByDenial(vCoin);

    // If the table isn't visible, stop here
    if (!this->isVisible()) {
        ui->tableWidgetCoins->setUpdatesEnabled(true);
        scheduledModel->UpdateModel();
        return;
    }

    ui->tableWidgetCoins->setRowCount(0);

    int nRow = 0;
    std::vector<QTableWidgetItem> vItem;
    for (const COutput& out : vCoin) {
        ui->tableWidgetCoins->insertRow(nRow);

        QString txid = QString::fromStdString(out.tx->GetHash().ToString());
        unsigned int nDenial = out.tx->nDenial;

        // Checkbox
        QTableWidgetItem *itemCheck = new QTableWidgetItem();
        itemCheck->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        itemCheck->setCheckState(Qt::Unchecked);
        itemCheck->setData(TXIDRole, txid);
        itemCheck->setData(iRole, out.i);

        // If the coin already has a denial score, disable the checkbox
        if (nDenial)
            itemCheck->setFlags(Qt::ItemIsUserCheckable);
        else
            itemCheck->setFlags(Qt::ItemIsUserCheckable | Qt::ItemIsEnabled);

        if (nDenial || (mapCheck.find(txid) != mapCheck.end() && mapCheck[txid] == out.i))
            itemCheck->setCheckState(Qt::Checked);

        ui->tableWidgetCoins->setItem(nRow, COLUMN_CHECKBOX, itemCheck);

        // txid
        QTableWidgetItem *itemTxid = new QTableWidgetItem();
        itemTxid->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        itemTxid->setText(txid + ":" + QString::number(out.i));
        itemTxid->setFlags(itemTxid->flags() & ~Qt::ItemIsEditable);
        ui->tableWidgetCoins->setItem(nRow, COLUMN_TXID, itemTxid);

        // Amount
        QTableWidgetItem *itemAmount = new QTableWidgetItem();
        itemAmount->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        itemAmount->setText(BitcoinUnits::format(BitcoinUnits::SKYDOGE, out.tx->tx->vout[out.i].nValue, false, BitcoinUnits::separatorNever));
        itemAmount->setFlags(itemAmount->flags() & ~Qt::ItemIsEditable);
        ui->tableWidgetCoins->setItem(nRow, COLUMN_AMOUNT, itemAmount);

        // Denial status
        QTableWidgetItem *itemDenial = new QTableWidgetItem();
        itemDenial->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
        QString hops = nDenial == 1 ? " Hop" : " Hops";
        itemDenial->setText(QString::number(nDenial) + hops);
        itemDenial->setFlags(itemDenial->flags() & ~Qt::ItemIsEditable);

        // Set denial cell highlight color
        if (nDenial == 0)
            itemDenial->setBackground(QColor(178, 34, 34, 150));
        else
        if (nDenial == 1)
            itemDenial->setBackground(QColor(178, 34, 0, 100));
        else
        if (nDenial == 2)
            itemDenial->setBackground(QColor(255, 140, 0, 100));
        else
        if (nDenial == 3)
            itemDenial->setBackground(QColor(245, 245, 245, 80));

        ui->tableWidgetCoins->setItem(nRow, COLUMN_DENIAL, itemDenial);

        nRow++;
    }

    ui->tableWidgetCoins->setUpdatesEnabled(true);

    scheduledModel->UpdateModel();
}

void DenialDialog::UpdateOnShow()
{
    updateCoins();
}

void DenialDialog::on_tableWidgetCoins_doubleClicked(const QModelIndex& i)
{
    Deny(i);
}

void DenialDialog::broadcastScheduledTransactions()
{
    if (vpwallets.empty() || vpwallets[0]->IsLocked())
        return;

    // Get current time and day of the week
    QDateTime currentDateTime = QDateTime::currentDateTime();
    int nCurrentDay = currentDateTime.date().dayOfWeek();

    std::vector<ScheduledTransaction> vScheduled = vpwallets[0]->GetScheduled();
    std::vector<ScheduledTransaction> vComplete;
    for (ScheduledTransaction& s : vScheduled) {
        QDateTime txDateTime = QDateTime::fromString(
                    QString::fromStdString(s.strTime),
                    QString::fromStdString(SCHEDULED_TX_TIME_FORMAT));

        if (nCurrentDay != txDateTime.date().dayOfWeek())
            continue;

        QTime currentTime = currentDateTime.time();
        QTime txTime = txDateTime.time();

        // Skip if the scheduled time is > 1 minute away from now
        if (currentTime.secsTo(txTime) > 1 * 60)
            continue;

        if (!vpwallets[0]->BroadcastScheduled(s.wtxid))
            continue;

        vComplete.push_back(s);
    }

    for (ScheduledTransaction& s : vComplete)
        vpwallets[0]->RemoveScheduledTransaction(s);

    if (vComplete.size())
        updateCoins();
}

struct CompareByDenial
{
    bool operator()(const COutput& a, const COutput& b) const
    {
        return a.tx->nDenial < b.tx->nDenial;
    }
};

void DenialDialog::SortByDenial(std::vector<COutput>& vCoin)
{
    std::sort(vCoin.begin(), vCoin.end(), CompareByDenial());
}

void DenialDialog::Deny(const QModelIndex& index)
{
    QMessageBox messageBox;
    messageBox.setWindowTitle("Denial failed!");

    if (!index.isValid()) {
        messageBox.setText("Invalid index selected!\n");
        messageBox.exec();
        return;
    }

    size_t nRow = index.row();

    if (nRow >= vCoin.size()) {
        messageBox.setText("Invalid coin selected!\n");
        messageBox.exec();
        return;
    }

    if (vpwallets.empty() || vpwallets[0]->IsLocked()) {
        messageBox.setText("You must have an active & unlocked wallet to deny things!\n");
        messageBox.exec();
        return;
    }

    // Ask to schedule the transaction
    DenialScheduleDialog scheduleDialog;
    scheduleDialog.exec();

    const COutput coin = vCoin[nRow];

    CWalletTx wtx;
    std::string strFail = "";
    if (!scheduleDialog.GetScheduled())
        return;

    QString strAmount = BitcoinUnits::format(BitcoinUnits::SKYDOGE, coin.tx->tx->vout[coin.i].nValue, false, BitcoinUnits::separatorNever);

    QString confirm = "This will schedule a transaction which moves the coin you have selected to one or more new addresses!\n\n";
    confirm += "Amount to deny: " + strAmount + "\n\n";
    confirm += "Are you sure?\n";
    int nRes = QMessageBox::question(this, tr("Skydoge - confirm denial"),
                                     confirm,
                                     QMessageBox::Ok, QMessageBox::Cancel);
    if (nRes == QMessageBox::Cancel)
        return;

    // Schedule the transaction for later

    if (!vpwallets[0]->DenyCoin(wtx, strFail, coin, false /* fBroadcast */)) {
        messageBox.setText(QString::fromStdString(strFail));
        messageBox.exec();
        return;
    }

    QDateTime dateTime = scheduleDialog.GetDateTime();
    std::string strTime = dateTime.toString(QString::fromStdString(SCHEDULED_TX_TIME_FORMAT)).toStdString();
    if (!vpwallets[0]->ScheduleTransaction(wtx.GetHash(), strTime)) {
        messageBox.setText("Failed to schedule transaction!\n");
        messageBox.exec();
        return;
    }

    QString result = "Denial transaction scheduled!\n\n";
    result += "TxID:\n";
    result += QString::fromStdString(wtx.tx->GetHash().ToString()) + "\n\n";
    result += "Check the transactions tab to view scheduled transactions.";

    messageBox.setWindowTitle("Denial scheduled!");
    messageBox.setText(result);
    messageBox.exec();

    updateCoins();
}

void DenialDialog::on_denyAction_clicked()
{
    if (!ui->tableWidgetCoins->selectionModel())
        return;

    QModelIndexList selection = ui->tableWidgetCoins->selectionModel()->selectedRows();
    if (!selection.isEmpty())
        Deny(selection.front());
}

void DenialDialog::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableWidgetCoins->indexAt(point);
    if (index.isValid())
        contextMenu->popup(ui->tableWidgetCoins->viewport()->mapToGlobal(point));
}
