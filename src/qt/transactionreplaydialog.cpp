// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/transactionreplaydialog.h>
#include <qt/forms/ui_transactionreplaydialog.h>

#include <QProgressDialog>

#include <qt/addresstablemodel.h>
#include <qt/clientmodel.h>
#include <qt/coinsplitconfirmationdialog.h>
#include <qt/skydogeunits.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/walletmodel.h>

#include <apiclient.h>
#include <amount.h>
#include <uint256.h>
#include <primitives/transaction.h>
#include <utilmoneystr.h>
#include <wallet/wallet.h>

TransactionReplayDialog::TransactionReplayDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::TransactionReplayDialog)
{
    ui->setupUi(this);

    ui->tableWidgetCoins->setColumnCount(COLUMN_CONFIRMATIONS + 1);
    ui->tableWidgetCoins->setHorizontalHeaderLabels(
                QStringList() << "Replay status" << "Amount" << "Address"
                << "Date" << "txid" << "n" << "Confirmations");
    ui->tableWidgetCoins->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);

    // Resize cells (in a backwards compatible way)
#if QT_VERSION < 0x050000
    ui->tableWidgetCoins->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
#else
    ui->tableWidgetCoins->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
#endif

    ui->tableWidgetCoins->horizontalHeader()->setStretchLastSection(false);
    ui->tableWidgetCoins->verticalHeader()->setVisible(false);

    coinSplitConfirmationDialog = new CoinSplitConfirmationDialog(this);
}

TransactionReplayDialog::~TransactionReplayDialog()
{
    delete ui;
}

void TransactionReplayDialog::SetWalletModel(WalletModel* model)
{
    this->walletModel = model;
    Update();
}

void TransactionReplayDialog::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        connect(model, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)),
                this, SLOT(Update()));
    }
}

void TransactionReplayDialog::SetPlatformStyle(const PlatformStyle* style)
{
    platformStyle = style;

    // Set button icons
    if (platformStyle) {
        ui->pushButtonCheckReplay->setIcon(platformStyle->SingleColorIcon(":/icons/refresh"));
        ui->pushButtonSplitCoins->setIcon(platformStyle->SingleColorIcon(":/icons/replay_split"));
    }
}

void TransactionReplayDialog::Update()
{
    if (!this->isVisible())
        return;

    if (!walletModel || !walletModel->getOptionsModel()
            || !walletModel->getAddressTableModel())
        return;

    ui->tableWidgetCoins->setSortingEnabled(false);
    ui->tableWidgetCoins->setUpdatesEnabled(false);

    ui->tableWidgetCoins->setRowCount(0);

    int nDisplayUnit = walletModel->getOptionsModel()->getDisplayUnit();

    std::map<QString, std::vector<COutput> > mapCoins;
    walletModel->listCoins(mapCoins);

    int nRow = 0;
    for (const std::pair<QString, std::vector<COutput>>& coins : mapCoins) {
        QString sWalletAddress = coins.first;
        QString sWalletLabel = walletModel->getAddressTableModel()->labelForAddress(sWalletAddress);
        if (sWalletLabel.isEmpty())
            sWalletLabel = tr("(no label)");

        CAmount nSum = 0;
        int nChildren = 0;
        for (const COutput& out : coins.second) {
            ui->tableWidgetCoins->insertRow(nRow);
            nSum += out.tx->tx->vout[out.i].nValue;
            nChildren++;

            uint256 txhash = out.tx->GetHash();

            // Check if the coin is locked - if it is we will create the
            // item with disabled status
            bool fLocked = walletModel->isLockedCoin(txhash, out.i);

            // replay status
            int nReplayStatus = walletModel->GetReplayStatus(txhash);
            QTableWidgetItem *itemReplay = new QTableWidgetItem();
            itemReplay->setText(FormatReplayStatus(nReplayStatus));
            if (platformStyle) {
                itemReplay->setIcon(GetReplayIcon(nReplayStatus));
            }
            itemReplay->setFlags(itemReplay->flags() & ~Qt::ItemIsEditable);
            if (fLocked)
                itemReplay->setFlags(itemReplay->flags() & ~Qt::ItemIsEnabled);
            ui->tableWidgetCoins->setItem(nRow, COLUMN_REPLAY, itemReplay);

            // address
            CTxDestination outputAddress;
            QString sAddress = "";
            if(ExtractDestination(out.tx->tx->vout[out.i].scriptPubKey, outputAddress))
            {
                sAddress = QString::fromStdString(EncodeDestination(outputAddress));
            }
            QTableWidgetItem *itemAddress = new QTableWidgetItem();
            itemAddress->setText(sAddress);
            itemAddress->setFlags(itemAddress->flags() & ~Qt::ItemIsEditable);
            if (fLocked)
                itemAddress->setFlags(itemAddress->flags() & ~Qt::ItemIsEnabled);
            ui->tableWidgetCoins->setItem(nRow, COLUMN_ADDRESS, itemAddress);

            // amount
            QTableWidgetItem *itemAmount = new QTableWidgetItem();
            itemAmount->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            itemAmount->setText(BitcoinUnits::format(nDisplayUnit, out.tx->tx->vout[out.i].nValue));
            itemAmount->setFlags(itemAmount->flags() & ~Qt::ItemIsEditable);
            if (fLocked)
                itemAmount->setFlags(itemAmount->flags() & ~Qt::ItemIsEnabled);
            ui->tableWidgetCoins->setItem(nRow, COLUMN_AMOUNT, itemAmount);

            // date
            QTableWidgetItem *itemDate = new QTableWidgetItem();
            itemDate->setText(GUIUtil::dateTimeStr(out.tx->GetTxTime()));
            itemDate->setFlags(itemDate->flags() & ~Qt::ItemIsEditable);
            if (fLocked)
                itemDate->setFlags(itemDate->flags() & ~Qt::ItemIsEnabled);
            ui->tableWidgetCoins->setItem(nRow, COLUMN_DATE, itemDate);

            // txid
            QTableWidgetItem *itemTXID = new QTableWidgetItem();
            itemTXID->setText(QString::fromStdString(txhash.GetHex()));
            itemTXID->setFlags(itemTXID->flags() & ~Qt::ItemIsEditable);
            if (fLocked)
                itemTXID->setFlags(itemTXID->flags() & ~Qt::ItemIsEnabled);
            ui->tableWidgetCoins->setItem(nRow, COLUMN_TXHASH, itemTXID);

            // vout n
            QTableWidgetItem *itemN = new QTableWidgetItem();
            itemN->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            itemN->setText(QString::number(out.i));
            itemN->setFlags(itemN->flags() & ~Qt::ItemIsEditable);
            if (fLocked)
                itemN->setFlags(itemN->flags() & ~Qt::ItemIsEnabled);
            ui->tableWidgetCoins->setItem(nRow, COLUMN_VOUT_INDEX, itemN);

            // confirmations
            QTableWidgetItem *itemConf = new QTableWidgetItem();
            itemConf->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
            itemConf->setText(QString::number(out.nDepth));
            itemConf->setFlags(itemConf->flags() & ~Qt::ItemIsEditable);
            if (fLocked)
                itemConf->setFlags(itemConf->flags() & ~Qt::ItemIsEnabled);
            ui->tableWidgetCoins->setItem(nRow, COLUMN_CONFIRMATIONS, itemConf);

            nRow++;
        }
    }

    // TODO display loaded coins?
//    // Add loaded coins to the view
//    std::vector<LoadedCoin> vLoadedCoin;
//    vLoadedCoin = walletModel->getMyLoadedCoins();
//    for (const LoadedCoin& c : vLoadedCoin) {
//        if (walletModel->isSpent(c.out))
//            continue;

//        CCoinControlWidgetItem *itemOutput = new CCoinControlWidgetItem(ui->treeWidget);
//        itemOutput->setFlags(flgCheckbox);
//        itemOutput->setCheckState(COLUMN_CHECKBOX, Qt::Unchecked);
//        CTxDestination outputAddress;
//        QString sAddress = "";
//        if (ExtractDestination(c.coin.out.scriptPubKey, outputAddress)) {
//            sAddress = QString::fromStdString(EncodeDestination(outputAddress));
//            // TODO use scriptPubKey from LoadedCoin class so that we can
//            // guess what the address might have been...?
//            //itemOutput->setText(COLUMN_ADDRESS, sAddress);
//            itemOutput->setText(COLUMN_ADDRESS, tr("Loaded Coin (unknown address)"));
//        }
//        itemOutput->setText(COLUMN_LABEL, tr("(LOADED)"));
//        // amount
//        itemOutput->setText(COLUMN_AMOUNT, BitcoinUnits::format(nDisplayUnit, c.coin.out.nValue));
//        itemOutput->setData(COLUMN_AMOUNT, Qt::UserRole, QVariant((qlonglong)c.coin.out.nValue));
//        // TODO show other data that coincontroldialog displays
//        // transaction hash
//        itemOutput->setText(COLUMN_TXHASH, QString::fromStdString(c.out.hash.ToString()));
//        // vout index
//        itemOutput->setText(COLUMN_VOUT_INDEX, QString::number(c.out.n));
//        // set checkbox
//        if (coinControl()->IsSelected(c.out))
//            itemOutput->setCheckState(COLUMN_CHECKBOX, Qt::Checked);
//    }

    ui->tableWidgetCoins->setSortingEnabled(true);
    ui->tableWidgetCoins->setUpdatesEnabled(true);
}

void TransactionReplayDialog::on_pushButtonCheckReplay_clicked()
{
    if (!walletModel || !walletModel->getOptionsModel()) {
        return;
    }

    QMessageBox messageBox;
    QModelIndexList selection = ui->tableWidgetCoins->selectionModel()->selectedRows(COLUMN_TXHASH);
    if (!selection.size()) {
        messageBox.setWindowTitle("Please select transaction(s)!");
        QString str = QString("<p>You must select one or more transactions to check the replay status of!</p>");
        messageBox.setText(str);
        messageBox.setIcon(QMessageBox::Information);
        messageBox.setStandardButtons(QMessageBox::Ok);
        messageBox.exec();
        return;
    }

    messageBox.setWindowTitle("Are you sure?");
    QString warning = "Privacy Warning:\n\n";
    warning += "Using this feature will send requests over the internet ";
    warning += "which include information about your wallet's transactions.";
    warning += "\n\n";
    warning += "Checking the replay status of your wallet's transactions ";
    warning += "will require sending the same data over the internet as ";
    warning += "if you had visited a block explorer yourself.\n";
    messageBox.setText(warning);
    messageBox.setIcon(QMessageBox::Warning);
    messageBox.setStandardButtons(QMessageBox::Abort | QMessageBox::Ok);
    messageBox.setDefaultButton(QMessageBox::Abort);
    int ret = messageBox.exec();
    if (ret != QMessageBox::Ok) {
        return;
    }

    QString strProgress = "Checking transaction replay status...\n\n";
    strProgress += "Contacting block explorer API to check if selected ";
    strProgress += "transaction(s) have been replayed.\n\n";

    // Progress dialog with abort button. If user selects many transactions
    // to check, the operation can take a while.
    QProgressDialog progress(strProgress, "Abort", 0, selection.size(), this);
    progress.setWindowModality(Qt::WindowModal);
    progress.setWindowTitle("Replay status");
    progress.setMinimumDuration(0);
    progress.setMinimumSize(500, 100);

    QFont font;
    font.setStyleHint(QFont::Monospace);
    font.setFamily("noto");
    progress.setFont(font);

    progress.setValue(0);

    // Check replay status & display progress
    APIClient client;
    for (int i = 0; i < selection.size(); i++) {
        progress.setValue(i);
        if (progress.wasCanceled())
            break;

        QVariant data = selection[i].data();
        uint256 txid = uint256S(data.toString().toStdString());

        QString strStatus = strProgress;
        strStatus += "Checking: ";
        strStatus += QString::fromStdString(txid.ToString());
        strStatus += "\n";

        progress.setLabelText(strStatus);

        // Skip checking transactions that have replay protection enabled
        if (walletModel->GetReplayStatus(txid) == REPLAY_SPLIT)
            continue;

        // TODO handle request failure
        if (client.IsTxReplayed(txid)) {
            walletModel->UpdateReplayStatus(txid, REPLAY_TRUE);
        } else {
            walletModel->UpdateReplayStatus(txid, REPLAY_FALSE);
        }
    }
    progress.setValue(selection.size());

    // Update the model - replay status may have changed
    Update();
}

void TransactionReplayDialog::on_pushButtonSplitCoins_clicked()
{
    if (!walletModel || !walletModel->getOptionsModel()) {
        return;
    }

    QMessageBox messageBox;
    QModelIndexList selection = ui->tableWidgetCoins->selectionModel()->selectedRows(0);
    if (!selection.size()) {
        messageBox.setWindowTitle("Please select transaction(s)!");
        QString str = QString("<p>You must select one or more transactions to split!</p>");
        messageBox.setText(str);
        messageBox.setIcon(QMessageBox::Information);
        messageBox.setStandardButtons(QMessageBox::Ok);
        messageBox.exec();
        return;
    }

    if (selection.size() > 1) {
        messageBox.setWindowTitle("Are you sure you want to split multiple coins?");
        QString str = "If you select more than one output, multiple ";
        str+= "confirmation dialogs will be shown.";
        messageBox.setText(str);
        messageBox.setIcon(QMessageBox::Warning);
        messageBox.setStandardButtons(QMessageBox::Ok | QMessageBox::Cancel);
        int nRes = messageBox.exec();
        if (nRes == QMessageBox::Cancel)
            return;
    }

    QString strProgress = "Enabling replay protection...\n\n";
    strProgress += "Moving coins to new replay protected output.\n";

    for (int i = 0; i < selection.size(); i++) {
        int nRow = selection[i].row();

        QString txid = QVariant(selection[i].sibling(nRow, COLUMN_TXHASH).data()).toString();
        QString address = QVariant(selection[i].sibling(nRow, COLUMN_ADDRESS).data()).toString();
        int index = QVariant(selection[i].sibling(nRow, COLUMN_VOUT_INDEX).data()).toInt();

        // Skip transactions that already have replay protection enabled
        if (walletModel->GetReplayStatus(uint256S(txid.toStdString())) == REPLAY_SPLIT)
            continue;

        // Parse amount from table
        int nDisplayUnit = walletModel->getOptionsModel()->getDisplayUnit();
        CAmount amount;
        QString qAmount = QVariant(selection[i].sibling(nRow, COLUMN_AMOUNT).data()).toString();
        if (!BitcoinUnits::parse(nDisplayUnit, qAmount, &amount)) {
            // This error message shouldn't ever actually be displayed - but
            // if parsing the amount from the table does fail we want to know.
            messageBox.setWindowTitle("Failed to parse transaction amount!");
            QString str = QString("<p>Failed to parse transaction amount!</p>");
            messageBox.setText(str);
            messageBox.setIcon(QMessageBox::Critical);
            messageBox.setStandardButtons(QMessageBox::Ok);
            messageBox.exec();
            return;
        }

        coinSplitConfirmationDialog->SetInfo(amount, txid, address, index);
        coinSplitConfirmationDialog->exec();
    }

    // Update the model - replay status may have changed
    Update();
}

QIcon TransactionReplayDialog::GetReplayIcon(int nReplayStatus) const
{
    switch (nReplayStatus) {
    case REPLAY_UNKNOWN:
        return QIcon(platformStyle->SingleColorIcon(":/icons/replay_unknown"));
    case REPLAY_FALSE:
        return QIcon(platformStyle->SingleColorIcon(":/icons/replay_not_replayed"));
    case REPLAY_LOADED:
        return QIcon(platformStyle->SingleColorIcon(":/icons/replay_loaded"));
    case REPLAY_TRUE:
        return QIcon(platformStyle->SingleColorIcon(":/icons/replay_replayed"));
    case REPLAY_SPLIT:
        return QIcon(platformStyle->SingleColorIcon(":/icons/replay_split"));
    default:
        return QIcon(platformStyle->SingleColorIcon(":/icons/replay_unknown"));
    }
}

void TransactionReplayDialog::showEvent(QShowEvent* event) {
    QWidget::showEvent(event);
    Update();
}

QString FormatReplayStatus(int nReplayStatus)
{
    switch (nReplayStatus) {
    case REPLAY_UNKNOWN:
        return "Unknown";
    case REPLAY_FALSE:
        return "Not replayed";
    case REPLAY_LOADED:
        return "Loaded coin";
    case REPLAY_TRUE:
        return "Replayed";
    case REPLAY_SPLIT:
        return "Protected";
    default:
        return "Unknown";
    }
}
