// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/sidechainpage.h>
#include <qt/forms/ui_sidechainpage.h>

#include <qt/clientmodel.h>
#include <qt/skydogeunits.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/optionsmodel.h>
#include <qt/platformstyle.h>
#include <qt/sidechainactivationdialog.h>
#include <qt/sidechaindetailsdialog.h>
#include <qt/sidechaindepositconfirmationdialog.h>
#include <qt/scdbdialog.h>
#include <qt/sidechainwithdrawaltablemodel.h>
#include <qt/txdetails.h>
#include <qt/walletmodel.h>

#include <base58.h>
#include <coins.h>
#include <consensus/validation.h>
#include <core_io.h>
#include <init.h>
#include <miner.h>
#include <net.h>
#include <primitives/block.h>
#include <sidechaindb.h>
#include <txdb.h>
#include <validation.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>

#include <QApplication>
#include <QClipboard>
#include <QHeaderView>
#include <QMessageBox>
#include <QScrollBar>
#include <QStackedWidget>
#include <QString>
#include <QTimer>

#include <sstream>

// SIDECHAIN_DEPOSIT_FEE now comes from sidechain.h (shared with the RPC)

SidechainPage::SidechainPage(const PlatformStyle *_platformStyle, QWidget *parent) :
    QWidget(parent),
    ui(new Ui::SidechainPage),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    // Setup sidechain list widget & combo box. Read scdb under cs_main (it is
    // move-assigned wholesale by ConnectBlock), but non-blocking: if a block is
    // connecting while the window is built, skip the initial fill and let
    // numBlocksChanged (fired when the client model is set) populate it. A
    // blocking lock here would stall window creation during IBD.
    {
        TRY_LOCK(cs_main, lockMain);
        if (lockMain) {
            std::vector<Sidechain> vSidechain = scdb.GetSidechains();
            SetupSidechainList(vSidechain);
        }
    }

    depositConfirmationDialog = new SidechainDepositConfirmationDialog(this);

    activationDialog = new SidechainActivationDialog(platformStyle);
    activationDialog->setParent(this, Qt::Window);

    scdbDialog = new SCDBDialog(platformStyle);
    scdbDialog->setParent(this, Qt::Window);

    // Setup recent deposits table
    ui->tableWidgetRecentDeposits->setColumnCount(COLUMN_STATUS + 1);
    ui->tableWidgetRecentDeposits->setHorizontalHeaderLabels(
                QStringList() << "SC #" << "Amount" << "Conf" << "Deposit visible on SC?");
    ui->tableWidgetRecentDeposits->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);

    // Resize cells (in a backwards compatible way)
#if QT_VERSION < 0x050000
    ui->tableWidgetRecentDeposits->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
#else
    ui->tableWidgetRecentDeposits->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
#endif

    ui->tableWidgetRecentDeposits->horizontalHeader()->setStretchLastSection(false);
    ui->tableWidgetRecentDeposits->verticalHeader()->setVisible(false);

    // Setup platform style single color icons

    // Buttons
    ui->pushButtonAddRemove->setIcon(platformStyle->SingleColorIcon(":/icons/options"));
    ui->pushButtonWithdrawalVote->setIcon(platformStyle->SingleColorIcon(":/icons/options"));
    ui->pushButtonDeposit->setIcon(platformStyle->SingleColorIcon(":/icons/send"));
    ui->pushButtonPaste->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
    ui->pushButtonClear->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));
    ui->pushButtonWTDoubleClickHelp->setIcon(platformStyle->SingleColorIcon(":/icons/transaction_0"));
    ui->pushButtonRecentDepositHelp->setIcon(platformStyle->SingleColorIcon(":/icons/transaction_0"));

    addRemoveAnimationTimer = new QTimer(this);
    connect(addRemoveAnimationTimer, SIGNAL(timeout()), this, SLOT(AnimateAddRemoveIcon()));
    addRemoveAnimationTimer->start(3000);
    AnimateAddRemoveIcon();

    nSelectedSidechain = 0;
}

SidechainPage::~SidechainPage()
{
    delete ui;
}

void SidechainPage::AnimateAddRemoveIcon()
{
    QString strIcon = fAnimationStatus ? ":/icons/add" : ":/icons/delete";
    fAnimationStatus = !fAnimationStatus;
    ui->pushButtonAddRemove->setIcon(platformStyle->SingleColorIcon(strIcon));
}

void SidechainPage::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        numBlocksChanged();

        connect(model, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)),
                this, SLOT(numBlocksChanged()));

        scdbDialog->setClientModel(model);
    }
}

void SidechainPage::setWalletModel(WalletModel *model)
{
    this->walletModel = model;
    if (model && model->getOptionsModel())
    {
        connect(model, SIGNAL(balanceChanged(CAmount,CAmount,CAmount,CAmount,CAmount,CAmount)), this,
                SLOT(setBalance(CAmount,CAmount,CAmount,CAmount,CAmount,CAmount)));
    }
}

void SidechainPage::setWithdrawalModel(SidechainWithdrawalTableModel *model)
{
    this->withdrawalModel = model;

    if (model) {
        // Add model to table view
        ui->tableViewWT->setModel(withdrawalModel);

        // Resize cells (in a backwards compatible way)
    #if QT_VERSION < 0x050000
        ui->tableViewWT->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
    #else
        ui->tableViewWT->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
    #endif

        // Don't stretch last cell of horizontal header
        ui->tableViewWT->horizontalHeader()->setStretchLastSection(false);

        // Hide vertical header
        ui->tableViewWT->verticalHeader()->setVisible(false);

        // Left align the horizontal header text
        ui->tableViewWT->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);

        // Set horizontal scroll speed to per 3 pixels (very smooth, default is awful)
        ui->tableViewWT->horizontalHeader()->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
        ui->tableViewWT->horizontalHeader()->horizontalScrollBar()->setSingleStep(3); // 3 Pixels

        // Disable word wrap
        ui->tableViewWT->setWordWrap(false);
    }
}

void SidechainPage::setBalance(const CAmount& balance, const CAmount& unconfirmedBalance,
                               const CAmount& immatureBalance, const CAmount& watchOnlyBalance,
                               const CAmount& watchUnconfBalance, const CAmount& watchImmatureBalance)
{
    // TODO use all of these values
    // int unit = walletModel->getOptionsModel()->getDisplayUnit();
    // const CAmount& pending = immatureBalance + unconfirmedBalance;
    // ui->available->setText(BitcoinUnits::formatWithUnit(unit, balance, false, BitcoinUnits::separatorAlways));
    // ui->pending->setText(BitcoinUnits::formatWithUnit(unit, pending, false, BitcoinUnits::separatorAlways));
}

void SidechainPage::SetupSidechainList(const std::vector<Sidechain>& vSidechain)
{
    // Caller must hold cs_main: this reads the global scdb (IsSidechainActive /
    // GetSidechainName / GetCTIP / GetActiveSidechains), which ConnectBlock
    // move-assigns under cs_main. Both callers (the constructor and
    // numBlocksChanged) hold it non-blocking before calling.
    //
    // Asserted rather than left to the comment: a future call site that forgets
    // the lock reintroduces the use-after-free silently, and the read races
    // only when a block happens to connect mid-refresh, so testing would not
    // reliably show it.
    AssertLockHeld(cs_main);

    // Setup Sidechains list widget

    // If there are no active sidechains, display message on deposit section
    if (vSidechain.empty())
        ui->stackedWidgetSecondary->setCurrentIndex(1);
    else
        ui->stackedWidgetSecondary->setCurrentIndex(0);

    // Remove any existing list widget items
    ui->listWidgetSidechains->clear();

    // Update the list widget with new sidechains
    for (const Sidechain& s : vSidechain) {
        QListWidgetItem *item = new QListWidgetItem(ui->listWidgetSidechains);

        if (scdb.IsSidechainActive(s.nSidechain)) {
            // Display active sidechain
            QString title = FormatSidechainTitle(QString::fromStdString(scdb.GetSidechainName(s.nSidechain)), s.nSidechain);

            SidechainCTIP ctip;
            if (!scdb.GetCTIP(s.nSidechain, ctip))
                title += " (" + BitcoinUnits::formatWithUnit(BitcoinUnit::SKYDOGE, CAmount(0), false, BitcoinUnits::separatorAlways) + ")";
            else
                title += " (" + BitcoinUnits::formatWithUnit(BitcoinUnit::SKYDOGE, ctip.amount, false, BitcoinUnits::separatorAlways) + ")";

            item->setText(title);
            QFont font = item->font();
            font.setPointSize(12);
            item->setFont(font);

            ui->listWidgetSidechains->addItem(item);
        } else {
            // Display inactive sidechain slot
            item->setFlags(item->flags() & ~Qt::ItemIsEnabled);

            // Set text
            item->setText(FormatSidechainTitle("Inactive", s.nSidechain));
            QFont font = item->font();
            font.setPointSize(12);
            item->setFont(font);

            ui->listWidgetSidechains->addItem(item);
        }
    }

    // If the highlighted sidechain number is inactive, highlight the first
    // active sidechain in the list.
    if (!scdb.IsSidechainActive(nSelectedSidechain)) {
        std::vector<Sidechain> vActive = scdb.GetActiveSidechains();
        if (vActive.size())
            nSelectedSidechain = vActive.front().nSidechain;
    }

    ui->listWidgetSidechains->setCurrentRow(nSelectedSidechain);
}

void SidechainPage::on_pushButtonDeposit_clicked()
{
    QMessageBox messageBox;

    unsigned int nSidechain = nSelectedSidechain;

    // Read the global scdb only under cs_main (ConnectBlock move-assigns it),
    // and never hold the lock across a modal dialog's exec() below - that would
    // stall the validation thread for as long as the dialog is open. Each scdb
    // read in this handler therefore takes cs_main in its own short scope.
    bool fActive;
    {
        LOCK(cs_main);
        fActive = scdb.IsSidechainActive(nSidechain);
    }
    if (!fActive) {
        // Should never be displayed
        messageBox.setWindowTitle("Invalid sidechain selected");
        messageBox.exec();
        return;
    }

    if (!validateDepositAmount()) {
        // Invalid deposit amount message box
        messageBox.setWindowTitle("Invalid deposit amount!");
        QString error = "Check the amount you have entered and try again.\n\n";
        error += "Your deposit must be > 0.00001 SKYDOGE to cover the sidechain ";
        error += "deposit fee. If the output amount is dust after paying the ";
        error += "fee, you will not receive anything on the sidechain.\n";
        messageBox.setText(error);
        messageBox.exec();
        return;
    }

    if (!validateFeeAmount()) {
        // Invalid fee amount message box
        messageBox.setWindowTitle("Invalid fee amount!");
        QString error = "Check the fee you have entered and try again.\n\n";
        error += "Your fee must be greater than 0 & not dust!\n";
        messageBox.setText(error);
        messageBox.exec();
        return;
    }

    // Get the destination string from the sidechain deposit address
    std::string strDest = "";
    unsigned int nSidechainFromAddress = 0;
    if (!ParseDepositAddress(ui->payTo->text().toStdString(), strDest, nSidechainFromAddress)) {
        // Invalid deposit address
        messageBox.setWindowTitle("Invalid sidechain deposit address!");
        messageBox.setText("Check the address you have entered and try again.");
        messageBox.exec();
        return;
    }

    if (strDest == SIDECHAIN_WITHDRAWAL_RETURN_DEST) {
        // Invalid deposit address
        messageBox.setWindowTitle("Invalid sidechain deposit address!");
        messageBox.setText("Destination cannot be SIDECHAIN_WITHDRAWAL_RETURN_DEST, please choose another address and try again.");
        messageBox.exec();
        return;
    }

    if (nSidechainFromAddress != nSidechain) {
        // Invalid sidechain number in deposit address
        messageBox.setWindowTitle("Incorrect sidechain number in deposit address!");
        QString error = "The address you have entered is for a different sidechain than you have selected!\n\n";
        error += "Please check the address you have entered and try again.";
        messageBox.setText(error);
        messageBox.exec();
        return;
    }

    // Wallet policy: a destination that is no known address
    // format (Base58Check, bech32, 0x-hex) can never be paid by the sidechain.
    if (!IsPlausibleSidechainDestination(strDest)) {
        messageBox.setWindowTitle("Invalid sidechain deposit address!");
        QString error = "The sidechain address inside this deposit address is not a valid address.\n\n";
        error += "The sidechain could not pay it: your coins would stay locked in the sidechain escrow.\n";
        error += "Copy the deposit address from the sidechain wallet again.";
        messageBox.setText(error);
        messageBox.exec();
        return;
    }

    // Get fee and deposit amount
    const CAmount& nValue = ui->payAmount->value();
    const CAmount& nFee = ui->feeAmount->value();

    // Format strings for confirmation dialog
    std::string strSidechainName;
    {
        LOCK(cs_main);
        strSidechainName = scdb.GetSidechainName(nSidechain);
    }
    QString strSidechain = QString::fromStdString(strSidechainName);
    QString strValue = BitcoinUnits::formatWithUnit(BitcoinUnit::SKYDOGE, nValue, false, BitcoinUnits::separatorAlways);
    QString strFee = BitcoinUnits::formatWithUnit(BitcoinUnit::SKYDOGE, nFee, false, BitcoinUnits::separatorAlways);

    // Once we've made it to this point and validated what we can, show the
    // deposit confirmation dialog and check the result.
    // Note that GetConfirmed() will automatically reset the dialog
    depositConfirmationDialog->SetInfo(strSidechain, strValue, strFee);
    depositConfirmationDialog->exec();
    if (!depositConfirmationDialog->GetConfirmed())
        return;

#ifdef ENABLE_WALLET
    if (vpwallets.empty()) {
        messageBox.setWindowTitle("Wallet Error!");
        messageBox.setText("No active wallets to create the deposit.");
        messageBox.exec();
        return;
    }

    if (vpwallets[0]->IsLocked()) {
        // Locked wallet message box
        messageBox.setWindowTitle("Wallet locked!");
        messageBox.setText("Wallet must be unlocked to create sidechain deposit.");
        messageBox.exec();
        return;
    }

    // Block until the wallet has been updated with the latest chain tip
    vpwallets[0]->BlockUntilSyncedToCurrentChain();

    // Attempt to create the deposit
    CTransactionRef tx;
    std::string strFail = "";
    CScript sidechainScriptPubKey;
    bool fHaveScript;
    {
        LOCK(cs_main);
        fHaveScript = scdb.GetSidechainScript(nSidechain, sidechainScriptPubKey);
    }
    if (!fHaveScript) {
        // Invalid sidechain message box
        messageBox.setWindowTitle("Invalid Sidechain!");
        messageBox.setText("The sidechain you're trying to deposit to does not appear to be active!");
        messageBox.exec();
        return;
    }
    // Catch the wallet up before building the deposit. Done here, holding no
    // locks, rather than inside the wallet - from inside it deadlocks any
    // caller that already holds cs_main and cs_wallet.
    vpwallets[0]->BlockUntilSyncedToCurrentChain();

    if (!vpwallets[0]->CreateSidechainDeposit(tx, strFail, sidechainScriptPubKey, nSidechain, nValue, nFee, strDest)) {
        // Create transaction error message box
        messageBox.setWindowTitle("Creating deposit transaction failed!");
        QString createError = "Error creating transaction!\n\n";
        createError += QString::fromStdString(strFail);
        messageBox.setText(createError);
        messageBox.exec();
        return;
    }

    // Successful deposit message box
    messageBox.setWindowTitle("Deposit transaction created!");
    QString result = "Deposited to " + strSidechain;
    result += "\n";
    result += "txid: " + QString::fromStdString(tx->GetHash().ToString());
    result += "\n";
    result += "Amount deposited: ";
    result += BitcoinUnits::formatWithUnit(BitcoinUnit::SKYDOGE, nValue, false, BitcoinUnits::separatorAlways);
    messageBox.setText(result);
    messageBox.exec();

    // Cache recent deposit
    RecentDepositTableObject obj;
    obj.nSidechain = nSidechain;
    obj.amount = nValue;
    obj.txid = tx->GetHash();
    vRecentDepositCache.push_back(obj);

    // Update recent deposits table
    UpdateRecentDeposits();
#endif
}

void SidechainPage::on_pushButtonPaste_clicked()
{
    // Paste text from clipboard into recipient field
    ui->payTo->setText(QApplication::clipboard()->text());
}

void SidechainPage::on_pushButtonClear_clicked()
{
    ui->payTo->clear();
}

void SidechainPage::on_listWidgetSidechains_currentRowChanged(int nRow)
{
    if (nRow < 0 || nRow >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        return;

    nSelectedSidechain = nRow;

    // Format placeholder text (demo version)
    QString strAddress = "s";
    strAddress += QString::number(nRow);
    strAddress += "_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx_xxxxxx";

    ui->payTo->setPlaceholderText(strAddress);
}

void SidechainPage::on_listWidgetSidechains_doubleClicked(const QModelIndex& i)
{
    // On double click show sidechain details
    if (i.row() >= SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        return;

    Sidechain sidechain;
    {
        // scdb is move-assigned by ConnectBlock under cs_main; read it under the
        // lock, then release before showing the (blocking) details dialog.
        LOCK(cs_main);
        if (!scdb.GetSidechain(i.row(), sidechain))
            return;
    }

    SidechainDetailsDialog dialog(sidechain);
    dialog.exec();
}

void SidechainPage::on_tableViewWT_doubleClicked(const QModelIndex& index)
{
    int row = index.row();
    QString qHash = index.sibling(row, 5).data().toString();

    QMessageBox messageBox;
    messageBox.setWindowTitle("Failed to locate Withdrawal raw transaction!");

    uint256 hash = uint256S(qHash.toStdString());
    if (hash.IsNull()) {
        messageBox.setText("Invalid Withdrawal hash!");
        messageBox.exec();
        return;
    }

    CMutableTransaction mtx;
    bool fHaveWithdrawal;
    {
        // scdb is move-assigned by ConnectBlock under cs_main; read it under the
        // lock, then release before the (blocking) message/details dialogs.
        LOCK(cs_main);
        fHaveWithdrawal = scdb.GetCachedWithdrawalTx(hash, mtx);
    }
    if (!fHaveWithdrawal) {
        QString error;
        error += "Withdrawal not in cache!\n\n";
        error += "Try using the 'rebroadcastwithdrawaltx' RPC command on the sidechain.\n";
        messageBox.setText(error);
        messageBox.exec();
        return;
    }

    TxDetails detailsDialog;
    detailsDialog.SetTransaction(mtx);

    detailsDialog.exec();
}

bool SidechainPage::validateDepositAmount()
{
    if (!ui->payAmount->validate()) {
        ui->payAmount->setValid(false);
        return false;
    }

    // Sending a zero amount is invalid
    if (ui->payAmount->value(0) <= 0) {
        ui->payAmount->setValid(false);
        return false;
    }

    // Reject dust outputs:
    if (GUIUtil::isDust(ui->payTo->text(), ui->payAmount->value())) {
        ui->payAmount->setValid(false);
        return false;
    }

    // Reject deposits which cannot cover sidechain fee. A deposit of
    // exactly the fee pays nothing either, so <= (the message says "> fee").
    if (ui->payAmount->value() <= SIDECHAIN_DEPOSIT_FEE) {
        ui->payAmount->setValid(false);
        return false;
    }

    // Reject deposits which would net the user no payout on the sidechain
    if (GUIUtil::isDust(ui->payTo->text(), ui->payAmount->value() - SIDECHAIN_DEPOSIT_FEE)) {
        ui->payAmount->setValid(false);
        return false;
    }

    return true;
}

bool SidechainPage::validateFeeAmount()
{
    if (!ui->feeAmount->validate()) {
        ui->feeAmount->setValid(false);
        return false;
    }

    // Sending a zero amount is invalid
    if (ui->feeAmount->value(0) <= 0) {
        ui->feeAmount->setValid(false);
        return false;
    }

    // Reject dust outputs:
    if (GUIUtil::isDust(ui->payTo->text(), ui->feeAmount->value())) {
        ui->feeAmount->setValid(false);
        return false;
    }

    return true;
}

void SidechainPage::on_pushButtonAddRemove_clicked()
{
    ShowActivationDialog();
}

void SidechainPage::on_pushButtonWithdrawalVote_clicked()
{
    ShowSCDBDialog();
}

void SidechainPage::on_pushButtonWTDoubleClickHelp_clicked()
{
    QMessageBox::information(this, tr("Skydoge - information"),
        tr("If you have a sidechain full node, and have granted it RPC-access, "
           "then your mainchain node will periodically receive a cache of raw "
           "Withdrawal transactions. From this cache, the Withdrawal transaction-details can "
           "be obtained and displayed.\n\n"
           "If you do not have a sidechain full node connected, then you have no "
           "direct firsthand knowledge about Withdrawals. You do NOT know how much money "
           "the Withdrawal is withdrawing, nor where that money is trying to go, nor if "
           "the Withdrawal is sidechain-valid. Until the Withdrawal accumulates sufficient ACK-score, "
           "you will not even know if it is mainchain-valid.\n"),
        QMessageBox::Ok);
}

void SidechainPage::on_pushButtonRecentDepositHelp_clicked()
{
    QMessageBox::information(this, tr("Skydoge - information"),
        tr("Hello, from the creators of Skydoge! We wrote Skydoge "
           "(the software you are using right now), and we wrote you this "
           "message. \n\n"
           "But the sidechain software (ie, the software that "
           "you are trying to send your coins to) was (probably) written "
           "by someone else. As far as we know, they had no idea what "
           "they were doing! Perhaps your coins will be lost forever. "
           "Or perhaps they will not show up for a very long time. Or, "
           "perhaps (via clever scanning of the mempool) they will show "
           "up immediately. We don't know because we didn't write that "
           "software.\n\n"
           "But we can nonetheless give you our expert opinion: "
           "Skydoge Deposits likely require one mainchain confirmation, "
           "and one sidechain confirmation. Probably, this means that two "
           "Mainchain confirmations should do the trick.\n"),
        QMessageBox::Ok);
}

void SidechainPage::gotoWTPage()
{
    // Go to the Withdrawal table
    ui->tabWidget->setCurrentIndex(1);
}

void SidechainPage::numBlocksChanged()
{
    // This refresh runs on every numBlocksChanged signal. During sync the
    // validation thread holds cs_main for long stretches while connecting
    // blocks, so take it non-blocking and skip this refresh if the node is
    // busy; the next block signal retries once cs_main is free.
    TRY_LOCK(cs_main, lockMain);
    if (!lockMain)
        return;

    // TODO only update sidechain list when a sidechain is activated or
    // deactivated
    //
    // Update sidechain list
    std::vector<Sidechain> vSidechain = scdb.GetSidechains();
    SetupSidechainList(vSidechain);

    // Update recent deposits table. Take cs_wallet non-blocking too so the GUI
    // never stalls waiting on the wallet during catch-up; UpdateRecentDeposits
    // (and its LOCK2) then run safely under the already-held locks.
    if (!vpwallets.empty()) {
        TRY_LOCK(vpwallets[0]->cs_wallet, lockWallet);
        if (!lockWallet)
            return;

        UpdateRecentDeposits();
    }
}

void SidechainPage::ShowActivationDialog()
{
    activationDialog->show();
}

void SidechainPage::ShowSCDBDialog()
{
    scdbDialog->show();
    scdbDialog->UpdateOnShow();
}

void SidechainPage::UpdateRecentDeposits()
{
    if (!walletModel || !walletModel->getOptionsModel()
            || !walletModel->getAddressTableModel())
        return;

    if (vpwallets.empty() || vpwallets[0]->IsLocked())
        return;

    ui->tableWidgetRecentDeposits->setUpdatesEnabled(false);
    ui->tableWidgetRecentDeposits->setRowCount(0);

    int nDisplayUnit = walletModel->getOptionsModel()->getDisplayUnit();

    // Locks for GetDepthInMainchain()
    LOCK2(cs_main, vpwallets[0]->cs_wallet);

    // nRow is always 0, we are always inserting to the top of the table
    int nRow = 0;
    for (const RecentDepositTableObject& o : vRecentDepositCache) {
        ui->tableWidgetRecentDeposits->insertRow(nRow);

        // nSidechain
        QTableWidgetItem *itemSidechain = new QTableWidgetItem();
        itemSidechain->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        itemSidechain->setText(QString::number(o.nSidechain));
        itemSidechain->setFlags(itemSidechain->flags() & ~Qt::ItemIsEditable);
        ui->tableWidgetRecentDeposits->setItem(nRow, COLUMN_SIDECHAIN, itemSidechain);

        // amount
        QTableWidgetItem *itemAmount = new QTableWidgetItem();
        itemAmount->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        itemAmount->setText(BitcoinUnits::format(nDisplayUnit, o.amount));
        itemAmount->setFlags(itemAmount->flags() & ~Qt::ItemIsEditable);
        ui->tableWidgetRecentDeposits->setItem(nRow, COLUMN_AMOUNT, itemAmount);

        // Get number of confirmations from the wallet
        int nConf = -1;
        std::map<uint256, CWalletTx>::iterator mi = vpwallets[0]->mapWallet.find(o.txid);
        if (mi != vpwallets[0]->mapWallet.end())
            nConf = mi->second.GetDepthInMainChain();

        // confirmations
        QTableWidgetItem *itemConf = new QTableWidgetItem();
        itemConf->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        itemConf->setText(QString::number(nConf));
        itemConf->setFlags(itemConf->flags() & ~Qt::ItemIsEditable);
        ui->tableWidgetRecentDeposits->setItem(nRow, COLUMN_CONFIRMATIONS, itemConf);

        // Status
        QTableWidgetItem *itemStatus = new QTableWidgetItem();
        QString strStatus = "";
        if (nConf < 2)
            strStatus = "Not yet. Waiting for confirmations.";
        else
            strStatus = "Ready for SC processing!";
        itemStatus->setText(strStatus);
        itemStatus->setFlags(itemStatus->flags() & ~Qt::ItemIsEditable);
        ui->tableWidgetRecentDeposits->setItem(nRow, COLUMN_STATUS, itemStatus);
    }

    ui->tableWidgetRecentDeposits->setUpdatesEnabled(true);
}

QString FormatSidechainTitle(const QString& strSidechain, int nSidechain)
{
    QString str = "";

    if (strSidechain.isEmpty() || nSidechain < 0 || nSidechain > SIDECHAIN_ACTIVATION_MAX_ACTIVE)
        return str;

    str += QString::number(nSidechain);

    int nDigits = 1;
    while (nSidechain /= 10)
        nDigits++;

    if (nDigits == 1) {
        str += ":   ";
    }
    else
    if (nDigits == 2) {
        str += ":  ";
    }
    else
    if (nDigits == 3) {
        str += ": ";
    }

    str += strSidechain;

    // Cut number + name down to max 15 characters
    if (str.size() > 15) {
        str = str.left(12);
        str += "...";
    }

    // Make all titles the same length before we append the balance
    while (str.size() < 15)
        str.append(" ");

    return str;
}
