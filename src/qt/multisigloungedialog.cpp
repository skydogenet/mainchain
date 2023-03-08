// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/multisigloungedialog.h>
#include <qt/forms/ui_multisigloungedialog.h>

#include <qt/guiutil.h>
#include <qt/multisigdialog.h>
#include <qt/multisigdetailsdialog.h>
#include <qt/platformstyle.h>

#include <QCheckBox>
#include <QMessageBox>
#include <QMenu>
#include <QString>

#include <addressbook.h>
#include <amount.h>
#include <base58.h>
#include <core_io.h>
#include <pubkey.h>
#include <script/script.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h>
#include <validation.h>

MultisigLoungeDialog::MultisigLoungeDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MultisigLoungeDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    // Setup partner table
    ui->tableWidgetPartner->setColumnCount(3);
    ui->tableWidgetPartner->setHorizontalHeaderLabels(
                QStringList() << "" << "Name" << "PubKey");
    ui->tableWidgetPartner->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);

    ui->tableWidgetPartner->setColumnWidth(COLUMN_CHECKBOX, COLUMN_CHECKBOX_WIDTH);
    ui->tableWidgetPartner->setColumnWidth(COLUMN_NAME, COLUMN_NAME_WIDTH);
    ui->tableWidgetPartner->setColumnWidth(COLUMN_PUBKEY, COLUMN_PUBKEY_WIDTH);

    ui->tableWidgetPartner->horizontalHeader()->setStretchLastSection(true);

    // Setup multisig table
    ui->tableWidgetMultisig->setColumnCount(3);
    ui->tableWidgetMultisig->setHorizontalHeaderLabels(
                QStringList() << "#Required" << "P2SH Address" << "Balance");
    ui->tableWidgetMultisig->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);

    ui->tableWidgetMultisig->setColumnWidth(COLUMN_M, COLUMN_M_WIDTH);
    ui->tableWidgetMultisig->setColumnWidth(COLUMN_ADDRESS, COLUMN_ADDRESS_WIDTH);

    ui->tableWidgetMultisig->horizontalHeader()->setStretchLastSection(true);

    // Select rows
    ui->tableWidgetMultisig->setSelectionBehavior(QAbstractItemView::SelectRows);

    // Setup multisig table context menu

    ui->tableWidgetMultisig->setContextMenuPolicy(Qt::CustomContextMenu);

    QAction *transferAction = new QAction(tr("Start Transfer"), this);
    QAction *detailsAction = new QAction(tr("Show Details"), this);

    contextMenuMultisig = new QMenu(this);
    contextMenuMultisig->setObjectName("contextMenuMultisig");
    contextMenuMultisig->addAction(transferAction);
    contextMenuMultisig->addAction(detailsAction);

    // Connect context menus
    connect(ui->tableWidgetMultisig, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(multisigContextualMenu(QPoint)));
    connect(transferAction, SIGNAL(triggered()), this, SLOT(on_multisigTransferAction_clicked()));
    connect(detailsAction, SIGNAL(triggered()), this, SLOT(on_multisigDetailsAction_clicked()));

    multisigDialog = new MultisigDialog(platformStyle, this);
}

MultisigLoungeDialog::~MultisigLoungeDialog()
{
    delete ui;
}

void MultisigLoungeDialog::UpdateOnShow()
{
    UpdatePartners();
}

void MultisigLoungeDialog::on_pushButtonAdd_clicked()
{
    // Add partner info to cache

    QString name = ui->lineEditName->text();
    QString pubkey = ui->lineEditPub->text();

    if (name.isEmpty()) {
        QMessageBox::critical(this, tr("Drivechain - error"),
            tr("Multisig partner must have a name!\n"),
            QMessageBox::Ok);
        return;
    }

    if (!IsHex(pubkey.toStdString())) {
        QMessageBox::critical(this, tr("Drivechain - error"),
            tr("Key must be Hex!\n"),
            QMessageBox::Ok);
        return;
    }

    if (pubkey.size() != 66) {
        QMessageBox::critical(this, tr("Drivechain - error"),
            tr("Invalid key size!\n"),
            QMessageBox::Ok);
        return;
    }

    CPubKey pubKey(ParseHex(pubkey.toStdString()));
    if (!pubKey.IsFullyValid()) {
        QMessageBox::critical(this, tr("Drivechain - error"),
            tr("Invalid key!\n"),
            QMessageBox::Ok);
        return;
    }

    PartnerTableObject obj;
    obj.name = name;
    obj.pubkey = pubkey;

    AddPartner(obj);

    UpdateMultisigs();

    // Add to address book
    MultisigPartner partner;
    partner.strName = name.toStdString();
    partner.strPubKey = pubkey.toStdString();
    addressBook.AddMultisigPartner(partner);
}

void MultisigLoungeDialog::UpdatePartners()
{
    ui->tableWidgetPartner->setUpdatesEnabled(false);
    ui->tableWidgetPartner->setRowCount(0);

    std::vector<MultisigPartner> vPartner = addressBook.GetMultisigPartners();
    for (const MultisigPartner& p : vPartner) {
        PartnerTableObject obj;
        obj.name = QString::fromStdString(p.strName);
        obj.pubkey = QString::fromStdString(p.strPubKey);
        AddPartner(obj);
    }

    ui->tableWidgetPartner->setUpdatesEnabled(true);
}

void MultisigLoungeDialog::UpdateMultisigs()
{
    // Update list of multsig scripts and info based on partner list
    if (vPartner.empty())
        return;

    std::vector<CPubKey> vPubKey;
    for (size_t i = 0; i < vPartner.size(); i++ /*const PartnerTableObject& partner : vPartner*/) {
        if ((int) i >= ui->tableWidgetPartner->rowCount())
            return;

        // Skip if not checked
        bool fChecked = ui->tableWidgetPartner->item(i, COLUMN_CHECKBOX)->checkState() == Qt::Checked;
        if (!fChecked)
            continue;

        std::string strKey = vPartner[i].pubkey.toStdString();
        if (strKey.empty())
            continue;

        if (!IsHex(strKey))
            return;

        if (strKey.size() != 66)
            return;

        CPubKey pubKey(ParseHex(strKey));
        if (!pubKey.IsFullyValid())
            return;

        vPubKey.push_back(pubKey);
    }

    if (vPubKey.size() > 16) {
        QMessageBox::critical(this, tr("Drivechain - error"),
            tr("Too many keys (>16)!\n"),
            QMessageBox::Ok);
        return;
    }

    ui->tableWidgetMultisig->setUpdatesEnabled(false);
    ui->tableWidgetMultisig->setRowCount(0);

    // Create 1 through nKeys m of n
    int nRow = 0;
    for (size_t i = 1; i <= vPubKey.size(); i++) {
        ui->tableWidgetMultisig->insertRow(nRow);

        // Create multisig script (P2SH inner script / redeem script)
        CScript script = GetScriptForMultisig(i /* nReq */, vPubKey);
        CScriptID id(script);

        std::string strDestination = EncodeDestination(id);
        std::string strRedeemScript = HexStr(script.begin(), script.end());

        CScript scriptP2SH = GetScriptForDestination(id);

        QString details;
        details += "P2SH Address:\n" + QString::fromStdString(strDestination) + "\n\n";
        details += "P2SH Script Hex:\n" + QString::fromStdString(HexStr(scriptP2SH)) + "\n\n";
        details += "P2SH Script:\n" + QString::fromStdString(ScriptToAsmStr(scriptP2SH)) + "\n\n";
        details += "Redeem Script Hex:\n" + QString::fromStdString(strRedeemScript) + "\n\n";
        details += "Redeem Script:\n" + QString::fromStdString(ScriptToAsmStr(script)) + "\n\n";

        details += "Public key order:\n";
        for (size_t i = 0; i < vPubKey.size(); i++)
            details += QString::fromStdString(HexStr(vPubKey[i].begin(), vPubKey[i].end())) + "\n";

        details += "\nKeys required: " + QString::number(i) + " / " + QString::number(vPubKey.size()) + "\n";

        QString m = QString::number(i) + "/" + QString::number(vPubKey.size());

        // M
        QTableWidgetItem *itemM = new QTableWidgetItem();
        itemM->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        itemM->setText(m);
        itemM->setFlags(itemM->flags() & ~Qt::ItemIsEditable);
        itemM->setData(DetailsRole, details);
        ui->tableWidgetMultisig->setItem(nRow, COLUMN_M, itemM);

        // Address
        QTableWidgetItem *itemAddr = new QTableWidgetItem();
        itemAddr->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
        itemAddr->setText(QString::fromStdString(strDestination));
        itemAddr->setFlags(itemAddr->flags() & ~Qt::ItemIsEditable);
        ui->tableWidgetMultisig->setItem(nRow, COLUMN_ADDRESS, itemAddr);

        // Balance
        QTableWidgetItem *itemBalance = new QTableWidgetItem();
        itemBalance->setTextAlignment(Qt::AlignRight | Qt::AlignVCenter);
        itemBalance->setText(QString::fromStdString(FormatMoney(CAmount(0))));
        itemBalance->setFlags(itemBalance->flags() & ~Qt::ItemIsEditable);
        ui->tableWidgetMultisig->setItem(nRow, COLUMN_BALANCE, itemBalance);

        nRow++;
    }

    ui->tableWidgetMultisig->setUpdatesEnabled(true);

    ui->labelN->setText(QString::number(vPubKey.size()));
}

void MultisigLoungeDialog::multisigContextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableWidgetMultisig->indexAt(point);
    if (index.isValid())
        contextMenuMultisig->popup(ui->tableWidgetMultisig->viewport()->mapToGlobal(point));
}

void MultisigLoungeDialog::on_multisigTransferAction_clicked()
{
    if (!ui->tableWidgetMultisig->selectionModel())
        return;

    QModelIndexList selection = ui->tableWidgetMultisig->selectionModel()->selectedRows();
    if (selection.isEmpty())
        return;
}

void MultisigLoungeDialog::on_multisigDetailsAction_clicked()
{
    if (!ui->tableWidgetMultisig->selectionModel())
        return;

    QModelIndexList selection = ui->tableWidgetMultisig->selectionModel()->selectedRows();
    if (selection.isEmpty())
        return;

    QTableWidgetItem *itemM = ui->tableWidgetMultisig->item(selection[0].row(), COLUMN_M);
    QString details = itemM->data(DetailsRole).toString();

    MultisigDetailsDialog dialog;
    dialog.SetDetails(details);
    dialog.exec();
}

void MultisigLoungeDialog::on_pushButtonMultisigDialog_clicked()
{
    multisigDialog->show();
}

void MultisigLoungeDialog::on_tableWidgetPartner_itemChanged(QTableWidgetItem*)
{
    UpdateMultisigs();
}

void MultisigLoungeDialog::AddPartner(const PartnerTableObject& obj)
{
    vPartner.push_back(obj);

    // Show partner on table

    int nRow = ui->tableWidgetPartner->rowCount();

    ui->tableWidgetPartner->setUpdatesEnabled(false);
    ui->tableWidgetPartner->insertRow(nRow);

    // Checkbox
    QTableWidgetItem *itemCheck = new QTableWidgetItem();
    itemCheck->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);
    itemCheck->setCheckState(Qt::Unchecked);
    ui->tableWidgetPartner->setItem(nRow, COLUMN_CHECKBOX, itemCheck);

    // Name
    QTableWidgetItem *itemName = new QTableWidgetItem();
    itemName->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    itemName->setText(QString("$") + obj.name);
    itemName->setFlags(itemName->flags() & ~Qt::ItemIsEditable);
    ui->tableWidgetPartner->setItem(nRow, COLUMN_NAME, itemName);

    // PubKey
    QTableWidgetItem *itemPub = new QTableWidgetItem();
    itemPub->setTextAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    itemPub->setText(obj.pubkey);
    itemPub->setFlags(itemName->flags() & ~Qt::ItemIsEditable);
    ui->tableWidgetPartner->setItem(nRow, COLUMN_PUBKEY, itemPub);

    ui->tableWidgetPartner->setUpdatesEnabled(true);
}
