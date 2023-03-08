// Copyright (c) 2020-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/sidechainactivationdialog.h>
#include <qt/forms/ui_sidechainactivationdialog.h>

#include <qt/platformstyle.h>
#include <qt/sidechainactivationtablemodel.h>
#include <qt/sidechainescrowtablemodel.h>
#include <qt/sidechainproposaldialog.h>

#include <QMessageBox>
#include <QScrollBar>

#include <sidechain.h>
#include <sidechaindb.h>
#include <validation.h>

SidechainActivationDialog::SidechainActivationDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SidechainActivationDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    activationModel = new SidechainActivationTableModel(this);

    ui->tableViewActivation->setModel(activationModel);
    // Don't stretch last cell of horizontal header
    ui->tableViewActivation->horizontalHeader()->setStretchLastSection(false);
    // Hide vertical header
    ui->tableViewActivation->verticalHeader()->setVisible(false);
    // Left align the horizontal header text
    ui->tableViewActivation->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
    // Set horizontal scroll speed to per 3 pixels (very smooth, default is awful)
    ui->tableViewActivation->horizontalHeader()->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->tableViewActivation->horizontalHeader()->horizontalScrollBar()->setSingleStep(3); // 3 Pixels
    // Select entire row
    ui->tableViewActivation->setSelectionBehavior(QAbstractItemView::SelectRows);

    if (escrowModel)
        delete escrowModel;

    // Initialize table models
    escrowModel = new SidechainEscrowTableModel(this);

    // Add models to table views
    ui->tableViewEscrow->setModel(escrowModel);

    // Resize cells (in a backwards compatible way)
#if QT_VERSION < 0x050000
    ui->tableViewEscrow->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
#else
    ui->tableViewEscrow->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
#endif

    // Don't stretch last cell of horizontal header
    ui->tableViewEscrow->horizontalHeader()->setStretchLastSection(false);

    // Hide vertical header
    ui->tableViewEscrow->verticalHeader()->setVisible(false);

    // Left align the horizontal header text
    ui->tableViewEscrow->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);

    // Set horizontal scroll speed to per 3 pixels (very smooth, default is awful)
    ui->tableViewEscrow->horizontalHeader()->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->tableViewEscrow->horizontalHeader()->horizontalScrollBar()->setSingleStep(3); // 3 Pixels

    // Disable word wrap
    ui->tableViewEscrow->setWordWrap(false);

    proposalDialog = new SidechainProposalDialog(platformStyle);
    proposalDialog->setParent(this, Qt::Window);

    ui->pushButtonActivate->setIcon(platformStyle->SingleColorIcon(":/icons/transaction_confirmed"));
    ui->pushButtonReject->setIcon(platformStyle->SingleColorIcon(":/icons/transaction_conflicted"));
    ui->pushButtonHelp->setIcon(platformStyle->SingleColorIcon(":/icons/transaction_0"));
    ui->pushButtonCreate->setIcon(platformStyle->SingleColorIcon(":/icons/add"));
}

SidechainActivationDialog::~SidechainActivationDialog()
{
    delete ui;
}

void SidechainActivationDialog::on_pushButtonActivate_clicked()
{
    QModelIndexList selected = ui->tableViewActivation->selectionModel()->selectedIndexes();

    for (int i = 0; i < selected.size(); i++) {
        uint256 hash;
        if (activationModel->GetHashAtRow(selected[i].row(), hash))
            scdb.CacheSidechainHashToAck(hash);
    }
}

void SidechainActivationDialog::on_pushButtonReject_clicked()
{
    QModelIndexList selected = ui->tableViewActivation->selectionModel()->selectedIndexes();

    for (int i = 0; i < selected.size(); i++) {
        uint256 hash;
        if (activationModel->GetHashAtRow(selected[i].row(), hash))
            scdb.RemoveSidechainHashToAck(hash);
    }
}

void SidechainActivationDialog::on_pushButtonHelp_clicked()
{
    // TODO move text into static const
    QMessageBox::information(this, tr("Drivechain - information"),
        tr("Sidechain activation signalling:\n\n"
           "Use this page to ACK (acknowledgement) or NACK "
           "(negative-acknowledgement) sidechains.\n\n"
           "Set ACK to activate a proposed sidechain, and NACK to reject a "
           "proposed sidechain.\n\n"
           "Once set, the chosen signal will be included in blocks mined by "
           "this node."),
        QMessageBox::Ok);
}

void SidechainActivationDialog::on_pushButtonCreate_clicked()
{
    proposalDialog->show();
}
