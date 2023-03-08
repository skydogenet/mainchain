// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/opreturndialog.h>
#include <qt/forms/ui_opreturndialog.h>

#include <qt/clientmodel.h>
#include <qt/createopreturndialog.h>
#include <qt/decodeviewdialog.h>
#include <qt/guiutil.h>
#include <qt/opreturntablemodel.h>
#include <qt/platformstyle.h>

#include <QMenu>
#include <QMessageBox>
#include <QPoint>
#include <QScrollBar>
#include <QSortFilterProxyModel>

OPReturnDialog::OPReturnDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::OPReturnDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    createOPReturnDialog = new CreateOPReturnDialog(_platformStyle, this);
    opReturnModel = new OPReturnTableModel(this);

    proxyModel = new QSortFilterProxyModel(this);
    proxyModel->setSourceModel(opReturnModel);
    proxyModel->setSortRole(Qt::EditRole);

    ui->tableView->setModel(proxyModel);

    // Resize cells (in a backwards compatible way)
#if QT_VERSION < 0x050000
    ui->tableView->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
#else
    ui->tableView->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
#endif

    // Stretch last section
    ui->tableView->horizontalHeader()->setStretchLastSection(true);

    // Hide vertical header
    ui->tableView->verticalHeader()->setVisible(false);

    // Left align the horizontal header text
    ui->tableView->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);

    // Set horizontal scroll speed to per 3 pixels (very smooth, default is awful)
    ui->tableView->horizontalHeader()->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->tableView->horizontalHeader()->horizontalScrollBar()->setSingleStep(3); // 3 Pixels

    // Disable word wrap
    ui->tableView->setWordWrap(false);

    // Select rows
    ui->tableView->setSelectionBehavior(QAbstractItemView::SelectRows);

    // Apply custom context menu
    ui->tableView->setContextMenuPolicy(Qt::CustomContextMenu);

    QAction *showDetailsAction = new QAction(tr("Show full data decode"), this);
    QAction *copyDecodeAction = new QAction(tr("Copy decode"), this);
    QAction *copyHexAction = new QAction(tr("Copy hex"), this);
    contextMenu = new QMenu(this);
    contextMenu->setObjectName("contextMenuOPReturn");
    contextMenu->addAction(showDetailsAction);
    contextMenu->addAction(copyDecodeAction);
    contextMenu->addAction(copyHexAction);

    // Connect context menus
    connect(ui->tableView, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
    connect(showDetailsAction, SIGNAL(triggered()), this, SLOT(showDetails()));
    connect(copyDecodeAction, SIGNAL(triggered()), this, SLOT(copyDecode()));
    connect(copyHexAction, SIGNAL(triggered()), this, SLOT(copyHex()));

    ui->pushButtonCreate->setIcon(platformStyle->SingleColorIcon(":/icons/add"));

    opReturnModel->setDays(ui->spinBoxDays->value());

    ui->tableView->setSortingEnabled(true);
    ui->tableView->sortByColumn(0, Qt::DescendingOrder);

    connect(this, SIGNAL(UpdateTable()), opReturnModel, SLOT(UpdateModel()));
}

OPReturnDialog::~OPReturnDialog()
{
    delete ui;
}

void OPReturnDialog::setClientModel(ClientModel *model)
{
    if (model)
    {
        connect(model, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)),
                this, SLOT(numBlocksChanged(int, QDateTime)));
    }
}

void OPReturnDialog::on_tableView_doubleClicked(const QModelIndex& index)
{
    if (!index.isValid())
        return;

    if (!platformStyle)
        return;

    QString strDecode = index.data(OPReturnTableModel::DecodeRole).toString();
    QString strHex = index.data(OPReturnTableModel::HexRole).toString();

    DecodeViewDialog dialog;
    dialog.SetPlatformStyle(platformStyle);
    dialog.SetData(strDecode, strHex, "OP_RETURN Graffiti: ");
    dialog.exec();
}

void OPReturnDialog::contextualMenu(const QPoint &point)
{
    QModelIndex index = ui->tableView->indexAt(point);
    if (index.isValid())
        contextMenu->popup(ui->tableView->viewport()->mapToGlobal(point));
}

void OPReturnDialog::showDetails()
{
    if (!ui->tableView->selectionModel())
        return;

    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if (!selection.isEmpty())
        on_tableView_doubleClicked(selection.front());
}

void OPReturnDialog::copyDecode()
{
    if (!ui->tableView->selectionModel())
        return;

    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if (selection.isEmpty())
        return;

    QModelIndex index = selection.front();
    if (!index.isValid())
        return;

    QString strDecode = index.data(OPReturnTableModel::DecodeRole).toString();

    GUIUtil::setClipboard(strDecode);
}

void OPReturnDialog::copyHex()
{
    if (!ui->tableView->selectionModel())
        return;

    QModelIndexList selection = ui->tableView->selectionModel()->selectedRows();
    if (selection.isEmpty())
        return;

    QModelIndex index = selection.front();
    if (!index.isValid())
        return;

    QString strHex = index.data(OPReturnTableModel::HexRole).toString();

    GUIUtil::setClipboard(strHex);
}

void OPReturnDialog::on_pushButtonCreate_clicked()
{
    createOPReturnDialog->show();
}

void OPReturnDialog::on_spinBoxDays_editingFinished()
{
    opReturnModel->setDays(ui->spinBoxDays->value());
}

void OPReturnDialog::updateOnShow()
{
    Q_EMIT(UpdateTable());
}

void OPReturnDialog::numBlocksChanged(int nHeight, const QDateTime& time)
{
    if (!clientModel)
        return;

    if (clientModel->inInitialBlockDownload())
        return;

    // Update the table model if the dialog is open
    if (this->isVisible())
        Q_EMIT(UpdateTable());
}
