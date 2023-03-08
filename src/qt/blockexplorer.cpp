// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/blockexplorer.h>
#include <qt/forms/ui_blockexplorer.h>

#include <QDateTime>
#include <QMessageBox>
#include <QScrollBar>
#include <QString>

#include <qt/blockexplorertablemodel.h>
#include <qt/blockindexdetailsdialog.h>
#include <qt/clientmodel.h>
#include <qt/platformstyle.h>

#include <chain.h>

BlockExplorer::BlockExplorer(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::BlockExplorer),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    blockExplorerModel = new BlockExplorerTableModel(this);
    blockIndexDialog = new BlockIndexDetailsDialog(this);

    ui->tableViewBlocks->setModel(blockExplorerModel);

    // Table style
    ui->tableViewBlocks->horizontalHeader()->setVisible(false);

    ui->tableViewBlocks->setRowHeight(0, 100);
    ui->tableViewBlocks->setRowHeight(1, 50);
    ui->tableViewBlocks->setRowHeight(2, 50);
    ui->tableViewBlocks->setRowHeight(3, 50);
    ui->tableViewBlocks->setRowHeight(4, 50);
    ui->tableViewBlocks->setRowHeight(5, 50);

    // Resize cells (in a backwards compatible way)
#if QT_VERSION < 0x050000
    ui->tableViewBlocks->horizontalHeader()->setResizeMode(QHeaderView::ResizeToContents);
#else
    ui->tableViewBlocks->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);
#endif

    // Change scrolling speed
    ui->tableViewBlocks->horizontalHeader()->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->tableViewBlocks->horizontalHeader()->horizontalScrollBar()->setSingleStep(3); // 3 Pixels

    QString style;
    style += "QTableView::item { border-left: 2px solid black; ";
    style += "border-right: 2px solid black;}\n";
    style += "QTableView::item::selected { background-color: rgb(0, 139, 139, 180); }";

    ui->tableViewBlocks->setStyleSheet(style);

    connect(this, SIGNAL(UpdateTable()), blockExplorerModel, SLOT(UpdateModel()));
    connect(blockExplorerModel, SIGNAL(columnsInserted(QModelIndex, int, int)), this, SLOT(scrollRight()));
}

BlockExplorer::~BlockExplorer()
{
    delete ui;
}

void BlockExplorer::on_pushButtonSearch_clicked()
{
    Search();
}

void BlockExplorer::numBlocksChanged(int nHeight, const QDateTime& time)
{
    ui->labelNumBlocks->setText(QString::number(nHeight));
    ui->labelBlockTime->setText(time.toString("dd MMMM yyyy hh:mm"));

    // Update the table model if the explorer is open
    if (this->isVisible())
        Q_EMIT(UpdateTable());
}

void BlockExplorer::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        connect(model, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)),
                this, SLOT(numBlocksChanged(int, QDateTime)));

        // Display current block time & height
        CBlockIndex *pindex = blockExplorerModel->GetTip();
        if (pindex) {
            int nHeight = pindex->nHeight;
            QDateTime time = QDateTime::fromTime_t(pindex->GetBlockTime());

            ui->labelNumBlocks->setText(QString::number(nHeight));
            ui->labelBlockTime->setText(time.toString("dd MMMM yyyy hh:mm"));
        }
    }
}

void BlockExplorer::on_tableViewBlocks_doubleClicked(const QModelIndex& index)
{
    if (!index.isValid())
        return;

    QMessageBox messageBox;

    QString strHash = index.data(BlockExplorerTableModel::HashRole).toString();
    uint256 hash = uint256S(strHash.toStdString());

    // TODO update error message
    if (hash.IsNull()) {
        messageBox.setWindowTitle("Error - invalid block hash!");
        messageBox.setText("Block hash is null!\n");
        messageBox.exec();
        return;
    }

    // TODO update error message
    CBlockIndex* pBlockIndex = blockExplorerModel->GetBlockIndex(hash);
    if (!pBlockIndex) {
        messageBox.setWindowTitle("Error - couldn't locate block index!");
        messageBox.setText("Invalid block index!\n");
        messageBox.exec();
        return;
    }

    blockIndexDialog->SetBlockIndex(pBlockIndex);
    blockIndexDialog->show();
}

void BlockExplorer::scrollRight()
{
    int nMax = ui->tableViewBlocks->horizontalScrollBar()->maximum();
    ui->tableViewBlocks->horizontalScrollBar()->setValue(nMax);
}

void BlockExplorer::updateOnShow()
{
    Q_EMIT(UpdateTable());
}

void BlockExplorer::on_lineEditSearch_returnPressed()
{
    Search();
}

void BlockExplorer::Search()
{
    QString input = ui->lineEditSearch->text();

    CBlockIndex *pindex = nullptr;

    // Check if the input is base 10
    bool fOk = false;
    int nValue = input.toInt(&fOk, 10);
    if (fOk) {
        // Value was a base 10 number, so look up block index by height
        pindex = blockExplorerModel->GetBlockIndex(nValue);
    } else {
        uint256 hash = uint256S(input.toStdString());
        if (!hash.IsNull()) {
            pindex = blockExplorerModel->GetBlockIndex(hash);
        }
    }

    if (!pindex) {
        // Show error message
        QMessageBox messageBox;
        messageBox.setWindowTitle("Error - failed to locate block!");
        messageBox.setText("Block hash or height is invalid!\n");
        messageBox.exec();
        return;
    }

    blockIndexDialog->SetBlockIndex(pindex);
    blockIndexDialog->show();
}
