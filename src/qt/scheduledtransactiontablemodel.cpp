// Copyright (c) 2022- The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/scheduledtransactiontablemodel.h>

#include <QMetaType>
#include <QVariant>

#include <qt/clientmodel.h>

#include <uint256.h>
#include <wallet/wallet.h>

Q_DECLARE_METATYPE(ScheduledTableObject)

ScheduledTransactionTableModel::ScheduledTransactionTableModel(QObject *parent) :
    QAbstractTableModel(parent)
{
}

int ScheduledTransactionTableModel::rowCount(const QModelIndex & /*parent*/) const
{
    return model.size();
}

int ScheduledTransactionTableModel::columnCount(const QModelIndex & /*parent*/) const
{
    return 2;
}

QVariant ScheduledTransactionTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return false;
    }

    int row = index.row();
    int col = index.column();

    if (!model.at(row).canConvert<ScheduledTableObject>())
        return QVariant();

    ScheduledTableObject object = model.at(row).value<ScheduledTableObject>();

    switch (role) {
    case Qt::DisplayRole:
    {
        // TxID
        if (col == 0) {
            return object.txid;
        }
        // Time
        if (col == 1) {
            return object.time;
        }
    }
    }
    return QVariant();
}

QVariant ScheduledTransactionTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole) {
        if (orientation == Qt::Horizontal) {
            switch (section) {
            case 0:
                return QString("TxID");
            case 1:
                return QString("Time");
            }
        }
    }
    return QVariant();
}

void ScheduledTransactionTableModel::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if (model)
    {
        connect(model, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)),
                this, SLOT(UpdateModel()));

        UpdateModel();
    }
}

void ScheduledTransactionTableModel::UpdateModel()
{
    if (vpwallets.empty())
        return;

    if (vpwallets[0]->IsLocked())
        return;

    std::vector<ScheduledTransaction> vScheduled;
    {
        LOCK(vpwallets[0]->cs_wallet);
        vScheduled = vpwallets[0]->GetScheduled();
    }

    beginResetModel();
    model.clear();
    endResetModel();

    beginInsertRows(QModelIndex(), 0, vScheduled.size());
    for (const ScheduledTransaction& tx : vScheduled) {
        ScheduledTableObject object;

        object.txid = QString::fromStdString(tx.wtxid.ToString());
        object.time = QString::fromStdString(tx.strTime);

        model.append(QVariant::fromValue(object));
    }
    endInsertRows();
}

bool ScheduledTransactionTableModel::GetTxidAtRow(int row, uint256& txid) const
{
    if (row >= model.size())
        return false;

    if (!model[row].canConvert<ScheduledTableObject>())
        return false;

    ScheduledTableObject object = model[row].value<ScheduledTableObject>();

    txid = uint256S(object.txid.toStdString());

    return true;
}
