// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/mempooltablemodel.h>

#include <qt/skydogeunits.h>
#include <qt/guiutil.h>

#include <primitives/transaction.h>
#include <txmempool.h>
#include <utilmoneystr.h>
#include <validation.h>

#include <QString>

Q_DECLARE_METATYPE(MemPoolTableObject)

MemPoolTableModel::MemPoolTableModel(QObject *parent) :
    QAbstractTableModel(parent)
{
    nTx = 0;
    nBytes = 0;
}

int MemPoolTableModel::rowCount(const QModelIndex & /*parent*/) const
{
    return model.size();
}

int MemPoolTableModel::columnCount(const QModelIndex & /*parent*/) const
{
    return 4;
}

QVariant MemPoolTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return false;
    }

    int row = index.row();
    int col = index.column();

    if (!model.at(row).canConvert<MemPoolTableObject>())
        return QVariant();

    MemPoolTableObject object = model.at(row).value<MemPoolTableObject>();

    switch (role) {
    case Qt::DisplayRole:
    {
        // txid
        if (col == 0) {
            return QString::fromStdString(object.txid.ToString()).left(21) + "...";
        }
        // Time
        if (col == 1) {
            return object.time;
        }
        // Value
        if (col == 2) {
            return BitcoinUnits::formatWithUnit(BitcoinUnit::SKYDOGE, object.value, false, BitcoinUnits::separatorAlways);
        }
        // Feerate
        if (col == 3) {
            QString rate = BitcoinUnits::formatWithUnit(BitcoinUnit::SKYDOGE, object.feeRate.GetFeePerK(), false, BitcoinUnits::separatorAlways);
            rate += "/kB";
            return rate;
        }
    }
    case Qt::TextAlignmentRole:
    {
        // txid
        if (col == 0) {
            return int(Qt::AlignLeft | Qt::AlignVCenter);
        }
        // Time
        if (col == 1) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // Value
        if (col == 2) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // Feerate
        if (col == 3) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
    }
    case HashRole:
    {
        return QString::fromStdString(object.txid.ToString());
    }
    }
    return QVariant();
}

QVariant MemPoolTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole) {
        if (orientation == Qt::Horizontal) {
            switch (section) {
            case 0:
                return QString("TxID");
            case 1:
                return QString("Time");
            case 2:
                return QString("Value");
            case 3:
                return QString("Fee");
            }
        }
    }
    return QVariant();
}

void MemPoolTableModel::updateModel()
{
    // Clear old data
    beginResetModel();
    model.clear();
    endResetModel();

    // Get 6 most recent mempool entries
    std::vector<TxMempoolInfo> vInfo = mempool.InfoRecent(6);

    beginInsertRows(QModelIndex(), model.size(), model.size() + vInfo.size());
    for (const TxMempoolInfo& i : vInfo) {
        if (!i.tx)
            continue;

        MemPoolTableObject object;
        object.txid = i.tx->GetHash();
        object.time = GUIUtil::timeStr(i.nTime);
        object.value = i.tx->GetValueOut();
        object.feeRate = i.feeRate;

        model.append(QVariant::fromValue(object));
    }
    endInsertRows();
}

void MemPoolTableModel::memPoolSizeChanged(long nTxIn, size_t nBytesIn)
{
    if (nTxIn != nTx || nBytesIn != nBytes) {
        nTx = nTxIn;
        nBytes = nBytesIn;

        updateModel();
    }
}

bool MemPoolTableModel::GetTx(const uint256& txid, CTransactionRef& tx) const
{
    if (!mempool.exists(txid))
        return false;

    tx = mempool.get(txid);
    return true;
}
