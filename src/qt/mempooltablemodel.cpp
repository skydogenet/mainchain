// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/mempooltablemodel.h>

#include <qt/skydogeunits.h>
#include <qt/clientmodel.h>
#include <qt/optionsmodel.h>
#include <qt/guiutil.h>

#include <primitives/transaction.h>
#include <txmempool.h>
#include <utilmoneystr.h>
#include <validation.h>

#include <QDateTime>
#include <QLocale>
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
    return 6;
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
        // Time
        if (col == 0) {
            return object.time;
        }
        // Value
        if (col == 1) {
            return QString::fromStdString(FormatMoney(object.value));
        }
        // Value USD
        if (col == 2) {
// old DC
            //return BitcoinUnits::formatWithUnit(BitcoinUnit::SKYDOGE, object.value, false, BitcoinUnits::separatorAlways);
            return "$" + QLocale(QLocale::English).toString(ConvertToFiat(object.value, nUSDBTC), 'f', 0);
        }
        // sats / byte
        if (col == 3) {
// old DC
            //QString rate = BitcoinUnits::formatWithUnit(BitcoinUnit::SKYDOGE, object.feeRate.GetFeePerK(), false, BitcoinUnits::separatorAlways);
            //rate += "/kB";
            //return rate;
            return QString::number(object.feeRate.GetFeePerB());
        }
        // Total fee in USD
        // txid
        if (col == 4) {
            return "$" + QLocale(QLocale::English).toString(ConvertToFiat(object.fee, nUSDBTC), 'f', 2);
        }
        if (col == 5) {
            return QString::fromStdString(object.txid.ToString()).left(21) + "...";
        }
    }
    case Qt::TextAlignmentRole:
    {
        // Time
        if (col == 0) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // Value
        if (col == 1) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // Value USD
        if (col == 2) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // Sats / byte
        if (col == 3) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // Fee in USD
        if (col == 4) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // txid
        if (col == 5) {
            return int(Qt::AlignLeft | Qt::AlignVCenter);
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
                return QString("Time");
            case 1:
                return QString("BTC");
            case 2:
                return QString("$");
            case 3:
                return QString("Sat/vB");
            case 4:
                return QString("Fee $");
            case 5:
                return QString("TxID");
            }
        }
    }
    return QVariant();
}

void MemPoolTableModel::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    OptionsModel* optionsModel = model->getOptionsModel();

    connect(optionsModel, SIGNAL(usdBTCChanged(int)),
            this, SLOT(setUSDBTC(int)));

    setUSDBTC(optionsModel->getUSDBTC());
}

void MemPoolTableModel::updateModel()
{
    if (!clientModel)
        return;

    if (clientModel->inInitialBlockDownload())
        return;

    // Get recent mempool entries
    std::vector<TxMempoolInfo> vInfo = mempool.InfoRecent(10);

    // Check if there is a transaction that we already know.
    // If we find one then cut down vInfo to only new transactions.
    if (model.size() && model.front().canConvert<MemPoolTableObject>()) {
        MemPoolTableObject old = model.front().value<MemPoolTableObject>();

        for (auto it = vInfo.begin(); it != vInfo.end(); it++) {
            if (!it->tx)
                continue;

            if (it->tx->GetHash() == old.txid) {
                vInfo = std::vector<TxMempoolInfo>(vInfo.begin(), it);
                break;
            }
        }
    }

    if (vInfo.empty())
        return;

    // Add new data to table
    beginInsertRows(QModelIndex(), 0, vInfo.size() - 1);
    for (auto it = vInfo.begin(); it != vInfo.end(); it++) {
        if (!it->tx)
            continue;

        MemPoolTableObject object;
        object.txid = it->tx->GetHash();
        object.time = QDateTime::fromTime_t((int64_t)it->nTime).toString("hh:mm MMM dd");
        object.value = it->tx->GetValueOut();
        object.feeRate = it->feeRate;
        object.fee = it->fee;

        model.prepend(QVariant::fromValue(object));
    }
    endInsertRows();

    // Remove extra entries
    if (model.size() > 50)
    {
        beginRemoveRows(QModelIndex(), model.size() - std::abs(50 - model.size()), model.size() - 1);
        while (model.size() > 50)
            model.pop_back();
        endRemoveRows();
    }
}

void MemPoolTableModel::memPoolSizeChanged(long nTxIn, size_t nBytesIn)
{
    if (nTxIn != nTx || nBytesIn != nBytes) {
        nTx = nTxIn;
        nBytes = nBytesIn;
        updateModel();
    }
}

void MemPoolTableModel::setUSDBTC(int nUSDBTCIn)
{
    nUSDBTC = nUSDBTCIn;
    updateModel();
}

bool MemPoolTableModel::GetTx(const uint256& txid, CTransactionRef& tx) const
{
    if (!mempool.exists(txid))
        return false;

    tx = mempool.get(txid);
    return true;
}
