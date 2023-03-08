// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/opreturntablemodel.h>

#include <chain.h>
#include <txdb.h>
#include <utilmoneystr.h>
#include <validation.h>

#include <QDateTime>
#include <QMetaType>
#include <QVariant>

Q_DECLARE_METATYPE(OPReturnTableObject)

OPReturnTableModel::OPReturnTableModel(QObject *parent) :
    QAbstractTableModel(parent)
{
    nDays = 1;
}

int OPReturnTableModel::rowCount(const QModelIndex & /*parent*/) const
{
    return model.size();
}

int OPReturnTableModel::columnCount(const QModelIndex & /*parent*/) const
{
    return 3;
}

QVariant OPReturnTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return false;
    }

    int row = index.row();
    int col = index.column();

    if (!model.at(row).canConvert<OPReturnTableObject>())
        return QVariant();

    OPReturnTableObject object = model.at(row).value<OPReturnTableObject>();

    switch (role) {
    case Qt::DisplayRole:
    {
        // Time
        if (col == 0) {
            return QDateTime::fromTime_t((int64_t)object.nTime).toString("hh:mm MMMM dd");
        }
        // Fees
        if (col == 1) {
            return QString::fromStdString(object.fees);
        }
        // Decode
        if (col == 2) {
                return QString::fromStdString(object.decode);
        }
    }
    case Qt::TextAlignmentRole:
    {
        // Time
        if (col == 0) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // Fees
        if (col == 1) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // Decode
        if (col == 2) {
            return int(Qt::AlignLeft | Qt::AlignVCenter);
        }
    }
    case Qt::EditRole:
    {
        // Time
        if (col == 0) {
            return object.nTime;
        }
        // Fees
        if (col == 1) {
            return object.feeAmount;
        }
        // Decode
        if (col == 2) {
            return QString::fromStdString(object.decode);
        }
    }
    case DecodeRole:
    {
        return QString::fromStdString(object.decode);
    }
    case HexRole:
    {
        return QString::fromStdString(object.hex);
    }
    }
    return QVariant();
}

QVariant OPReturnTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole) {
        if (orientation == Qt::Horizontal) {
            switch (section) {
            case 0:
                return QString("Time");
            case 1:
                return QString("Fees");
            case 2:
                return QString("Decode");
            }
        }
    }
    return QVariant();
}

void OPReturnTableModel::setDays(int nDaysIn)
{
    nDays = nDaysIn;
    UpdateModel();
}

// TODO append new data to the model instead of loading all every time
void OPReturnTableModel::UpdateModel()
{
    // Clear old data
    beginResetModel();
    model.clear();
    endResetModel();

    int nHeight = chainActive.Height();

    QDateTime tipTime = QDateTime::fromTime_t(chainActive.Tip()->GetBlockTime());
    QDateTime targetTime = tipTime.addDays(-nDays);

    // Loop backwards from chainTip until we reach target time or genesis block.
    std::vector<OPReturnTableObject> vObj;
    int nBatchSize = 300;
    for (int i = nHeight; i > 1; i--) {
        CBlockIndex *index = chainActive[i];
        if (!index)
            break;

        // Have we gone back in time far enough?
        QDateTime indexTime = QDateTime::fromTime_t(index->GetBlockTime());

        if (indexTime <= targetTime)
            break;

        // For each block load our cached OP_RETURN data
        std::vector<OPReturnData> vData;
        if (!popreturndb->GetBlockData(index->GetBlockHash(), vData))
            continue;

        for (const OPReturnData& d : vData) {
            OPReturnTableObject object;
            object.nTime = index->nTime;

            // Copy chars from script, skipping OP_RETURN
            std::string strDecode;
            for (size_t i = 1; i < d.script.size(); i++)
                strDecode += d.script[i];

            object.decode = strDecode;
            object.fees = FormatMoney(d.fees);
            object.feeAmount = d.fees;
            object.hex = HexStr(d.script.begin(), d.script.end(), false);

            vObj.push_back(object);
        }

        // Write batch
        if (i % nBatchSize == 0 && vObj.size()) {
            int offset = model.size() ? 2 : 1;
            beginInsertRows(QModelIndex(), model.size(), model.size() + vObj.size() - offset);
            for (const OPReturnTableObject& o : vObj)
                model.append(QVariant::fromValue(o));
            endInsertRows();

            vObj.clear();
        }
    }

    if (!vObj.size())
        return;

    // Write final batch
    int offset = model.size() ? 2 : 1;
    beginInsertRows(QModelIndex(), model.size(), model.size() + vObj.size() - offset);
    for (const OPReturnTableObject& o : vObj)
        model.append(QVariant::fromValue(o));
    endInsertRows();
}
