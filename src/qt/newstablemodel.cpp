// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/newstablemodel.h>

#include <chain.h>
#include <txdb.h>
#include <utilmoneystr.h>
#include <validation.h>

#include <qt/clientmodel.h>
#include <qt/newstypestablemodel.h>

#include <QDateTime>
#include <QMetaType>
#include <QTimer>
#include <QVariant>

Q_DECLARE_METATYPE(NewsTableObject)

NewsTableModel::NewsTableModel(QObject *parent) :
    QAbstractTableModel(parent)
{
    nFilter = 0;
}

int NewsTableModel::rowCount(const QModelIndex & /*parent*/) const
{
    return model.size();
}

int NewsTableModel::columnCount(const QModelIndex & /*parent*/) const
{
    return 3;
}

QVariant NewsTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return false;
    }

    int row = index.row();
    int col = index.column();

    if (!model.at(row).canConvert<NewsTableObject>())
        return QVariant();

    NewsTableObject object = model.at(row).value<NewsTableObject>();

    switch (role) {
    case Qt::DisplayRole:
    {
        // Fees
        if (col == 0) {
            return QString::fromStdString(object.fees);
        }
        // Time
        if (col == 1) {
            return QDateTime::fromTime_t((int64_t)object.nTime).toString("hh:mm MMM dd");
        }
        // Decode
        if (col == 2) {
            // Display up to NEWS_HEADLINE_CHARS or until newline
            std::string str = "";
            bool fNewline = false;
            for (size_t x = 0; x < object.decode.size(); x++) {
                if (x == NEWS_HEADLINE_CHARS)
                    break;

                if (object.decode[x] == '\n' || object.decode[x] == '\r') {
                    fNewline = true;
                    break;
                }

                str += object.decode[x];
            }

            if (fNewline || object.decode.size() > NEWS_HEADLINE_CHARS)
                str += "...";

            return QString::fromStdString(str);
        }
    }
    case Qt::TextAlignmentRole:
    {
        // Fees
        if (col == 0) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // Time
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
        // Fees
        if (col == 0) {
            return object.feeAmount;
        }
        // Time
        if (col == 1) {
            return object.nTime;
        }
        // Decode
        if (col == 2) {
            return QString::fromStdString(object.decode);
        }
    }
    case NewsRole:
    {
        return QString::fromStdString(object.decode);
    }
    case NewsHexRole:
    {
        return QString::fromStdString(object.hex);
    }
    }
    return QVariant();
}

QVariant NewsTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole) {
        if (orientation == Qt::Horizontal) {
            switch (section) {
            case 0:
                return QString("Fees");
            case 1:
                return QString("Time");
            case 2:
                return QString("Headline");
            }
        }
    }
    return QVariant();
}

void NewsTableModel::setClientModel(ClientModel *model)
{
    this->clientModel = model;
    if(model)
    {
        numBlocksChanged();

        connect(model, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)),
                this, SLOT(numBlocksChanged()));
    }
}

void NewsTableModel::setNewsTypesModel(NewsTypesTableModel *model)
{
    this->newsTypesModel = model;
}

void NewsTableModel::numBlocksChanged()
{
    UpdateModel();
}

// TODO append new data to the model instead of loading all every time
void NewsTableModel::UpdateModel()
{
    if (!newsTypesModel || !clientModel)
        return;

    if (clientModel->inInitialBlockDownload())
        return;

    // Clear old data
    beginResetModel();
    model.clear();
    endResetModel();

    int nHeight = chainActive.Height();

    NewsType type;
    if (!newsTypesModel->GetType(nFilter, type))
        return;

    QDateTime tipTime = QDateTime::fromMSecsSinceEpoch(chainActive.Tip()->GetBlockTime() * 1000);
    QDateTime targetTime = tipTime.addDays(-type.nDays);

    // Loop backwards from chainTip until we reach target time or genesis block.
    std::vector<NewsTableObject> vNews;
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

        // Find the data we want to display
        for (const OPReturnData& d : vData) {
            bool fFound = false;
            if (d.script.size() >= 5 && type.header.size() >= 4) {
                if (d.script[0] ==  OP_RETURN &&
                        d.script[1] == type.header[0] &&
                        d.script[2] == type.header[1] &&
                        d.script[3] == type.header[2] &&
                        d.script[4] == type.header[3])
                {
                            fFound = true;
                }
            }
            if (!fFound)
                continue;

            NewsTableObject object;
            object.nTime = index->nTime;

            // Copy chars from script, skipping non-message bytes
            std::string strDecode;
            for (size_t i = 5; i < d.script.size(); i++)
                strDecode += d.script[i];

            object.decode = strDecode;
            object.fees = FormatMoney(d.fees);
            object.feeAmount = d.fees;
            object.hex = HexStr(d.script.begin(), d.script.end(), false);

            vNews.push_back(object);
        }
    }

    // Sort by fees
    SortByFees(vNews);

    beginInsertRows(QModelIndex(), model.size(), model.size() + vNews.size() - 1);
    for (const NewsTableObject& o : vNews)
        model.append(QVariant::fromValue(o));
    endInsertRows();
}

void NewsTableModel::setFilter(size_t nFilterIn)
{
    nFilter = nFilterIn;
    UpdateModel();
}

struct CompareByFee
{
    bool operator()(const NewsTableObject& a, const NewsTableObject& b) const
    {
        return a.fees > b.fees;
    }
};

void NewsTableModel::SortByFees(std::vector<NewsTableObject>& vNews)
{
    std::sort(vNews.begin(), vNews.end(), CompareByFee());
}
