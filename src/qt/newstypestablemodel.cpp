// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <qt/newstypestablemodel.h>

#include <QIcon>
#include <QMetaType>
#include <QTimer>
#include <QVariant>

#include <script/script.h>
#include <txdb.h>
#include <validation.h>

Q_DECLARE_METATYPE(NewsTypesTableObject)

std::vector<NewsTypesTableObject> vDefaultType
{
    NewsTypesTableObject("Daily Doge", "a1a1a1a1", 7, "7{a1a1a1a1}Daily Doge"),
    NewsTypesTableObject("Doge Extra", "a2a2a2a2", 7, "7{a2a2a2a2}Doge Extra")
};

NewsTypesTableModel::NewsTypesTableModel(QObject *parent) :
    QAbstractTableModel(parent)
{
    updateModel();
}

int NewsTypesTableModel::rowCount(const QModelIndex & /*parent*/) const
{
    return model.size();
}

int NewsTypesTableModel::columnCount(const QModelIndex & /*parent*/) const
{
    return 4;
}

QVariant NewsTypesTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return false;
    }

    int row = index.row();
    int col = index.column();

    if (!model.at(row).canConvert<NewsTypesTableObject>())
        return QVariant();

    NewsTypesTableObject object = model.at(row).value<NewsTypesTableObject>();

    switch (role) {
    case Qt::DisplayRole:
    {
        // Title
        if (col == 0) {
            return object.title;
        }
        // Days
        if (col == 1) {
            return QString::number(object.nDays);
        }
        // Bytes
        if (col == 2) {
            return object.bytes;
        }
        // URL
        if (col == 3) {
            return object.url;
        }
    }
    case URLRole:
        return object.url;
    }
    return QVariant();
}

QVariant NewsTypesTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole) {
        if (orientation == Qt::Horizontal) {
            switch (section) {
            case 0:
                return QString("Title");
            case 1:
                return QString("Days");
            case 2:
                return QString("Bytes");
            case 3:
                return QString("URL");
            }
        }
    }
    return QVariant();
}

void NewsTypesTableModel::updateModel()
{
    std::vector<NewsType> vType;
    popreturndb->GetNewsTypes(vType);

    beginResetModel();
    model.clear();
    endResetModel();

    beginInsertRows(QModelIndex(), 0, vDefaultType.size());
    for (const NewsTypesTableObject& object : vDefaultType)
        model.append(QVariant::fromValue(object));
    endInsertRows();

    beginInsertRows(QModelIndex(), model.size(), model.size() + vType.size());
    for (const NewsType& type : vType) {
        NewsTypesTableObject object;

        object.title = QString::fromStdString(type.title);
        object.nDays = type.nDays;
        object.bytes = QString::fromStdString(HexStr(type.header.begin(), type.header.end()));
        object.url = QString::fromStdString(type.GetShareURL());

        model.append(QVariant::fromValue(object));
    }
    endInsertRows();
}

bool NewsTypesTableModel::GetURLAtRow(int row, QString& url) const
{
    if (row >= model.size())
        return false;

    if (!model[row].canConvert<NewsTypesTableObject>())
        return false;

    NewsTypesTableObject object = model[row].value<NewsTypesTableObject>();
    url = object.url;

    return true;
}

std::vector<NewsType> NewsTypesTableModel::GetTypes() const
{
    std::vector<NewsType> vType;
    for (int i = 0; i < model.size(); i++) {
        if (!model[i].canConvert<NewsTypesTableObject>())
            continue;

        NewsTypesTableObject object = model[i].value<NewsTypesTableObject>();
        NewsType type;
        if (!type.SetURL(object.url.toStdString()))
            continue;
        vType.push_back(type);
    }
    return vType;
}


bool NewsTypesTableModel::GetType(int nRow, NewsType& type) const
{
    if (nRow < 0 || nRow >= model.size())
        return false;

    if (!model[nRow].canConvert<NewsTypesTableObject>())
        return false;

    NewsTypesTableObject object = model[nRow].value<NewsTypesTableObject>();

    if (!type.SetURL(object.url.toStdString()))
        return false;

    return true;
}

bool NewsTypesTableModel::IsHeaderUnique(const CScript& header) const
{
    // Check if any of our news type have this header
    std::vector<NewsType> vType;
    for (int i = 0; i < model.size(); i++) {
        if (!model[i].canConvert<NewsTypesTableObject>())
            continue;

        NewsTypesTableObject object = model[i].value<NewsTypesTableObject>();
        NewsType type;
        if (!type.SetURL(object.url.toStdString()))
            continue;

        if (header == type.header)
            return false;
    }

    return true;
}

bool NewsTypesTableModel::IsDefaultType(const CScript& header) const
{
    // Check if any of the built in types have this header
    for (const NewsTypesTableObject& object : vDefaultType) {
        NewsType type;
        if (!type.SetURL(object.url.toStdString()))
            continue;

        if (header == type.header)
            return true;
    }
    return false;
}
