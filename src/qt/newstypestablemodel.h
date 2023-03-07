// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef NEWSTYPESTABLEMODEL_H
#define NEWSTYPESTABLEMODEL_H

#include <QAbstractTableModel>
#include <QList>

class NewsType;
class CScript;

struct NewsTypesTableObject
{
    QString title;
    QString bytes;
    int nDays;
    QString url;

    NewsTypesTableObject() {};

    NewsTypesTableObject(QString titleIn, QString bytesIn, int nDaysIn,
            QString urlIn)
    {
        title = titleIn;
        bytes = bytesIn;
        nDays = nDaysIn;
        url = urlIn;
    };
};

class NewsTypesTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit NewsTypesTableModel(QObject *parent = 0);

    enum RoleIndex {
        /** News type URL */
        URLRole = Qt::UserRole
    };

    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;

    bool GetURLAtRow(int row, QString& url) const;

    std::vector<NewsType> GetTypes() const;
    bool GetType(int row, NewsType& type) const;

    bool IsHeaderUnique(const CScript& header) const;
    bool IsDefaultType(const CScript& header) const;

public Q_SLOTS:
    void updateModel();

private:
    QList<QVariant> model;
};

#endif // NEWSTYPESTABLEMODEL_H
