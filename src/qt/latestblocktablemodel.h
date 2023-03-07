// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef LATESTBLOCKTABLEMODEL_H
#define LATESTBLOCKTABLEMODEL_H

#include <uint256.h>

#include <QAbstractTableModel>
#include <QList>

class CBlockIndex;
class ClientModel;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

struct BlockTableObject
{
    int nHeight;
    uint256 hash;
    int nTime;
};

class LatestBlockTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit LatestBlockTableModel(QObject *parent = 0);
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;

    void setClientModel(ClientModel *model);

    CBlockIndex* GetBlockIndex(const uint256& hash) const;
    CBlockIndex* GetBlockIndex(int nHeight) const;
    CBlockIndex* GetTip() const;

    enum RoleIndex {
        HashRole = Qt::UserRole,
    };

public Q_SLOTS:
    void numBlocksChanged();

private:
    QList<QVariant> model;

    ClientModel *clientModel = nullptr;

    void UpdateModel();
};

#endif // LATESTBLOCKTABLEMODEL_H
