// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MEMPOOLTABLEMODEL_H
#define MEMPOOLTABLEMODEL_H

#include <QAbstractTableModel>
#include <QList>

#include <amount.h>
#include <policy/feerate.h>
#include <uint256.h>

class ClientModel;
class CTransaction;
typedef std::shared_ptr<const CTransaction> CTransactionRef;

QT_BEGIN_NAMESPACE
class QString;
QT_END_NAMESPACE

struct MemPoolTableObject
{
    uint256 txid;
    QString time;
    CAmount value;
    CFeeRate feeRate;
    CAmount fee;
};

class MemPoolTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit MemPoolTableModel(QObject *parent = 0);
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;
    bool GetTx(const uint256& txid, CTransactionRef& tx) const;

    void setClientModel(ClientModel *model);

    enum RoleIndex {
        HashRole = Qt::UserRole,
    };

public Q_SLOTS:
    void memPoolSizeChanged(long nTx, size_t nBytes);
    void setUSDBTC(int nUSDBTC);

private:
    void updateModel();

    QList<QVariant> model;

    ClientModel *clientModel = nullptr;

    long nTx;
    size_t nBytes;
    int64_t nUSDBTC;
};

#endif // MEMPOOLTABLEMODEL_H
