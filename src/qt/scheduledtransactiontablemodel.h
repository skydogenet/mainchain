// Copyright (c) 2022- The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SCHEDULEDTRANSACTIONTABLDEMODEL_H
#define SCHEDULEDTRANSACTIONTABLDEMODEL_H

#include <QAbstractTableModel>
#include <QList>

QT_BEGIN_NAMESPACE
class QString;
QT_END_NAMESPACE

class ClientModel;
class uint256;

struct ScheduledTableObject
{
    QString txid;
    QString time;
};

class ScheduledTransactionTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit ScheduledTransactionTableModel(QObject *parent = 0);
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;

    bool GetTxidAtRow(int row, uint256& txid) const;
    void setClientModel(ClientModel *model);

public Q_SLOTS:
    void UpdateModel();

private:
    QList<QVariant> model;

    ClientModel* clientModel= nullptr;
};

#endif // SCHEDULEDTRANSACTIONTABLDEMODEL_H
