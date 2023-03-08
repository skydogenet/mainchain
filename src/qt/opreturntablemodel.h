// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OPRETURNTABLEMODEL_H
#define OPRETURNTABLEMODEL_H

#include <uint256.h>

#include <QAbstractTableModel>
#include <QList>

class CBlockIndex;
class OPReturnData;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

struct OPReturnTableObject
{
    int nTime;
    std::string decode;
    std::string fees;
    std::string hex;
    int feeAmount;
};

class OPReturnTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit OPReturnTableModel(QObject *parent = 0);
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;

    void setDays(int nDays);

    enum RoleIndex {
        DecodeRole = Qt::UserRole,
        HexRole,
    };

public Q_SLOTS:
    void UpdateModel();

private:
    QList<QVariant> model;
    int nDays;
};

#endif // OPRETURNTABLEMODEL_H
