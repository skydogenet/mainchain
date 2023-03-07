#ifndef BLOCKEXPLORERTABLEMODEL_H
#define BLOCKEXPLORERTABLEMODEL_H

#include <uint256.h>

#include <QAbstractTableModel>
#include <QList>

class CBlockIndex;
class ClientModel;

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

struct BlockExplorerTableObject
{
    int nHeight;
    uint256 hash;
    uint256 hashPrev;
    uint256 hashMerkleRoot;
    int nTime;
    int nBits;
};

class BlockExplorerTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit BlockExplorerTableModel(QObject *parent = 0);
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;

    void setClientModel(ClientModel *model);

    CBlockIndex* GetBlockIndex(const uint256& hash) const;
    CBlockIndex* GetBlockIndex(int nHeight) const;
    CBlockIndex* GetTip() const;

    enum RoleIndex {
        HeightRole = Qt::UserRole,
        HashRole
    };

public Q_SLOTS:
    void numBlocksChanged();

private:
    QList<QVariant> model;

    ClientModel *clientModel = nullptr;

    void UpdateModel();
};

#endif // BLOCKEXPLORERTABLEMODEL_H
