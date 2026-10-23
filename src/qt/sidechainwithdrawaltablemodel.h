#ifndef SIDECHAINWITHDRAWALTABLEMODEL_H
#define SIDECHAINWITHDRAWALTABLEMODEL_H

#include <QAbstractTableModel>
#include <QList>

QT_BEGIN_NAMESPACE
class QTimer;
QT_END_NAMESPACE

struct SidechainWithdrawalTableObject
{
    // DEFAULT-INITIALISED ON PURPOSE. These are plain members read directly by
    // data() during paint, and AddDemoData() builds objects field by field - so
    // a member added here and missed there is an uninitialised read that renders
    // as garbage in the table rather than failing anywhere a test would see it.
    // Adding nMinWorkScore did exactly that before these initialisers existed.
    QString sidechain;
    QString hash;
    uint32_t nAcks = 0;   // tracks nWorkScore
    uint32_t nAge = 0;
    uint32_t nMaxAge = 0;
    //! Resolved from the HEIGHT-GATED accessors at refresh, not from the legacy
    //! constants at paint time. data() runs per cell on every repaint and has no
    //! height and no cs_main; refreshModel() has both. Storing the resolved
    //! values is what lets the display follow the consensus parameters.
    uint32_t nMinWorkScore = 0;
    bool fApproved = false;
};

class SidechainWithdrawalTableModel : public QAbstractTableModel
{
    Q_OBJECT

public:
    explicit SidechainWithdrawalTableModel(QObject *parent = 0);
    int rowCount(const QModelIndex &parent = QModelIndex()) const;
    int columnCount(const QModelIndex &parent = QModelIndex()) const;
    QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const;
    QVariant headerData(int section, Qt::Orientation orientation, int role) const;

    enum RoleIndex {
        AcksRole = Qt::UserRole,
        HashRole
    };

    // Populate the model with demo data
    void AddDemoData();

    // Clear demo data and start syncing with real data again
    void ClearDemoData();

public Q_SLOTS:
    void updateModel();

    void numBlocksChanged();

private:
    QList<QVariant> model;
};

#endif // SIDECHAINWITHDRAWALTABLEMODEL_H
