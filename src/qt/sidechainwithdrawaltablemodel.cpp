#include <qt/sidechainwithdrawaltablemodel.h>

#include <qt/guiconstants.h>

#include <random.h>
#include <sidechain.h>
#include <sidechaindb.h>
#include <validation.h>

#ifdef ENABLE_WALLET
#include <wallet/wallet.h>
#endif

#include <math.h>

#include <QIcon>
#include <QMetaType>
#include <QTimer>
#include <QVariant>

#include <base58.h>
#include <script/standard.h>
#include <qt/guiutil.h>

#include <qt/skydogeaddressvalidator.h>
#include <qt/skydogeunits.h>
#include <qt/qvalidatedlineedit.h>
#include <qt/walletmodel.h>

#include <primitives/transaction.h>
#include <init.h>
#include <policy/policy.h>
#include <protocol.h>
#include <script/script.h>
#include <script/standard.h>
#include <util.h>

Q_DECLARE_METATYPE(SidechainWithdrawalTableObject)

SidechainWithdrawalTableModel::SidechainWithdrawalTableModel(QObject *parent) :
    QAbstractTableModel(parent)
{
}

int SidechainWithdrawalTableModel::rowCount(const QModelIndex & /*parent*/) const
{
    return model.size();
}

int SidechainWithdrawalTableModel::columnCount(const QModelIndex & /*parent*/) const
{
    return 6;
}

QVariant SidechainWithdrawalTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return false;
    }

    int row = index.row();
    int col = index.column();

    if (!model.at(row).canConvert<SidechainWithdrawalTableObject>())
        return QVariant();

    SidechainWithdrawalTableObject object = model.at(row).value<SidechainWithdrawalTableObject>();

    switch (role) {
    case Qt::DisplayRole:
    {
        // Sidechain name
        if (col == 0) {
            return object.sidechain;
        }
        // Age
        if (col == 1) {
            return object.nAge;
        }
        // Max age
        if (col == 2) {
            // TODO just use SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD and remove nMaxAge
            // from the model objects
            return object.nMaxAge;
        }
        // Acks
        if (col == 3) {
            QString qAcks;
            qAcks += QString::number(object.nAcks);
            qAcks += " / ";
            qAcks += QString::number(SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE);
            return qAcks;
        }
        // Approved
        if (col == 4) {
            return object.fApproved;
        }
        // hash
        if (col == 5) {
            return object.hash;
        }
    }
    case AcksRole:
    {
        return object.nAcks;
    }
    case HashRole:
    {
        return object.hash;
    }
    case Qt::TextAlignmentRole:
    {
        // Sidechain name
        if (col == 0) {
            return int(Qt::AlignLeft | Qt::AlignVCenter);
        }
        // Age
        if (col == 1) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // Max age
        if (col == 2) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // Acks
        if (col == 3) {
            return int(Qt::AlignRight | Qt::AlignVCenter);
        }
        // Approved
        if (col == 4) {
            return int(Qt::AlignLeft | Qt::AlignVCenter);
        }
        // hash
        if (col == 5) {
            return int(Qt::AlignLeft | Qt::AlignVCenter);
        }
    }
    }
    return QVariant();
}

QVariant SidechainWithdrawalTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole) {
        if (orientation == Qt::Horizontal) {
            switch (section) {
            case 0:
                return QString("Sidechain");
            case 1:
                return QString("Age");
            case 2:
                return QString("Max Age");
            case 3:
                return QString("Acks");
            case 4:
                return QString("Approved");
            case 5:
                return QString("Withdrawal hash");
            }
        }
    }
    return QVariant();
}

void SidechainWithdrawalTableModel::updateModel()
{
    // Clear old data
    beginResetModel();
    model.clear();
    endResetModel();

    if (!scdb.HasState())
        return;

    std::vector<Sidechain> vSidechain = scdb.GetActiveSidechains();

    int nSidechains = vSidechain.size();
    beginInsertRows(QModelIndex(), model.size(), model.size() + nSidechains);
    for (const Sidechain& s : vSidechain) {
        std::vector<SidechainWithdrawalState> vState = scdb.GetState(s.nSidechain);
        for (const SidechainWithdrawalState& state : vState) {
            SidechainWithdrawalTableObject object;
            object.sidechain = QString::fromStdString(s.GetSidechainName());
            object.hash = QString::fromStdString(state.hash.ToString());
            object.nAcks = state.nWorkScore;
            object.nAge = abs(state.nBlocksLeft - SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD);
            object.nMaxAge = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD;
            object.fApproved = scdb.CheckWorkScore(state.nSidechain, state.hash);

            model.append(QVariant::fromValue(object));
        }
    }
    endInsertRows();
}

void SidechainWithdrawalTableModel::numBlocksChanged()
{
    updateModel();
}

void SidechainWithdrawalTableModel::AddDemoData()
{
    // Clear old data
    beginResetModel();
    model.clear();
    endResetModel();

    beginInsertRows(QModelIndex(), 0, 5);

    // Withdrawal 1
    SidechainWithdrawalTableObject object1;
    object1.sidechain = QString::fromStdString("Grin");
    object1.hash = QString::fromStdString(GetRandHash().ToString());
    object1.nAcks = 42;
    object1.nAge = 50;
    object1.nMaxAge = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD;
    object1.fApproved = false;

    // Withdrawal 2
    SidechainWithdrawalTableObject object2;
    object2.sidechain = QString::fromStdString("Hivemind");
    object2.hash = QString::fromStdString(GetRandHash().ToString());
    object2.nAcks = 13141;
    object2.nAge = 21358;
    object2.nMaxAge = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD;
    object2.fApproved = true;

    // Withdrawal 3
    SidechainWithdrawalTableObject object3;
    object3.sidechain = QString::fromStdString("Hivemind");
    object3.hash = QString::fromStdString(GetRandHash().ToString());
    object3.nAcks = 1637;
    object3.nAge = 2000;
    object3.nMaxAge = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD;
    object3.fApproved = false;

    // Withdrawal 4
    SidechainWithdrawalTableObject object4;
    object4.sidechain = QString::fromStdString("Cash");
    object4.hash = QString::fromStdString(GetRandHash().ToString());
    object4.nAcks = 705;
    object4.nAge = 26215;
    object4.nMaxAge = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD;
    object4.fApproved = false;

    // Withdrawal 5
    SidechainWithdrawalTableObject object5;
    object5.sidechain = QString::fromStdString("Hivemind");
    object5.hash = QString::fromStdString(GetRandHash().ToString());
    object5.nAcks = 10;
    object5.nAge = 10;
    object5.nMaxAge = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD;
    object5.fApproved = false;

    // Withdrawal 6
    SidechainWithdrawalTableObject object6;
    object6.sidechain = QString::fromStdString("sofa");
    object6.hash = QString::fromStdString(GetRandHash().ToString());
    object6.nAcks = 1256;
    object6.nAge = 1378;
    object6.nMaxAge = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD;
    object6.fApproved = false;

    // Withdrawal 7
    SidechainWithdrawalTableObject object7;
    object7.sidechain = QString::fromStdString("Cash");
    object7.hash = QString::fromStdString(GetRandHash().ToString());
    object7.nAcks = SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE + 10;
    object7.nAge = SIDECHAIN_WITHDRAWAL_MIN_WORKSCORE + 11;
    object7.nMaxAge = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD;
    object7.fApproved = true;

    // Withdrawal 8
    SidechainWithdrawalTableObject object8;
    object8.sidechain = QString::fromStdString("Hivemind");
    object8.hash = QString::fromStdString(GetRandHash().ToString());
    object8.nAcks = 1;
    object8.nAge = 26142;
    object8.nMaxAge = SIDECHAIN_WITHDRAWAL_VERIFICATION_PERIOD;
    object8.fApproved = false;

    // Add demo objects to model
    model.append(QVariant::fromValue(object1));
    model.append(QVariant::fromValue(object2));
    model.append(QVariant::fromValue(object3));
    model.append(QVariant::fromValue(object4));
    model.append(QVariant::fromValue(object5));
    model.append(QVariant::fromValue(object6));
    model.append(QVariant::fromValue(object7));
    model.append(QVariant::fromValue(object8));

    endInsertRows();
}

void SidechainWithdrawalTableModel::ClearDemoData()
{
    // Clear demo data
    beginResetModel();
    model.clear();
    endResetModel();
}
