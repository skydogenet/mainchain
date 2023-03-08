#include <qt/sidechainwithdrawalvotetablemodel.h>

#include <sidechain.h>
#include <sidechaindb.h>
#include <util.h>
#include <validation.h>

#include <QIcon>
#include <QMetaType>
#include <QPushButton>
#include <QTimer>
#include <QVariant>

#include <qt/guiconstants.h>
#include <qt/guiutil.h>

Q_DECLARE_METATYPE(VoteTableObject)

SidechainWithdrawalVoteTableModel::SidechainWithdrawalVoteTableModel(QObject *parent) :
    QAbstractTableModel(parent)
{
    // This timer will be fired repeatedly to update the model
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(UpdateModel()));
    pollTimer->start(MODEL_UPDATE_DELAY);
}

int SidechainWithdrawalVoteTableModel::rowCount(const QModelIndex & /*parent*/) const
{
    return model.size();
}

int SidechainWithdrawalVoteTableModel::columnCount(const QModelIndex & /*parent*/) const
{
    return 3;
}

QVariant SidechainWithdrawalVoteTableModel::data(const QModelIndex &index, int role) const
{
    if (!index.isValid()) {
        return false;
    }

    int row = index.row();
    int col = index.column();

    if (!model.at(row).canConvert<VoteTableObject>())
        return QVariant();

    VoteTableObject object = model.at(row).value<VoteTableObject>();

    switch (role) {
    case Qt::DisplayRole:
    {
        // Vote
        if (col == 0) {
            if (object.vote == SCDB_UPVOTE)
                return "Upvote";
            else
            if (object.vote == SCDB_ABSTAIN)
                return "Abstain";
            else
            if (object.vote == SCDB_DOWNVOTE)
                return "Downvote";
            else
                return "N/A";
        }
        // nSidechain
        if (col == 1) {
            return object.nSidechain;
        }
        // Hash
        if (col == 2) {
            return object.hash;
        }
    }
    }
    return QVariant();
}

QVariant SidechainWithdrawalVoteTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if (role == Qt::DisplayRole) {
        if (orientation == Qt::Horizontal) {
            switch (section) {
            case 0:
                return QString("Vote");
            case 1:
                return QString("SC Number");
            case 2:
                return QString("Withdrawal Hash");
            }
        }
    }
    return QVariant();
}

void SidechainWithdrawalVoteTableModel::UpdateModel()
{
    // Get all of the current Withdrawal(s) into one vector
    std::vector<Sidechain> vSidechain = scdb.GetActiveSidechains();
    std::vector<SidechainWithdrawalState> vWithdrawal;
    for (const Sidechain& s : vSidechain) {
        std::vector<SidechainWithdrawalState> vState = scdb.GetState(s.nSidechain);
        vWithdrawal.insert(vWithdrawal.end(), vState.begin(), vState.end());
    }

    // Get users votes
    std::vector<SidechainCustomVote> vCustomVote = scdb.GetCustomVoteCache();

    bool fCustomVotes = vCustomVote.size();
    std::string strDefaultVote = gArgs.GetArg("-defaultwithdrawalvote", "abstain");

    char defaultVote;
    if (strDefaultVote == "upvote")
        defaultVote = SCDB_UPVOTE;
    else
    if (strDefaultVote == "downvote")
        defaultVote = SCDB_DOWNVOTE;
    else
        defaultVote = SCDB_ABSTAIN;

    // Look for updates to Withdrawal(s) & their vote already cached by the model and
    // update our model / view.
    //
    // Also look for Withdrawal(s) which have been removed, and remove them from our
    // model / view.
    std::vector<VoteTableObject> vRemoved;
    for (int i = 0; i < model.size(); i++) {
        if (!model[i].canConvert<VoteTableObject>())
            return;

        VoteTableObject object = model[i].value<VoteTableObject>();

        bool fFound = false;

        // Check if the Withdrawal should still be in the table and make sure we set
        // it with the current vote
        for (const SidechainWithdrawalState& s : vWithdrawal) {
            // Check if we need to update the vote type
            if (s.hash == uint256S(object.hash.toStdString())
                        && s.nSidechain == object.nSidechain) {
                fFound = true;
                if (fCustomVotes) {
                    // Check for updates to custom votes
                    for (const SidechainCustomVote& v : vCustomVote) {
                        if (v.nSidechain == s.nSidechain && v.hash == s.hash) {
                            if (object.vote != v.vote) {
                                // Update the vote type
                                object.vote = v.vote;

                                QModelIndex topLeft = index(i, 0);
                                QModelIndex topRight = index(i, columnCount() - 1);
                                Q_EMIT QAbstractItemModel::dataChanged(topLeft, topRight, {Qt::DecorationRole});

                                model[i] = QVariant::fromValue(object);
                            }
                        }
                    }
                } else {
                    // Check for updates to default vote
                    if (object.vote != defaultVote) {
                        // Update the vote type
                        object.vote = defaultVote;

                        QModelIndex topLeft = index(i, 0);
                        QModelIndex topRight = index(i, columnCount() - 1);
                        Q_EMIT QAbstractItemModel::dataChanged(topLeft, topRight, {Qt::DecorationRole});

                        model[i] = QVariant::fromValue(object);
                    }
                }
            }
        }

        // Add to vector of votes to be removed from model / view
        if (!fFound) {
            vRemoved.push_back(object);
        }
    }

    // Loop through the model and remove deleted votes
    for (int i = 0; i < model.size(); i++) {
        if (!model[i].canConvert<VoteTableObject>())
            return;

        VoteTableObject object = model[i].value<VoteTableObject>();

        for (const VoteTableObject& v : vRemoved) {
            if (v.hash == object.hash && v.nSidechain == object.nSidechain) {
                beginRemoveRows(QModelIndex(), i, i);
                model[i] = model.back();
                model.pop_back();
                endRemoveRows();
            }
        }
    }

    // Check for new Withdrawal(s)
    std::vector<SidechainWithdrawalState> vNew;
    for (const SidechainWithdrawalState& s : vWithdrawal) {
        bool fFound = false;

        for (const QVariant& qv : model) {
            if (!qv.canConvert<VoteTableObject>())
                return;

            VoteTableObject object = qv.value<VoteTableObject>();

            if (s.hash == uint256S(object.hash.toStdString())
                    && s.nSidechain == object.nSidechain)
                fFound = true;
        }
        if (!fFound)
            vNew.push_back(s);
    }

    if (vNew.empty())
        return;

    // Add new Withdrawal(s) if we need to - with correct vote type
    beginInsertRows(QModelIndex(), model.size(), model.size() + vNew.size() - 1);
    for (const SidechainWithdrawalState& s : vNew) {
        VoteTableObject object;

        // If custom votes are set, check to see if one is set for this Withdrawal and
        // if not set SCDB_ABSTAIN. If custom votes are not set, use the current
        // default vote
        if (fCustomVotes) {
            // Set vote to default abstain, and then look for a custom vote and
            // update the vote type if foudn
            object.vote = SCDB_ABSTAIN;
            for (const SidechainCustomVote& v : vCustomVote) {
                if (v.hash == s.hash && v.nSidechain == s.nSidechain) {
                    object.vote = v.vote;
                }
            }
        } else {
            object.vote = defaultVote;
        }

        // Insert new Withdrawal into table
        object.hash = QString::fromStdString(s.hash.ToString());
        object.nSidechain = s.nSidechain;
        model.append(QVariant::fromValue(object));
    }
    endInsertRows();
}

bool SidechainWithdrawalVoteTableModel::GetWithdrawalInfoAtRow(int row, uint256& hash, unsigned int& nSidechain) const
{
    if (row >= model.size())
        return false;

    if (!model[row].canConvert<VoteTableObject>())
        return false;

    VoteTableObject object = model[row].value<VoteTableObject>();

    hash = uint256S(object.hash.toStdString());
    nSidechain = object.nSidechain;

    return true;
}
