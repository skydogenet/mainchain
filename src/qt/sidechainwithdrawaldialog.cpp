// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/sidechainwithdrawaldialog.h>
#include <qt/forms/ui_sidechainwithdrawaldialog.h>

#include <qt/platformstyle.h>
#include <qt/sidechainwithdrawalvotetablemodel.h>

#include <QMessageBox>
#include <QScrollBar>
#include <QTimer>

#include <sidechain.h>
#include <sidechaindb.h>
#include <util.h>
#include <validation.h>

enum DefaultWithdrawalVote {
    WITHDRAWAL_UPVOTE = 0,
    WITHDRAWAL_ABSTAIN = 1,
    WITHDRAWAL_DOWNVOTE = 2,
};

SidechainWithdrawalDialog::SidechainWithdrawalDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::SidechainWithdrawalDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    withdrawalVoteModel = new SidechainWithdrawalVoteTableModel(this);

    ui->tableViewWithdrawalVote->setModel(withdrawalVoteModel);

    // Set resize mode for withdrawal vote table
    ui->tableViewWithdrawalVote->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    // Don't stretch last cell of horizontal header
    ui->tableViewWithdrawalVote->horizontalHeader()->setStretchLastSection(false);

    // Hide vertical header
    ui->tableViewWithdrawalVote->verticalHeader()->setVisible(false);

    // Left align the horizontal header text
    ui->tableViewWithdrawalVote->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);

    // Set horizontal scroll speed to per 3 pixels (very smooth, default is awful)
    ui->tableViewWithdrawalVote->horizontalHeader()->setHorizontalScrollMode(QAbstractItemView::ScrollPerPixel);
    ui->tableViewWithdrawalVote->horizontalHeader()->horizontalScrollBar()->setSingleStep(3); // 3 Pixels

    // Select entire row
    ui->tableViewWithdrawalVote->setSelectionBehavior(QAbstractItemView::SelectRows);

    // If the user has withdrawal vote parameters set, update the default vote combobox
    std::string strDefault = gArgs.GetArg("-defaultwithdrawalvote", "");
    if (strDefault == "upvote")
    {
        ui->comboBoxDefaultVote->setCurrentIndex(WITHDRAWAL_UPVOTE);
    }
    else
    if (strDefault == "downvote")
    {
        ui->comboBoxDefaultVote->setCurrentIndex(WITHDRAWAL_DOWNVOTE);
    }
    else
    {
        ui->comboBoxDefaultVote->setCurrentIndex(WITHDRAWAL_ABSTAIN);
    }

    // Setup platform style single color icons

    ui->pushButtonUpvote->setIcon(platformStyle->SingleColorIcon(":/icons/ack"));
    ui->pushButtonDownvote->setIcon(platformStyle->SingleColorIcon(":/icons/nack"));
    ui->pushButtonAbstain->setIcon(platformStyle->SingleColorIcon(":/icons/replay_not_replayed"));
    ui->pushButtonHelp->setIcon(platformStyle->SingleColorIcon(":/icons/transaction_0"));
    ui->comboBoxDefaultVote->setItemIcon(0, platformStyle->SingleColorIcon(":/icons/ack"));
    ui->comboBoxDefaultVote->setItemIcon(1, platformStyle->SingleColorIcon(":/icons/replay_not_replayed"));
    ui->comboBoxDefaultVote->setItemIcon(2, platformStyle->SingleColorIcon(":/icons/nack"));

    // Start the poll timer to update the page
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(Update()));
    pollTimer->start(1000); // 1 second

    Update();
}

SidechainWithdrawalDialog::~SidechainWithdrawalDialog()
{
    delete ui;
}

void SidechainWithdrawalDialog::on_comboBoxDefaultVote_currentIndexChanged(const int i)
{
    if (i == WITHDRAWAL_UPVOTE) {
        gArgs.ForceSetArg("-defaultwithdrawalvote", "upvote");
    }
    else
    if (i == WITHDRAWAL_ABSTAIN) {
        gArgs.ForceSetArg("-defaultwithdrawalvote", "abstain");
    }
    else
    if (i == WITHDRAWAL_DOWNVOTE) {
        gArgs.ForceSetArg("-defaultwithdrawalvote", "downvote");
    }
}

void SidechainWithdrawalDialog::on_pushButtonHelp_clicked()
{
    // TODO move text into static const
    QMessageBox::information(this, tr("Skydoge - information"),
        tr("Sidechain withdrawal vote signalling:\n\n"
           "Use this page to set votes for withdrawal(s).\n\n"
           "Set Upvote to increase the work score of withdrawal(s) in blocks "
           "that you mine. Downvote to decrease the work score, and Abstain "
           "to ignore a withdrawal and not change its workscore.\n\n"
           "You may also use the RPC command 'setwithdrawalvote' to set votes "
           "or 'clearwithdrawalvotes' to reset and erase any votes you have set."
           ),
        QMessageBox::Ok);
}

// TODO
// refactor all of the voting pushButton slots to use one function for
// setting withdrawal vote type.

void SidechainWithdrawalDialog::on_pushButtonUpvote_clicked()
{
    // Set withdrawal vote type

    QModelIndexList selected = ui->tableViewWithdrawalVote->selectionModel()->selectedIndexes();

    for (int i = 0; i < selected.size(); i++) {
        uint256 hash;
        unsigned int nSidechain;
        if (withdrawalVoteModel->GetWithdrawalInfoAtRow(selected[i].row(), hash, nSidechain)) {
            SidechainCustomVote vote;
            vote.nSidechain = nSidechain;
            vote.hash = hash;
            vote.vote = SCDB_UPVOTE;

            scdb.CacheCustomVotes(std::vector<SidechainCustomVote>{ vote });
        }
    }
}

void SidechainWithdrawalDialog::on_pushButtonDownvote_clicked()
{
    // Set withdrawal vote type

    QModelIndexList selected = ui->tableViewWithdrawalVote->selectionModel()->selectedIndexes();

    for (int i = 0; i < selected.size(); i++) {
        uint256 hash;
        unsigned int nSidechain;
        if (withdrawalVoteModel->GetWithdrawalInfoAtRow(selected[i].row(), hash, nSidechain)) {
            SidechainCustomVote vote;
            vote.nSidechain = nSidechain;
            vote.hash = hash;
            vote.vote = SCDB_DOWNVOTE;

            scdb.CacheCustomVotes(std::vector<SidechainCustomVote>{ vote });
        }
    }
}

void SidechainWithdrawalDialog::on_pushButtonAbstain_clicked()
{
    // Set withdrawal vote type

    QModelIndexList selected = ui->tableViewWithdrawalVote->selectionModel()->selectedIndexes();

    for (int i = 0; i < selected.size(); i++) {
        uint256 hash;
        unsigned int nSidechain;
        if (withdrawalVoteModel->GetWithdrawalInfoAtRow(selected[i].row(), hash, nSidechain)) {
            SidechainCustomVote vote;
            vote.nSidechain = nSidechain;
            vote.hash = hash;
            vote.vote = SCDB_ABSTAIN;

            scdb.CacheCustomVotes(std::vector<SidechainCustomVote>{ vote });
        }
    }
}

void SidechainWithdrawalDialog::Update()
{
    // Disable the default vote combo box if custom votes are set, enable it
    // if they are not.
    std::vector<SidechainCustomVote> vCustomVote = scdb.GetCustomVoteCache();
    bool fCustomVote = vCustomVote.size();
    ui->comboBoxDefaultVote->setEnabled(!fCustomVote);

    // Add a tip to the default vote label on how to reset them
    ui->labelClearVotes->setHidden(!fCustomVote);
}
