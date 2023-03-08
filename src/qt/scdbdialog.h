// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef SCDBDIALOG_H
#define SCDBDIALOG_H

#include <QDialog>

class ClientModel;
class PlatformStyle;

QT_BEGIN_NAMESPACE
class QTreeWidgetItem;
QT_END_NAMESPACE

enum TreeItemRoles {
    UserRole = Qt::UserRole,
    NumRole, // Sidechain number
    HashRole // Withdrawal bundle hash
};

namespace Ui {
class SCDBDialog;
}

class SCDBDialog : public QDialog
{
    Q_OBJECT

public:
    explicit SCDBDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~SCDBDialog();

    void setClientModel(ClientModel *model);
    void UpdateOnShow();

private:
    Ui::SCDBDialog *ui;

    const PlatformStyle *platformStyle;
    ClientModel *clientModel = nullptr;

    void AddHistoryTreeItem(int index, const int nHeight, QTreeWidgetItem *item);

    void UpdateVoteTree();
    void UpdateSCDBText();
    void UpdateHistoryTree();

private Q_SLOTS:
    void numBlocksChanged();
    void on_treeWidgetVote_itemChanged(QTreeWidgetItem *item, int column);
};

#endif // SCDBDIALOG_H
