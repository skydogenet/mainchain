// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MULTISIGLOUNGEDIALOG_H
#define MULTISIGLOUNGEDIALOG_H

#include <QDialog>

#include <string>

class MultisigDialog;
class PlatformStyle;

namespace Ui {
class MultisigLoungeDialog;
}

QT_BEGIN_NAMESPACE
class QMenu;
class QString;
class QTableWidgetItem;
QT_END_NAMESPACE

// Parter table

struct PartnerTableObject
{
    QString name;
    QString pubkey;
};

enum
{
    COLUMN_CHECKBOX = 0,
    COLUMN_NAME,
    COLUMN_PUBKEY,
};

enum
{
    COLUMN_CHECKBOX_WIDTH = 28,
    COLUMN_NAME_WIDTH = 160,
    COLUMN_PUBKEY_WIDTH = 80,
};

// Multisig table

enum MultisigRoles
{
    DetailsRole = Qt::UserRole,
};

struct MultisigTableObject
{
    int m;
    QString address;
    QString balance;
};

enum
{
    COLUMN_M = 0,
    COLUMN_ADDRESS,
    COLUMN_BALANCE,
};

enum
{
    COLUMN_M_WIDTH = 120,
    COLUMN_ADDRESS_WIDTH = 450,
    COLUMN_BALANCE_WIDTH = 80,
};

class MultisigLoungeDialog : public QDialog
{
    Q_OBJECT

public:
    explicit MultisigLoungeDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~MultisigLoungeDialog();

    void UpdateOnShow();

private:
    Ui::MultisigLoungeDialog *ui;

    const PlatformStyle *platformStyle;

    std::vector<PartnerTableObject> vPartner;
    std::vector<MultisigTableObject> vMultisig;

    QMenu *contextMenuMultisig = nullptr;

    MultisigDialog *multisigDialog = nullptr;

    void UpdateMultisigs();
    void UpdatePartners();
    void AddPartner(const PartnerTableObject& obj);

private Q_SLOTS:
    void on_pushButtonAdd_clicked();
    void multisigContextualMenu(const QPoint &);
    void on_multisigTransferAction_clicked();
    void on_multisigDetailsAction_clicked();
    void on_pushButtonMultisigDialog_clicked();
    void on_tableWidgetPartner_itemChanged(QTableWidgetItem*);
};

#endif // MULTISIGLOUNGEDIALOG_H
