// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef OPRETURNDIALOG_H
#define OPRETURNDIALOG_H

#include <QDialog>

class ClientModel;
class CreateOPReturnDialog;
class OPReturnTableModel;
class PlatformStyle;

namespace Ui {
class OPReturnDialog;
}

QT_BEGIN_NAMESPACE
class QMenu;
class QModelIndex;
class QSortFilterProxyModel;
QT_END_NAMESPACE

class OPReturnDialog : public QDialog
{
    Q_OBJECT

public:
    explicit OPReturnDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~OPReturnDialog();

    void setClientModel(ClientModel *clientModel);

private:
    Ui::OPReturnDialog *ui;

    CreateOPReturnDialog *createOPReturnDialog = nullptr;
    OPReturnTableModel *opReturnModel = nullptr;
    const PlatformStyle *platformStyle = nullptr;
    QMenu *contextMenu;
    QSortFilterProxyModel *proxyModel;

private Q_SLOTS:
    void on_tableView_doubleClicked(const QModelIndex& index);
    void contextualMenu(const QPoint &);
    void showDetails();
    void copyDecode();
    void copyHex();
    void on_pushButtonCreate_clicked();
    void on_spinBoxDays_valueChanged(int nDays);
};

#endif // OPRETURNDIALOG_H
