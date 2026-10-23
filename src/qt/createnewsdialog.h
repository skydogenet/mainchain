// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CREATENEWSDIALOG_H
#define CREATENEWSDIALOG_H

#include <QDialog>

class NewsTypesTableModel;
class PlatformStyle;
class WalletModel;

namespace Ui {
class CreateNewsDialog;
}

class CreateNewsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CreateNewsDialog(const PlatformStyle *_platformStyle, QWidget *parent = nullptr);
    ~CreateNewsDialog();

    void setNewsTypesModel(NewsTypesTableModel* model);
    void setWalletModel(WalletModel* model);

public Q_SLOTS:
    void updateTypes();

private Q_SLOTS:
    void on_pushButtonCreate_clicked();
    void on_pushButtonHelp_clicked();
    void on_plainTextEdit_textChanged();

private:
    Ui::CreateNewsDialog *ui;

    QString cacheText;

    NewsTypesTableModel* newsTypesModel = nullptr;

    //! Needed to prompt for the passphrase on an encrypted wallet.
    WalletModel* walletModel = nullptr;

    const PlatformStyle *platformStyle = nullptr;
};

#endif // CREATENEWSDIALOG_H
