// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MULTISIGDIALOG_H
#define MULTISIGDIALOG_H

#include <QDialog>

class PlatformStyle;

namespace Ui {
class MultisigDialog;
}

class MultisigDialog : public QDialog
{
    Q_OBJECT

public:
    explicit MultisigDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~MultisigDialog();

private:
    Ui::MultisigDialog *ui;

    const PlatformStyle *platformStyle;

    void SetCreateMSErrorOutput(const QString& error);
    void SetTransferErrorOutput(const QString& error);
    void SetSignErrorOutput(const QString& error);

private Q_SLOTS:
    void on_plainTextEditCreateMS_textChanged();
    void on_pushButtonSign_clicked();
    void on_pushButtonTransfer_clicked();
    void on_spinBoxCreateMSReq_editingFinished();

    void updateCreateMSOutput();
};

#endif // MULTISIGDIALOG_H
