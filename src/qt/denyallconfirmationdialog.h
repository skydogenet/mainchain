// Copyright (c) 2022- The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DENYALLCONFIRMATIONDIALOG_H
#define DENYALLCONFIRMATIONDIALOG_H

#include <QDialog>

namespace Ui {
class DenyAllConfirmationDialog;
}

class DenyAllConfirmationDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DenyAllConfirmationDialog(QWidget *parent = nullptr);
    ~DenyAllConfirmationDialog();

    bool GetConfirmed();
    unsigned int GetSkipScore();
    unsigned int GetDelayMinutes();

private Q_SLOTS:
    void on_pushButtonConfirm_clicked();
    void on_pushButtonCancel_clicked();
    void on_pushButtonDefaultNormal_clicked();
    void on_pushButtonDefaultParanoid_clicked();

private:
    Ui::DenyAllConfirmationDialog *ui;

    bool fConfirmed;
    unsigned int nSkipScore;
    unsigned int nDelayMinutes;
};

#endif // DENYALLCONFIRMATIONDIALOG_H
