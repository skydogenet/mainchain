// Copyright (c) 2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef HASHCALCDIALOG_H
#define HASHCALCDIALOG_H

#include <QDialog>

class PlatformStyle;

namespace Ui {
class HashCalcDialog;
}

class HashCalcDialog : public QDialog
{
    Q_OBJECT

public:
    explicit HashCalcDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~HashCalcDialog();

public Q_SLOTS:
    void on_plainTextEdit_textChanged();

    void on_pushButtonClear_clicked();
    void on_pushButtonPaste_clicked();
    void on_pushButtonHelp_clicked();
    void on_pushButtonHelpInvalidHex_clicked();
    void on_radioButtonHex_toggled(bool fChecked);
    void on_pushButtonFlip_clicked();

private:
    Ui::HashCalcDialog *ui;

    const PlatformStyle *platformStyle;

    void ShowInvalidHexWarning(bool fShow);
    void ClearOutput();
    void UpdateOutput();
};

#endif // HASHCALCDIALOG_H
