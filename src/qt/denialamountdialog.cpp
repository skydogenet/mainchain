// Copyright (c) 2022- The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/denialamountdialog.h>
#include <qt/forms/ui_denialamountdialog.h>

#include <qt/skydogeamountfield.h>

#include <QMessageBox>

DenialAmountDialog::DenialAmountDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DenialAmountDialog)
{
    ui->setupUi(this);

    amount = CAmount(0);
}

DenialAmountDialog::~DenialAmountDialog()
{
    delete ui;
}

void DenialAmountDialog::on_pushButtonCreate_clicked()
{
    QMessageBox messageBox;

    if (!ValidateAmount()) {
        messageBox.setWindowTitle("Invalid amount!");
        QString error = "Check the amount you have entered and try again.\n\n";
        messageBox.setText(error);
        messageBox.exec();
        return;
    }

    amount = ui->amount->value();
    this->close();
}

bool DenialAmountDialog::ValidateAmount()
{
    if (!ui->amount->validate()) {
        ui->amount->setValid(false);
        return false;
    }

    // Sending a zero amount is invalid
    if (ui->amount->value(0) <= 0) {
        ui->amount->setValid(false);
        return false;
    }

    //// Reject dust outputs?
    //if (GUIUtil::isDust(ui->payTo->text(), ui->payAmount->value())) {
    //    ui->payAmount->setValid(false);
    //    return false;
    //}

    return true;
}

CAmount DenialAmountDialog::GetAmount()
{
    return amount;
}

