// Copyright (c) 2022- The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/denyallconfirmationdialog.h>
#include <qt/forms/ui_denyallconfirmationdialog.h>

DenyAllConfirmationDialog::DenyAllConfirmationDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DenyAllConfirmationDialog)
{
    ui->setupUi(this);

    fConfirmed = false;
    nSkipScore = 3;
    nDelayMinutes = 0;
    ui->spinBoxHr->setValue(2);
}

DenyAllConfirmationDialog::~DenyAllConfirmationDialog()
{
    delete ui;
}

void DenyAllConfirmationDialog::on_pushButtonConfirm_clicked()
{
    // Set skip score, delay minutes
    nSkipScore = ui->spinBoxSkip->value();

    nDelayMinutes = ui->spinBoxMin->value() +
            ui->spinBoxHr->value() * 60 +
            ui->spinBoxDay->value() * 1440;

    fConfirmed = true;
    this->close();
}

void DenyAllConfirmationDialog::on_pushButtonCancel_clicked()
{
    fConfirmed = false;
    this->close();
}

bool DenyAllConfirmationDialog::GetConfirmed()
{
    return fConfirmed;
}

unsigned int DenyAllConfirmationDialog::GetSkipScore()
{
    return nSkipScore;
}

unsigned int DenyAllConfirmationDialog::GetDelayMinutes()
{
    return nDelayMinutes;
}

void DenyAllConfirmationDialog::on_pushButtonDefaultNormal_clicked()
{
    ui->spinBoxMin->setValue(0);
    ui->spinBoxHr->setValue(2);
    ui->spinBoxDay->setValue(0);
    ui->spinBoxSkip->setValue(3);
}

void DenyAllConfirmationDialog::on_pushButtonDefaultParanoid_clicked()
{
    ui->spinBoxMin->setValue(0);
    ui->spinBoxHr->setValue(0);
    ui->spinBoxDay->setValue(2);
    ui->spinBoxSkip->setValue(6);
}
