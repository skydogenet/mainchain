// Copyright (c) 2022- The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/denialscheduledialog.h>
#include <qt/forms/ui_denialscheduledialog.h>

#include <random.h>

DenialScheduleDialog::DenialScheduleDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DenialScheduleDialog)
{
    ui->setupUi(this);

    dateTimeSelected = QDateTime::currentDateTime();
    ui->dateTimeEdit->setDateTime(dateTimeSelected);
    fScheduled = false;
}

DenialScheduleDialog::~DenialScheduleDialog()
{
    delete ui;
}

QDateTime DenialScheduleDialog::GetDateTime()
{
    return dateTimeSelected;
}

bool DenialScheduleDialog::GetScheduled()
{
    return fScheduled;
}

void DenialScheduleDialog::on_dateTimeEdit_dateTimeChanged(QDateTime dateTime)
{
    dateTimeSelected = dateTime;
}

void DenialScheduleDialog::on_pushButtonSchedule_clicked()
{
    fScheduled = true;
    this->close();
}

void DenialScheduleDialog::on_pushButtonReset_clicked()
{
    ui->dateTimeEdit->setDateTime(QDateTime::currentDateTime());
}

void DenialScheduleDialog::on_pushButtonRandom_clicked()
{
    QDateTime dateTime = QDateTime::currentDateTime();

    unsigned int nDaysAdd = GetRand(7);
    unsigned int nSecsAdd = GetRand(999999);

    dateTime = dateTime.addDays(nDaysAdd);
    dateTime = dateTime.addSecs(nSecsAdd);

    ui->dateTimeEdit->setDateTime(dateTime);
}
