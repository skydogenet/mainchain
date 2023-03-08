// Copyright (c) 2022- The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DENIALSCHEDULEDIALOG_H
#define DENIALSCHEDULEDIALOG_H

#include <QDialog>

#include <QDateTime>

namespace Ui {
class DenialScheduleDialog;
}

class DenialScheduleDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DenialScheduleDialog(QWidget *parent = nullptr);
    ~DenialScheduleDialog();

    QDateTime GetDateTime();
    bool GetScheduled();

private Q_SLOTS:
    void on_dateTimeEdit_dateTimeChanged(QDateTime dateTime);
    void on_pushButtonSchedule_clicked();
    void on_pushButtonReset_clicked();
    void on_pushButtonRandom_clicked();

private:
    Ui::DenialScheduleDialog *ui;

    QDateTime dateTimeSelected;
    bool fScheduled;
};

#endif // DENIALSCHEDULEDIALOG_H
