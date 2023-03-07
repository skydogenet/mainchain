// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/multisigdetailsdialog.h>
#include <qt/forms/ui_multisigdetailsdialog.h>

MultisigDetailsDialog::MultisigDetailsDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MultisigDetailsDialog)
{
    ui->setupUi(this);
}

MultisigDetailsDialog::~MultisigDetailsDialog()
{
    delete ui;
}

void MultisigDetailsDialog::SetDetails(const QString& details)
{
    ui->textBrowser->setPlainText(details);
}
