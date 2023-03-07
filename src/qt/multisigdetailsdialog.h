// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef MULTISIGDETAILSDIALOG_H
#define MULTISIGDETAILSDIALOG_H

#include <QDialog>

namespace Ui {
class MultisigDetailsDialog;
}

class MultisigDetailsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit MultisigDetailsDialog(QWidget *parent = nullptr);
    ~MultisigDetailsDialog();

    void SetDetails(const QString& details);

private:
    Ui::MultisigDetailsDialog *ui;
};

#endif // MULTISIGDETAILSDIALOG_H
