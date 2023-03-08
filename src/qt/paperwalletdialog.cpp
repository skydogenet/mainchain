// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
#include <qt/paperwalletdialog.h>
#include <qt/forms/ui_paperwalletdialog.h>

#include <qt/platformstyle.h>

#include <QFile>
#include <QMessageBox>
#include <QPainter>
#include <QPdfWriter>
//#include <QPdfDocument> // TODO update Qt version?
//#include <QPrinter>
//#include <QPrintDialog>
#include <QScrollBar>
#include <QString>
#include <QTextStream>

#include <base58.h>
#include <bip39words.h>
#include <crypto/sha256.h>
#include <hash.h>
#include <key.h>
#include <utilstrencodings.h>
#include <utiltime.h>
#include <wallet/wallet.h>

#include <bitset>

PaperWalletDialog::PaperWalletDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::PaperWalletDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);
}

PaperWalletDialog::~PaperWalletDialog()
{
    delete ui;
}

//void PaperWalletDialog::on_pushButtonPrint_clicked()
//{
    // TODO

    // QPrinter printer;
    // printer.setOutputFormat(QPrinter::NativeFormat);

    // Let user select printer or file destination
    // QPrintDialog dialog(&printer, this);
    // if (dialog.exec() != QDialog::Accepted)
    //    return;

    // QFile file(":/doc/paperwallet");

//    QPdfDocument pdf;

//    printer.setOutputFormat(QPrinter::PdfFormat);

    // Setting this will make it print to a file instead of going to spools
//    printer.setOutputFileName("file.pdf");

//    QPdfWriter writer(&printer);

//    QPainter painter;
//    if (!painter.begin(&printer))
//        return;

//    painter.drawText(10, 10, "Hello printer!");

//    if (!printer.newPage())
//        return;

//    painter.drawText(10, 10, "Hello second page!");
//    painter.end();
//}


