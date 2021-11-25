// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/decodeviewdialog.h>
#include <qt/forms/ui_decodeviewdialog.h>

#include <qt/guiutil.h>
#include <qt/platformstyle.h>

DecodeViewDialog::DecodeViewDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::DecodeViewDialog)
{
    ui->setupUi(this);

    decode = "";
    hex = "";
    type = "";
}

DecodeViewDialog::~DecodeViewDialog()
{
    delete ui;
}

void DecodeViewDialog::SetData(const QString& decodeIn, const QString& hexIn, const QString& typeIn)
{
    decode = decodeIn;
    hex = hexIn;
    type = typeIn;

    ui->textBrowserDecode->setText(decode);
    ui->textBrowserHex->setText(hex);
    ui->labelType->setText(type);
}

void DecodeViewDialog::on_pushButtonCopyDecode_clicked()
{
    GUIUtil::setClipboard(decode);
}

void DecodeViewDialog::on_pushButtonCopyHex_clicked()
{
    GUIUtil::setClipboard(hex);
}

void DecodeViewDialog::SetPlatformStyle(const PlatformStyle* platformStyleIn)
{
    if (platformStyleIn) {
        platformStyle = platformStyleIn;

        // Set icons
        ui->pushButtonCopyDecode->setIcon(platformStyle->SingleColorIcon(":/icons/editcopy"));
        ui->pushButtonCopyHex->setIcon(platformStyle->SingleColorIcon(":/icons/editcopy"));
    }
}
