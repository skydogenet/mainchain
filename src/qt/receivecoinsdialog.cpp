// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/wallet.h>
#include <validation.h>

#include <qt/forms/ui_receivecoinsdialog.h>

#include <qt/skydogeunits.h>
#include <qt/paymentrequestdialog.h>
#include <qt/platformstyle.h>
#include <qt/receivecoinsdialog.h>
#include <qt/walletmodel.h>

#if defined(HAVE_CONFIG_H)
#include <config/skydoge-config.h> /* for USE_QRCODE */
#endif

#ifdef USE_QRCODE
#include <qrencode.h>
#endif

ReceiveCoinsDialog::ReceiveCoinsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ReceiveCoinsDialog),
    model(nullptr),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    // Setup platform style single color icons
    ui->pushButtonNew->setIcon(platformStyle->SingleColorIcon(":/movies/spinner-000"));
    ui->pushButtonCopy->setIcon(platformStyle->SingleColorIcon(":/icons/editcopy"));
    ui->pushButtonPaymentRequest->setIcon(platformStyle->SingleColorIcon(":/icons/receiving_addresses"));

    requestDialog = new PaymentRequestDialog(platformStyle);
    requestDialog->setParent(this, Qt::Window);

    generateAddress();
}

void ReceiveCoinsDialog::setModel(WalletModel *_model)
{
    model = _model;

    if (model)
        requestDialog->setModel(model);
}

ReceiveCoinsDialog::~ReceiveCoinsDialog()
{
    delete ui;
}

void ReceiveCoinsDialog::generateQR(std::string data)
{
    if (data.empty())
        return;

    CTxDestination dest = DecodeDestination(data);
    if (!IsValidDestination(dest)) {
        return;
    }

#ifdef USE_QRCODE
    ui->QRCode->clear();

    QString encode = QString::fromStdString(data);
    QRcode *code = QRcode_encodeString(encode.toUtf8().constData(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);

    if (code) {
        QImage qr = QImage(code->width + 8, code->width + 8, QImage::Format_RGB32);
        qr.fill(0xffffff);

        unsigned char *data = code->data;
        for (int y = 0; y < code->width; y++) {
            for (int x = 0; x < code->width; x++) {
                qr.setPixel(x + 4, y + 4, ((*data & 1) ? 0x0 : 0xffffff));
                data++;
            }
        }

        QRcode_free(code);
        ui->QRCode->setPixmap(QPixmap::fromImage(qr).scaled(200, 200));
    }
#endif
}

void ReceiveCoinsDialog::generateAddress()
{
    if (vpwallets.empty())
        return;

    LOCK2(cs_main, vpwallets[0]->cs_wallet);

    vpwallets[0]->TopUpKeyPool();

    CPubKey newKey;
    if (vpwallets[0]->GetKeyFromPool(newKey)) {
        // We want a "legacy" type address
        OutputType type = OUTPUT_TYPE_LEGACY;
        CTxDestination dest = GetDestinationForKey(newKey, type);

        // Watch the script
        vpwallets[0]->LearnRelatedScripts(newKey, type);

        // Generate QR code
        std::string strAddress = EncodeDestination(dest);
        generateQR(strAddress);

        ui->lineEditAddress->setText(QString::fromStdString(strAddress));

        // Add to address book
        vpwallets[0]->SetAddressBook(dest, "", "receive");
    }
    // TODO display error if we didn't get a key
}

void ReceiveCoinsDialog::on_pushButtonCopy_clicked()
{
    GUIUtil::setClipboard(ui->lineEditAddress->text());
}

void ReceiveCoinsDialog::on_pushButtonNew_clicked()
{
    generateAddress();
}

void ReceiveCoinsDialog::on_pushButtonPaymentRequest_clicked()
{
    requestDialog->show();
}
