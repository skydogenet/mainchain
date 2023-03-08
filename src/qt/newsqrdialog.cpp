// Copyright (c) 2021-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/newsqrdialog.h>
#include <qt/forms/ui_newsqrdialog.h>

#if defined(HAVE_CONFIG_H)
#include <config/skydoge-config.h> /* for USE_QRCODE */
#endif

#ifdef USE_QRCODE
#include <qrencode.h>
#endif

NewsQRDialog::NewsQRDialog(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::NewsQRDialog)
{
    ui->setupUi(this);
}

NewsQRDialog::~NewsQRDialog()
{
    delete ui;
}

void NewsQRDialog::SetURL(const QString& url)
{
#ifdef USE_QRCODE
    QRcode *code = QRcode_encodeString(url.toUtf8().constData(), 0, QR_ECLEVEL_L, QR_MODE_8, 1);
    QImage qr;
    if (code) {
        qr = QImage(code->width + 8, code->width + 8, QImage::Format_RGB32);
        qr.fill(0xffffff);

        unsigned char *data = code->data;
        for (int y = 0; y < code->width; y++) {
            for (int x = 0; x < code->width; x++) {
                qr.setPixel(x + 4, y + 4, ((*data & 1) ? 0x0 : 0xffffff));
                data++;
            }
        }

        QRcode_free(code);
        ui->image->setPixmap(QPixmap::fromImage(qr).scaled(600, 600));
    }
    ui->label->setText(url);
#endif
}
