// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DECODEVIEWDIALOG_H
#define DECODEVIEWDIALOG_H

#include <QDialog>

class PlatformStyle;

QT_BEGIN_NAMESPACE
class QString;
QT_END_NAMESPACE

namespace Ui {
class DecodeViewDialog;
}

class DecodeViewDialog : public QDialog
{
    Q_OBJECT

public:
    explicit DecodeViewDialog(QWidget *parent = nullptr);
    ~DecodeViewDialog();

    void SetData(const QString& decodeIn, const QString& hexIn, const QString& typeIn);
    void SetPlatformStyle(const PlatformStyle* platformStyleIn);

private Q_SLOTS:
    void on_pushButtonCopyDecode_clicked();
    void on_pushButtonCopyHex_clicked();

private:
    Ui::DecodeViewDialog *ui;

    const PlatformStyle *platformStyle;
    QString decode;
    QString hex;
    QString type;
};

#endif // DECODEVIEWDIALOG_H
