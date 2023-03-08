// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CREATEWALLETDIALOG_H
#define CREATEWALLETDIALOG_H

#include <QDialog>

#include <uint256.h>

class PlatformStyle;

namespace Ui {
class CreateWalletDialog;
}

QT_BEGIN_NAMESPACE
class QString;
class QTableWidgetItem;
QT_END_NAMESPACE

// Word list table columns
enum
{
    COLUMN_BIN = 0,
    COLUMN_INDEX,
    COLUMN_WORD,
};

// Word list table column width
enum
{
    COLUMN_BIN_WIDTH = 160,
    COLUMN_INDEX_WIDTH = 80,
    COLUMN_INDEX_RESTORE_WIDTH = 180,
    COLUMN_WORD_WIDTH = 150,
};

struct WordTableObject
{
    QString bin;
    QString index;
    QString word;
};

class CreateWalletDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CreateWalletDialog(const PlatformStyle *platformStyle, QWidget *parent = nullptr);
    ~CreateWalletDialog();

    void SetRestoreMode();
    void SetCreateMode();

private:
    Ui::CreateWalletDialog *ui;

    const PlatformStyle *platformStyle;

    std::vector<WordTableObject> vWords;

    QString xpub;
    QString v3;

    std::vector<WordTableObject> EntropyToWordList(const std::vector<unsigned char>& vchEntropy, const std::vector<unsigned char>& vchEntropyHash);

    void Clear();

    bool fCreateMode;
    bool fRestoreMode;

private Q_SLOTS:
    void on_pushButtonHelp_clicked();
    void on_lineEditEntropy_textChanged(QString text);
    void on_tableWidgetWords_itemChanged(QTableWidgetItem* item);
    void on_pushButtonCopyXPub_clicked();
    void on_pushButtonCopyV3_clicked();
    void on_pushButtonRandom_clicked();
};

bool EntropyToKeys(const std::vector<unsigned char>& vchEntropy, std::string& strXPub, std::string& strXPriv, std::string& strV3, std::vector<std::string>& vChildAddr);

#endif // CREATEWALLETDIALOG_H
