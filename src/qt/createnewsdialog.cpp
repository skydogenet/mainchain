// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/createnewsdialog.h>
#include <qt/forms/ui_createnewsdialog.h>

#include <amount.h>
#include <wallet/wallet.h>
#include <txdb.h>
#include <validation.h>

#include <qt/skydogeunits.h>
#include <qt/newstablemodel.h>
#include <qt/newstypestablemodel.h>
#include <qt/platformstyle.h>

#include <QMessageBox>

CreateNewsDialog::CreateNewsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CreateNewsDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);
    ui->feeAmount->setValue(0);

    ui->labelCharsRemaining->setText(QString::number(NEWS_HEADLINE_CHARS));

    ui->pushButtonCreate->setIcon(platformStyle->SingleColorIcon(":/icons/broadcastnews"));
    ui->pushButtonHelp->setIcon(platformStyle->SingleColorIcon(":/icons/transaction_0"));
}

CreateNewsDialog::~CreateNewsDialog()
{
    delete ui;
}

void CreateNewsDialog::on_pushButtonCreate_clicked()
{
    if (!newsTypesModel)
        return;

    QMessageBox messageBox;

    const CAmount& nFee = ui->feeAmount->value();
    std::string strText = ui->plainTextEdit->toPlainText().toStdString();

    // Format strings for confirmation dialog
    QString strFee = BitcoinUnits::formatWithUnit(BitcoinUnit::SKYDOGE, nFee, false, BitcoinUnits::separatorAlways);

    // Show confirmation dialog
    int nRes = QMessageBox::question(this, tr("Confirm news broadcast"),
        tr("Are you sure you want to spend %1 to broadcast this news?").arg(strFee),
        QMessageBox::Ok, QMessageBox::Cancel);

    if (nRes == QMessageBox::Cancel)
        return;

#ifdef ENABLE_WALLET
    if (vpwallets.empty()) {
        messageBox.setWindowTitle("Wallet Error!");
        messageBox.setText("No active wallets to create the transaction.");
        messageBox.exec();
        return;
    }

    if (vpwallets[0]->IsLocked()) {
        // Locked wallet message box
        messageBox.setWindowTitle("Wallet locked!");
        messageBox.setText("Wallet must be unlocked to create transactions.");
        messageBox.exec();
        return;
    }

    // Lookup selected type
    NewsType type;
    if (!newsTypesModel->GetType(ui->comboBoxCategory->currentIndex(), type)) {
        messageBox.setWindowTitle("Invalid news type!");
        messageBox.setText("Failed to locate news type!");
        messageBox.exec();
        return;
    }

    // Block until the wallet has been updated with the latest chain tip
    vpwallets[0]->BlockUntilSyncedToCurrentChain();

    // Get hex bytes of data
    std::string strHex = HexStr(strText.begin(), strText.end());
    std::vector<unsigned char> vBytes = ParseHex(strHex);

    // Create news OP_RETURN script
    CScript script;
    script.resize(vBytes.size() + type.header.size() + 1);
    script[0] = OP_RETURN;
    memcpy(&script[1], type.header.data(), type.header.size());
    memcpy(&script[type.header.size() + 1], vBytes.data(), vBytes.size());

    CTransactionRef tx;
    std::string strFail = "";
    if (!vpwallets[0]->CreateOPReturnTransaction(tx, strFail, nFee, script))
    {
        messageBox.setWindowTitle("Creating transaction failed!");
        QString createError = "Error creating transaction!\n\n";
        createError += QString::fromStdString(strFail);
        messageBox.setText(createError);
        messageBox.exec();
        return;
    }

    // Success message box
    messageBox.setWindowTitle("Transaction created!");
    QString result = "txid: " + QString::fromStdString(tx->GetHash().ToString());
    result += "\n";
    messageBox.setText(result);
    messageBox.exec();
#endif
}

void CreateNewsDialog::on_pushButtonHelp_clicked()
{
    QMessageBox messageBox;
    messageBox.setWindowTitle("News Help");
    QString str = tr("With this page you can pay a fee to broadcast news on any topic. "
                     "Clicking \"Broadcast\" will create a transaction with an OP_RETURN "
                     "output that encodes the text you have entered. Anyone subscribed to "
                     "the topic will see posts filtered by time and sorted by fee amount.");
    messageBox.setText(str);
    messageBox.exec();
}

void CreateNewsDialog::on_plainTextEdit_textChanged()
{
    QString currentText = ui->plainTextEdit->toPlainText();
    if (currentText == cacheText)
        return;

    cacheText = currentText;
    std::string strText = currentText.toStdString();

    // Reset highlights
    QTextCursor cursor(ui->plainTextEdit->document());
    cursor.setPosition(0, QTextCursor::MoveAnchor);
    cursor.setPosition(strText.size(), QTextCursor::KeepAnchor);
    cursor.setCharFormat(QTextCharFormat());

    // Update the number of characters remaining label
    if (strText.size() >= NEWS_HEADLINE_CHARS)
        ui->labelCharsRemaining->setText(QString::number(0));
    else
        ui->labelCharsRemaining->setText(QString::number(NEWS_HEADLINE_CHARS - strText.size()));

    // Where the headline ends
    size_t nHeadlineEnd = 0;

    // Check for any newlines
    bool fNewLine = false;
    for (size_t i = 0; i < strText.size(); i++) {
        if (strText[i] == '\n' || strText[i] == '\r') {
            ui->labelCharsRemaining->setText(QString::number(0));
            nHeadlineEnd = i;
            fNewLine = true;
            break;
        }
    }

    if (fNewLine)
        nHeadlineEnd = nHeadlineEnd < NEWS_HEADLINE_CHARS ? nHeadlineEnd : NEWS_HEADLINE_CHARS;
    else
        nHeadlineEnd = strText.size() < NEWS_HEADLINE_CHARS ? strText.size() : NEWS_HEADLINE_CHARS;

    // Highlight characters that will fit into the headline
    cursor = QTextCursor(ui->plainTextEdit->document());

    QTextCharFormat highlight;
    highlight.setBackground(Qt::green);

    cursor.setPosition(0, QTextCursor::MoveAnchor);
    cursor.setPosition(nHeadlineEnd, QTextCursor::KeepAnchor);
    cursor.setCharFormat(highlight);
}

void CreateNewsDialog::updateTypes()
{
    if (!newsTypesModel)
        return;

    ui->comboBoxCategory->clear();

    std::vector<NewsType> vType = newsTypesModel->GetTypes();

    for (const NewsType t : vType)
        ui->comboBoxCategory->addItem(QString::fromStdString(t.title));
}

void CreateNewsDialog::setNewsTypesModel(NewsTypesTableModel* newsTypesModelIn)
{
    newsTypesModel = newsTypesModelIn;
    updateTypes();
}
