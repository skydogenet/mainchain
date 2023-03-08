// Copyright (c) 2023 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/multisigdialog.h>
#include <qt/forms/ui_multisigdialog.h>

#include <qt/drivechainamountfield.h>
#include <qt/guiutil.h>
#include <qt/platformstyle.h>

#include <amount.h>
#include <base58.h>
#include <core_io.h>
#include <keystore.h>
#include <pubkey.h>
#include <policy/policy.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/standard.h>
#include <utilmoneystr.h>
#include <utilstrencodings.h>

MultisigDialog::MultisigDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::MultisigDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    ui->plainTextEditCreateMS->setPlaceholderText("Enter up to 16 pubkeys, one per line. Ex:\n" \
                                                  "023bd869b33291776477d3ca56ea8062750542163a57c50b91cdb0470fa64cf605\n" \
                                                  "03f786ec75e8e6635500d276f232e051ec1a85dc82eff419ba31492da88876469e\n");
}

MultisigDialog::~MultisigDialog()
{
    delete ui;
}

void MultisigDialog::on_plainTextEditCreateMS_textChanged()
{
    updateCreateMSOutput();
}

void MultisigDialog::on_pushButtonSign_clicked()
{
    std::string strP2SH = ui->lineEditSignP2SH->text().toStdString();
    std::string strRedeem = ui->lineEditSignRedeem->text().toStdString();
    std::string strTx = ui->lineEditSignTx->text().toStdString();
    std::string strKey = ui->lineEditSignKey->text().toStdString();

    // Check prevout amount

    if (!ui->amountSign->validate()) {
        ui->amountSign->setValid(false);
        return;
    }
    // Sending a zero amount is invalid
    if (ui->amountSign->value(0) <= 0) {
        ui->amountSign->setValid(false);
        return;
    }

    const CAmount amountSign = ui->amountSign->value();

    CMutableTransaction mtx;
    if (!DecodeHexTx(mtx, strTx)) {
        SetSignErrorOutput("Failed to decode transaction!\n");
        return;
    }

    if (!mtx.vin.size()) {
        SetSignErrorOutput("Invalid transaction!\n");
        return;
    }

    CBasicKeyStore keystore;
    CBitcoinSecret vchSecret;
    if (!vchSecret.SetString(strKey)) {
        SetSignErrorOutput("Invalid private key!\n");
        return;
    }
    CKey key = vchSecret.GetKey();
    if (!key.IsValid()) {
        SetSignErrorOutput("Private key outside allowed range!\n");
        return;
    }
    keystore.AddKey(key);

    std::vector<unsigned char> vRedeemBytes(ParseHex(strRedeem));
    CScript scriptRedeem(vRedeemBytes.begin(), vRedeemBytes.end());
    keystore.AddCScript(scriptRedeem);

    std::vector<unsigned char> vPrevBytes(ParseHex(strP2SH));
    CScript scriptPrev(vPrevBytes.begin(), vPrevBytes.end());

    SignatureData sigdata;
    if (!ProduceSignature(MutableTransactionSignatureCreator(&keystore, &mtx, 0, amountSign, SIGHASH_ALL), scriptPrev, sigdata))
        SetSignErrorOutput("Failed to sign!\n");

    const CTransaction txCombine(mtx);
    sigdata = CombineSignatures(scriptPrev, TransactionSignatureChecker(&txCombine, 0, amountSign), sigdata, DataFromTransaction(txCombine, 0));

    UpdateTransaction(mtx, 0, sigdata);

    const CTransaction txConst(mtx);

    bool fMissing = false;
    ScriptError serror = SCRIPT_ERR_OK;
    if (!VerifyScript(txConst.vin[0].scriptSig, scriptPrev, &txConst.vin[0].scriptWitness, STANDARD_SCRIPT_VERIFY_FLAGS, TransactionSignatureChecker(&txConst, 0, amountSign), &serror)) {
        fMissing = true;
    }

    // Print out the signed tx

    QString output = "Signature added to transaction!\n\n";
    if (fMissing)
        output += "One or more signatures are still required!\n\n";
    else
        output += "Transaction fully signed and ready to broadcast (using the `sendrawtransaction` RPC)\n\n";

    output += "Signed transaction hex:\n";
    output += QString::fromStdString(EncodeHexTx(mtx)) + "\n";

    ui->textBrowserSignOutput->setPlainText(output);
}

void MultisigDialog::on_pushButtonTransfer_clicked()
{
    uint256 txid = uint256S(ui->lineEditTransferTXID->text().toStdString());
    int n = ui->spinBoxTransferN->value();

    // Check destination
    CTxDestination destination = DecodeDestination(ui->lineEditTransferDest->text().toStdString());
    if (!IsValidDestination(destination)) {
        SetTransferErrorOutput("Invalid destination!\n");
        return;
    }

    // Check change destination
    CTxDestination destinationChange = DecodeDestination(ui->lineEditTransferDestChange->text().toStdString());
    if (!IsValidDestination(destinationChange)) {
        SetTransferErrorOutput("Invalid change destination!\n");
        return;
    }

    // Check transfer and fee amounts

    if (!ui->amountTransfer->validate()) {
        ui->amountTransfer->setValid(false);
        return;
    }
    if (!ui->amountTransferFee->validate()) {
        ui->amountTransferFee->setValid(false);
        return;
    }

    // Sending a zero amount is invalid
    if (ui->amountTransfer->value(0) <= 0) {
        ui->amountTransfer->setValid(false);
        return;
    }
    if (ui->amountTransferFee->value(0) <= 0) {
        ui->amountTransferFee->setValid(false);
        return;
    }

    // Reject dust outputs:
    if (GUIUtil::isDust(ui->lineEditTransferDest->text(), ui->amountTransfer->value())) {
        ui->amountTransfer->setValid(false);
        return;
    }

    const CAmount amountTransfer = ui->amountTransfer->value();
    const CAmount amountTransferIn = ui->amountTransferIn->value();
    const CAmount amountTransferFee = ui->amountTransferFee->value();

    // Calculate change, check amount and fee
    CAmount amountChange = amountTransferIn - (amountTransfer + amountTransferFee);
    if (amountChange < 0) {
        SetTransferErrorOutput("Not enough input to cover output!\n");
        return;
    }

    // Create the unsigned multisig transfer transaction
    CMutableTransaction mtx;

    mtx.vin.push_back(CTxIn(COutPoint(txid, n)));
    mtx.vout.push_back(CTxOut(amountTransfer, GetScriptForDestination(destination)));
    if (amountChange) {
        mtx.vout.push_back(CTxOut(amountChange, GetScriptForDestination(destinationChange)));
    }

    QString output;
    output += "Tx Hex:\n";
    output += QString::fromStdString(EncodeHexTx(mtx)) + "\n\n";
    output += "Transaction details:\n";
    output += QString::fromStdString(CTransaction(mtx).ToString()) + "\n\n";

    ui->textBrowserTransferOutput->setPlainText(output);
}

void MultisigDialog::on_spinBoxCreateMSReq_editingFinished()
{
    updateCreateMSOutput();
}

void MultisigDialog::SetCreateMSErrorOutput(const QString& error)
{
    ui->textBrowserCreateMSOutput->setPlainText(error);
}

void MultisigDialog::SetTransferErrorOutput(const QString& error)
{
    ui->textBrowserTransferOutput->setPlainText(error);
}

void MultisigDialog::SetSignErrorOutput(const QString& error)
{
    ui->textBrowserSignOutput->setPlainText(error);
}

void MultisigDialog::updateCreateMSOutput()
{
    QString text = ui->plainTextEditCreateMS->toPlainText();
    if (text.isEmpty()) {
        ui->textBrowserCreateMSOutput->clear();

        // Update keys required label
        QString label = "of 0 total key(s) required to transfer from multisig.";
        ui->labelNReq->setText(label);

        return;
    }

    // Get a list of keys and check them
    QStringList listKeyText = text.split("\n");

    std::vector<CPubKey> vPubKey;
    for (int i = 0; i < listKeyText.size(); i++) {
        std::string strKey = listKeyText[i].toStdString();
        if (strKey.empty())
            continue;

        if (!IsHex(strKey)) {
            SetCreateMSErrorOutput("Not hex!\n");
            return;
        }

        if (strKey.size() != 66) {
            SetCreateMSErrorOutput("Invalid key size!\n");
            return;
        }

        CPubKey pubKey(ParseHex(strKey));
        if (!pubKey.IsFullyValid()) {
            SetCreateMSErrorOutput("Invalid key!\n");
            return;
        }

        vPubKey.push_back(pubKey);
    }

    int nRequired = ui->spinBoxCreateMSReq->value();

    if (nRequired < 1) {
        SetCreateMSErrorOutput("Multisignature must require at least one key to redeem!\n");
        return;
    }
    if ((int)vPubKey.size() < nRequired) {
        SetCreateMSErrorOutput("Not enough keys supplied!\n");
        return;
    }
    if (vPubKey.size() > 16) {
        SetCreateMSErrorOutput("Too many keys supplied (>16)!\n");
        return;
    }

    // Create multisig script (P2SH inner script / redeem script)
    CScript script = GetScriptForMultisig(nRequired, vPubKey);
    CScriptID id(script);

    std::string strDestination = EncodeDestination(id);
    std::string strRedeemScript = HexStr(script.begin(), script.end());

    CScript scriptP2SH = GetScriptForDestination(id);

    QString output = "Multisig created!:\n\n";
    output += "P2SH Address:\n" + QString::fromStdString(strDestination) + "\n\n";
    output += "P2SH Script Hex:\n" + QString::fromStdString(HexStr(scriptP2SH)) + "\n\n";
    output += "P2SH Script:\n" + QString::fromStdString(ScriptToAsmStr(scriptP2SH)) + "\n\n";
    output += "Redeem Script Hex:\n" + QString::fromStdString(strRedeemScript) + "\n\n";
    output += "Redeem Script:\n" + QString::fromStdString(ScriptToAsmStr(script)) + "\n\n";

    output += "Public key order:\n";
    for (size_t i = 0; i < vPubKey.size(); i++)
        output += QString::fromStdString(HexStr(vPubKey[i].begin(), vPubKey[i].end())) + "\n";

    output += "\nKeys required: " + QString::number(nRequired) + " / " + QString::number(vPubKey.size()) + "\n";

    ui->textBrowserCreateMSOutput->setPlainText(output);

    // Update keys required label
    QString label = "of " + QString::number(vPubKey.size());
    label += " total key(s) required to transfer from multisig.";
    ui->labelNReq->setText(label);
}
