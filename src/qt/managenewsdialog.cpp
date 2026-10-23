// Copyright (c) 2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/managenewsdialog.h>
#include <qt/forms/ui_managenewsdialog.h>

#include <QFile>
#include <QMenu>
#include <QMessageBox>
#include <QPoint>
#include <QTextStream>

#include <qt/csvmodelwriter.h>
#include <qt/guiutil.h>
#include <qt/newstypestablemodel.h>
#include <qt/newsqrdialog.h>
#include <qt/platformstyle.h>

#include <script/script.h>
#include <txdb.h>
#include <validation.h>

ManageNewsDialog::ManageNewsDialog(const PlatformStyle *_platformStyle, QWidget *parent) :
    QDialog(parent),
    ui(new Ui::ManageNewsDialog),
    platformStyle(_platformStyle)
{
    ui->setupUi(this);

    ui->tableViewTypes->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableViewTypes->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableViewTypes->setContextMenuPolicy(Qt::CustomContextMenu);
    ui->tableViewTypes->resizeColumnsToContents();

    // Context menu
    QAction *shareAction = new QAction(tr("Copy sharing URL"), this);
    QAction *qrAction = new QAction(tr("Show QR"), this);
    QAction *removeAction = new QAction(tr("Delete"), this);

    contextMenu = new QMenu(this);
    contextMenu->setObjectName("contextMenuManageNews");
    contextMenu->addAction(shareAction);
    contextMenu->addAction(qrAction);
    contextMenu->addAction(removeAction);

    connect(ui->tableViewTypes, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(contextualMenu(QPoint)));
    connect(shareAction, SIGNAL(triggered()), this, SLOT(copyShareURL()));
    connect(removeAction, SIGNAL(triggered()), this, SLOT(removeType()));
    connect(qrAction, SIGNAL(triggered()), this, SLOT(showQR()));

    ui->pushButtonImport->setIcon(platformStyle->SingleColorIcon(":/icons/open"));
    ui->pushButtonExport->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
    ui->pushButtonPaste->setIcon(platformStyle->SingleColorIcon(":/icons/editpaste"));
    ui->pushButtonAdd->setIcon(platformStyle->SingleColorIcon(":/icons/add"));
    ui->pushButtonWrite->setIcon(platformStyle->SingleColorIcon(":/icons/add"));
    ui->pushButtonDefaults->setIcon(platformStyle->SingleColorIcon(":/icons/remove"));
}

ManageNewsDialog::~ManageNewsDialog()
{
    delete ui;
}

void ManageNewsDialog::on_pushButtonWrite_clicked()
{
    if (!newsTypesModel)
        return;

    std::string strTitle = ui->lineEditTitle->text().toStdString();
    if (strTitle.empty()) {
        QMessageBox::critical(this, tr("Failed to create news type"),
            tr("News type must have a title!\n"),
            QMessageBox::Ok);
        return;
    }

    std::string strBytes = ui->lineEditBytes->text().toStdString();
    if (!IsHexNumber(strBytes)) {
        QMessageBox::critical(this, tr("Failed to create news type"),
            tr("Invalid header bytes!\n\n"
               "Header bytes must be four valid hexidecimal characters with no prefix."),
            QMessageBox::Ok);
        return;
    }

    // Create header bytes
    std::vector<unsigned char> vBytes = ParseHex(strBytes);

    // Copy header bytes into OP_RETURN script
    CScript script(vBytes.begin(), vBytes.end());

    if (script.size() != 4) {
        QMessageBox::critical(this, tr("Failed to create news type"),
            tr("Invalid hex bytes length!\n\n"
               "Header bytes must be four valid hexidecimal characters with no prefix."),
            QMessageBox::Ok);
        return;
    }

    // New news type object
    NewsType type;
    type.title = strTitle;
    type.header = script;
    type.nDays = ui->spinBoxDays->value();

    if (newsTypesModel->IsDefaultType(type.header)) {
        QMessageBox::critical(this, tr("Failed to create news type"),
            tr("Cannot re-create default news type!\n"),
            QMessageBox::Ok);
        return;
    }

    if (!newsTypesModel->IsHeaderUnique(type.header)) {
        QMessageBox::critical(this, tr("Failed to create news type"),
            tr("News type does not have unique header bytes!\n"),
            QMessageBox::Ok);
        return;
    }

    // Save new type
    popreturndb->WriteNewsType(type);

    // Tell widgets we have updated custom types
    newsTypesModel->updateModel();
    Q_EMIT(NewTypeCreated());

    QMessageBox::information(this, tr("News type created"),
        tr("News type created!"),
        QMessageBox::Ok);
}

void ManageNewsDialog::on_pushButtonPaste_clicked()
{
    ui->lineEditURL->setText(GUIUtil::getClipboard());
}

void ManageNewsDialog::on_pushButtonAdd_clicked()
{
    if (!newsTypesModel)
        return;

    QString url = ui->lineEditURL->text();
    NewsType type;
    if (!type.SetURL(url.toStdString())) {
        QMessageBox::critical(this, tr("Failed to add news type"),
            tr("Invalid news type URL!\n"),
            QMessageBox::Ok);
        return;
    }

    if (newsTypesModel->IsDefaultType(type.header)) {
        QMessageBox::critical(this, tr("Failed to add news type"),
            tr("Cannot re-add default news type!\n"),
            QMessageBox::Ok);
        return;
    }

    if (!newsTypesModel->IsHeaderUnique(type.header)) {
        QMessageBox::critical(this, tr("Failed to add news type"),
            tr("News type does not have unique header bytes!\n"),
            QMessageBox::Ok);
        return;
    }

    // Save shared custom type
    popreturndb->WriteNewsType(type);

    // Tell widgets we have updated custom types
    newsTypesModel->updateModel();
    Q_EMIT(NewTypeCreated());

    QMessageBox::information(this, tr("News type added"),
        tr("News type added!"),
        QMessageBox::Ok);
}

void ManageNewsDialog::on_pushButtonExport_clicked()
{
    if (!newsTypesModel)
        return;

    QString filename = GUIUtil::getSaveFileName(this,
        tr("Export News Types"), QString(),
        tr("Comma separated file (*.csv)"), nullptr);

    if (filename.isNull())
        return;

    CSVModelWriter writer(filename);

    // name, column, role
    writer.setModel(newsTypesModel);
    writer.addColumn(tr("URL"), 0, NewsTypesTableModel::URLRole);

    if(!writer.write()) {
        QMessageBox::critical(this, tr("Exporting Failed"),
            tr("There was an error trying to export news types to %1\n").arg(filename),
            QMessageBox::Ok);
    }
    else {
        QMessageBox::information(this, tr("Exporting Successful"),
            tr("News types successfully saved to %1\n").arg(filename),
            QMessageBox::Ok);
    }
}

void ManageNewsDialog::on_pushButtonImport_clicked()
{
    QString filename = GUIUtil::getOpenFileName(this, tr("Select news types file to open"), "", "", nullptr);
    if (filename.isEmpty())
        return;

    QFile file(filename);
    if (!file.open(QIODevice::ReadWrite | QIODevice::Text)) {
        QMessageBox::critical(this, tr("Import Failed"),
            tr("File cannot be opened!\n"),
            QMessageBox::Ok);
        return;
    }

    // Read
    QTextStream in(&file);
    QString str = in.readAll();
    file.close();

    // Split file by line into list
    QStringList list = str.split("\n", QString::SkipEmptyParts);

    // Remove first line of CSV file
    list.removeFirst();

    // Collect news types
    std::vector<NewsType> vType;
    for (const QString& str : list) {
        NewsType type;
        if (!type.SetURL(str.toStdString().substr(1, str.size() - 2))) {
            QMessageBox::critical(this, tr("Import Failed"),
                tr("File contains invalid URL: %1!\n").arg(str),
                QMessageBox::Ok);
            return;
        }

        if (newsTypesModel->IsDefaultType(type.header))
            continue;
        if (!newsTypesModel->IsHeaderUnique(type.header))
            continue;

        vType.push_back(type);
    }

    // Save news types
    for (const NewsType& type : vType)
        popreturndb->WriteNewsType(type);

    // Tell widgets we have updated custom types
    newsTypesModel->updateModel();
    Q_EMIT(NewTypeCreated());

    QMessageBox::information(this, tr("Import Complete"),
        tr("News types imported from file!\n"),
        QMessageBox::Ok);
}

void ManageNewsDialog::on_pushButtonDefaults_clicked()
{
    if (!newsTypesModel)
        return;

    // Show confirmation dialog
    int nRes = QMessageBox::question(this, tr("Confirm news types reset"),
        tr("Are you sure you want to reset your news types? "
           "This will delete all but the built-in news types."),
        QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Cancel);

    if (nRes == QMessageBox::Cancel)
        return;

    std::vector<NewsType> vType = newsTypesModel->GetTypes();
    for (const NewsType& type : vType)
        popreturndb->EraseNewsType(type.GetHash());

    // Tell widgets we have updated custom types
    newsTypesModel->updateModel();
    Q_EMIT(NewTypeCreated());

    QMessageBox::information(this, tr("News types reset!"),
        tr("All news types have been reset!\n"),
        QMessageBox::Ok);
}

void ManageNewsDialog::contextualMenu(const QPoint& point)
{
    QModelIndex index = ui->tableViewTypes->indexAt(point);
    if (index.isValid())
        contextMenu->popup(ui->tableViewTypes->viewport()->mapToGlobal(point));
}

void ManageNewsDialog::copyShareURL()
{
    if (!newsTypesModel)
        return;

    if (!ui->tableViewTypes->selectionModel())
        return;

    QModelIndexList selection = ui->tableViewTypes->selectionModel()->selectedRows();
    if (selection.isEmpty())
        return;

    QModelIndex index = selection.front();
    if (!index.isValid())
        return;

    int nRow = index.row();

    QString url = "";
    if (newsTypesModel->GetURLAtRow(nRow, url))
        GUIUtil::setClipboard(url);
}

void ManageNewsDialog::showQR()
{
    if (!newsTypesModel)
        return;

    if (!ui->tableViewTypes->selectionModel())
        return;

    QModelIndexList selection = ui->tableViewTypes->selectionModel()->selectedRows();
    if (selection.isEmpty())
        return;

    QModelIndex index = selection.front();
    if (!index.isValid())
        return;

    int nRow = index.row();

    QString url = "";
    if (!newsTypesModel->GetURLAtRow(nRow, url)) {
        QMessageBox::critical(this, tr("Cannot show QR!"),
            tr("Failed to locate news type URL!\n"),
            QMessageBox::Ok);
        return;
    }

    NewsQRDialog qrDialog;
    qrDialog.SetURL(url);
    qrDialog.exec();
}

void ManageNewsDialog::removeType()
{
    if (!newsTypesModel)
        return;

    if (!ui->tableViewTypes->selectionModel())
        return;

    QModelIndexList selection = ui->tableViewTypes->selectionModel()->selectedRows();
    if (selection.isEmpty())
        return;

    QModelIndex index = selection.front();
    if (!index.isValid())
        return;

    int nRow = index.row();

    QString url = "";
    if (!newsTypesModel->GetURLAtRow(nRow, url))
        return;

    NewsType type;
    if (!type.SetURL(url.toStdString())) {
        QMessageBox::critical(this, tr("Cannot erase!"),
            tr("Invalid news type URL!\n"),
            QMessageBox::Ok);
        return;
    }

    if (newsTypesModel->IsDefaultType(type.header)) {
        QMessageBox::critical(this, tr("Cannot erase!"),
            tr("Cannot erase default type!\n"),
            QMessageBox::Ok);
        return;
    }

    // Show confirmation dialog
    int nRes = QMessageBox::question(this, tr("Confirm erasing news type"),
        tr("Are you sure you want to erase %1?").arg(QString::fromStdString(type.title)),
        QMessageBox::Ok | QMessageBox::Cancel, QMessageBox::Cancel);

    if (nRes == QMessageBox::Cancel)
        return;

    popreturndb->EraseNewsType(type.GetHash());

    // Tell widgets we have updated custom types
    newsTypesModel->updateModel();
    Q_EMIT(NewTypeCreated());

    QMessageBox::information(this, tr("News type erased!"),
        tr("News type removed from database!\n"),
        QMessageBox::Ok);
}

void ManageNewsDialog::setNewsTypesModel(NewsTypesTableModel* model)
{
    newsTypesModel = model;
    ui->tableViewTypes->setModel(newsTypesModel);
    ui->tableViewTypes->resizeColumnsToContents();
}
