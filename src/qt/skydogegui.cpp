// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/skydogegui.h>

#include <qt/blockexplorer.h>
#include <qt/clientmodel.h>
#include <qt/skydogeunits.h>
#include <qt/createwalletdialog.h>
#include <qt/denialdialog.h>
#include <qt/hashcalcdialog.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/mempooltablemodel.h>
#include <qt/miningdialog.h>
#include <qt/modaloverlay.h>
#include <qt/multisigloungedialog.h>
#include <qt/networkstyle.h>
#include <qt/notificator.h>
#include <qt/openuridialog.h>
#include <qt/optionsdialog.h>
#include <qt/optionsmodel.h>
#include <qt/paperwalletdialog.h>
#include <qt/platformstyle.h>
#include <qt/rpcconsole.h>
#include <qt/utilitydialog.h>
#include <qt/sidechainpage.h>
#include <qt/sidechaintabledialog.h>
#include <qt/sidechainwithdrawaltablemodel.h>

#ifdef ENABLE_WALLET
#include <qt/walletframe.h>
#include <qt/walletmodel.h>
#endif // ENABLE_WALLET

#ifdef Q_OS_MAC
#include <qt/macdockiconhandler.h>
#endif

#include <chainparams.h>
#include <init.h>
#include <ui_interface.h>
#include <util.h>

#include <QAction>
#include <QApplication>
#include <QDesktopWidget>
#include <QDragEnterEvent>
#include <QListWidget>
#include <QMenuBar>
#include <QMessageBox>
#include <QMimeData>
#include <QSettings>
#include <QShortcut>
#include <QStackedWidget>
#include <QStatusBar>
#include <QStyle>
#include <QTextStream>
#include <QTimer>
#include <QToolBar>
#include <QVBoxLayout>

#if QT_VERSION < 0x050000
#include <QTextDocument>
#include <QUrl>
#else
#include <QUrlQuery>
#endif

const std::string BitcoinGUI::DEFAULT_UIPLATFORM =
#if defined(Q_OS_MAC)
        "macosx"
#elif defined(Q_OS_WIN)
        "windows"
#else
        "other"
#endif
        ;

#include <boost/bind/placeholders.hpp>

using namespace boost::placeholders;

/** Display name for default wallet name. Uses tilde to avoid name
 * collisions in the future with additional wallets */
const QString BitcoinGUI::DEFAULT_WALLET = "~Default";

//old DC
//! The required delta of headers to the estimated number of available headers until we show the IBD progress
static constexpr int HEADER_HEIGHT_DELTA_SYNC = 24;

BitcoinGUI::BitcoinGUI(const PlatformStyle *_platformStyle, const NetworkStyle *networkStyle, QWidget *parent) :
    QMainWindow(parent),
    enableWallet(false),
    clientModel(0),
    walletFrame(0),
    withdrawalModel(0),
    memPoolModel(0),
    labelWalletEncryptionIcon(0),
    connectionsControl(0),
    labelBlocksIcon(0),
    labelProgressReason(0),
    labelProgressPercentage(0),
    labelNumBlocks(0),
    labelLastBlock(0),
    appMenuBar(0),
    overviewAction(0),
    historyAction(0),
    quitAction(0),
    sendCoinsAction(0),
    sidechainAction(0),
    sendCoinsMenuAction(0),
    usedSendingAddressesAction(0),
    usedReceivingAddressesAction(0),
    signVerifyMessageAction(0),
    aboutAction(0),
    receiveCoinsAction(0),
    receiveCoinsMenuAction(0),
    optionsAction(0),
    toggleHideAction(0),
    encryptWalletAction(0),
    backupWalletAction(0),
    changePassphraseAction(0),
    aboutQtAction(0),
    openRPCConsoleAction(0),
    openAction(0),
    showHelpMessageAction(0),
    showSidechainTableDialogAction(0),
    showMiningDialogAction(0),
    showPaperWalletDialogAction(0),
    showPaperCheckDialogAction(0),
    showCreateWalletDialogAction(0),
    showRestoreWalletDialogAction(0),
    showHashCalcDialogAction(0),
    showBlockExplorerDialogAction(0),
    showSCDBDialogAction(0),
    showDenialDialogAction(0),
    showBip47AddrDialogAction(0),
    showProofOfFundsDialogAction(0),
    showMerkleTreeDialogAction(0),
    showMultisigLoungeDialogAction(0),
    showSignaturesDialogAction(0),
    showBase58DialogAction(0),
    showGraffitiDialogAction(0),
    showMerchantsDialogAction(0),
    showTimestampDialogAction(0),
    showStorageDialogAction(0),
    showCoinNewsDialogAction(0),
    showMiningPoolsDialogAction(0),
    showNetworkDialogAction(0),
    showAddRemoveSidechainDialogAction(0),
    showFileBroadcastDialogAction(0),
    showSidechainTransferAction(0),
    showSendMoneyAction(0),
    showReceiveMoneyAction(0),
    trayIcon(0),
    trayIconMenu(0),
    notificator(0),
    rpcConsole(0),
    helpMessageDialog(0),
    prevBlocks(0),
    spinnerFrame(0),
    platformStyle(_platformStyle)
{
    QSettings settings;
    if (!restoreGeometry(settings.value("MainWindowGeometry").toByteArray())) {
        // Restore failed (perhaps missing setting), center the window
        move(QApplication::desktop()->availableGeometry().center() - frameGeometry().center());
    }

    QString windowTitle = tr(PACKAGE_NAME) + "  ";
#ifdef ENABLE_WALLET
    enableWallet = WalletModel::isWalletEnabled();
#endif // ENABLE_WALLET
    windowTitle += " " + networkStyle->getTitleAddText();

    windowTitle += "(Bitcoin Core 0.16.99 + BIPs 300 and 301)";

#ifndef Q_OS_MAC
    QApplication::setWindowIcon(networkStyle->getTrayAndWindowIcon());
    setWindowIcon(networkStyle->getTrayAndWindowIcon());
#else
    MacDockIconHandler::instance()->setIcon(networkStyle->getAppIcon());
#endif
    setWindowTitle(windowTitle);

#if defined(Q_OS_MAC) && QT_VERSION < 0x050000
    // This property is not implemented in Qt 5. Setting it has no effect.
    // A replacement API (QtMacUnifiedToolBar) is available in QtMacExtras.
    setUnifiedTitleAndToolBarOnMac(true);
#endif

    rpcConsole = new RPCConsole(_platformStyle, 0);
    helpMessageDialog = new HelpMessageDialog(this, false);
#ifdef ENABLE_WALLET
    if(enableWallet)
    {
        /** Create wallet frame and make it the central widget */
        walletFrame = new WalletFrame(_platformStyle, this);
        setCentralWidget(walletFrame);

        sidechainTableDialog = new SidechainTableDialog(this);

        miningDialog = new MiningDialog(platformStyle);
        miningDialog->setParent(this, Qt::Window);

        paperWalletDialog = new PaperWalletDialog(platformStyle);
        paperWalletDialog->setParent(this, Qt::Window);

        createWalletDialog = new CreateWalletDialog(platformStyle);
        createWalletDialog->setParent(this, Qt::Window);

        hashCalcDialog = new HashCalcDialog(platformStyle);
        hashCalcDialog->setParent(this, Qt::Window);

        blockExplorerDialog = new BlockExplorer(platformStyle);
        blockExplorerDialog->setParent(this, Qt::Window);

        denialDialog = new DenialDialog(platformStyle);
        denialDialog->setParent(this, Qt::Window);

        multisigLoungeDialog = new MultisigLoungeDialog(platformStyle);
        multisigLoungeDialog->setParent(this, Qt::Window);

        connect(miningDialog, SIGNAL(ActivationDialogRequested()),
                walletFrame, SLOT(showSidechainActivationDialog()));

        connect(miningDialog, SIGNAL(WithdrawalDialogRequested()),
                walletFrame, SLOT(showSidechainWithdrawalDialog()));
                walletFrame, SLOT(showSCDBDialog()));

        connect(walletFrame, SIGNAL(requestedSyncWarningInfo()), this, SLOT(showModalOverlay()));

        connect(denialDialog, SIGNAL(requestedSendAllCoins()), this, SLOT(gotoSendAllCoins()));
    } else
#endif // ENABLE_WALLET
    {
        /* When compiled without wallet or -disablewallet is provided,
         * the central widget is the rpc console.
         */
        setCentralWidget(rpcConsole);
    }

    modalOverlay = new ModalOverlay(this->centralWidget());

    // Accept D&D of URIs
    setAcceptDrops(true);

    // Create actions for the toolbar, menu bar and tray/dock icon
    // Needs walletFrame to be initialized
    createActions();

    // Create application menu bar
    createMenuBar();

    // Create the toolbars
    createToolBars();

    // Create system tray icon and notification
    createTrayIcon(networkStyle);

    // Create status bar
    statusBar();

    // Disable size grip because it looks ugly and nobody needs it
    statusBar()->setSizeGripEnabled(false);

    // Status bar notification icons
    QFrame *frameBlocks = new QFrame();
    frameBlocks->setContentsMargins(0,0,0,0);
    frameBlocks->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Preferred);
    QHBoxLayout *frameBlocksLayout = new QHBoxLayout(frameBlocks);
    frameBlocksLayout->setContentsMargins(3,0,3,0);
    frameBlocksLayout->setSpacing(3);
    labelWalletEncryptionIcon = new QLabel();
    connectionsControl = new GUIUtil::ClickableLabel();
    labelBlocksIcon = new GUIUtil::ClickableLabel();
    labelNumBlocks = new QLabel();
    labelLastBlock = new QLabel();
    labelProgressReason = new QLabel();
    labelProgressPercentage = new QLabel();

    if(enableWallet)
    {
        frameBlocksLayout->addStretch();
        frameBlocksLayout->addStretch();
        frameBlocksLayout->addWidget(labelWalletEncryptionIcon);
    }
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(CreateVLine());
    frameBlocksLayout->addWidget(labelNumBlocks);
    frameBlocksLayout->addWidget(CreateVLine());
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(connectionsControl);
    frameBlocksLayout->addWidget(CreateVLine());
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelLastBlock);
    frameBlocksLayout->addStretch();
    frameBlocksLayout->addWidget(labelBlocksIcon);
    frameBlocksLayout->addStretch();

    statusBar()->addWidget(labelProgressReason);
    statusBar()->addWidget(labelProgressPercentage);
    statusBar()->addPermanentWidget(frameBlocks);

    // Install event filter to be able to catch status tip events (QEvent::StatusTip)
    this->installEventFilter(this);

    // Initially wallet actions should be disabled
    setWalletActionsEnabled(false);

    // Subscribe to notifications from core
    subscribeToCoreSignals();

    connect(connectionsControl, SIGNAL(clicked(QPoint)), this, SLOT(toggleNetworkActive()));

    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(updateBlockTime()));
    pollTimer->start(1000); // 1 second
}

BitcoinGUI::~BitcoinGUI()
{
    // Unsubscribe from notifications from core
    unsubscribeFromCoreSignals();

    QSettings settings;
    settings.setValue("MainWindowGeometry", saveGeometry());
    if(trayIcon) // Hide tray icon, as deleting will let it linger until quit (on Ubuntu)
        trayIcon->hide();
#ifdef Q_OS_MAC
    delete appMenuBar;
    MacDockIconHandler::cleanup();
#endif

    delete rpcConsole;
}

void BitcoinGUI::createActions()
{
    QActionGroup *tabGroup = new QActionGroup(this);

    overviewAction = new QAction(platformStyle->SingleColorIcon(":/icons/overview"), tr("&Overview"), this);
    overviewAction->setStatusTip(tr("Show general overview of wallet"));
    overviewAction->setToolTip(overviewAction->statusTip());
    overviewAction->setCheckable(true);
    overviewAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_1));
    tabGroup->addAction(overviewAction);

    sendCoinsAction = new QAction(platformStyle->SingleColorIcon(":/icons/send"), tr("&Send"), this);
    sendCoinsAction->setStatusTip(tr("Send coins to a Skydoge address"));
    sendCoinsAction->setToolTip(sendCoinsAction->statusTip());
    sendCoinsAction->setCheckable(true);
    sendCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_2));
    tabGroup->addAction(sendCoinsAction);

    sendCoinsMenuAction = new QAction(platformStyle->TextColorIcon(":/icons/send"), sendCoinsAction->text(), this);
    sendCoinsMenuAction->setStatusTip(sendCoinsAction->statusTip());
    sendCoinsMenuAction->setToolTip(sendCoinsMenuAction->statusTip());

    receiveCoinsAction = new QAction(platformStyle->SingleColorIcon(":/icons/receiving_addresses"), tr("&Receive"), this);
    receiveCoinsAction->setStatusTip(tr("Request payments (generates QR codes and Skydoge: URIs)"));
    receiveCoinsAction->setToolTip(receiveCoinsAction->statusTip());
    receiveCoinsAction->setCheckable(true);
    receiveCoinsAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_3));
    tabGroup->addAction(receiveCoinsAction);

    receiveCoinsMenuAction = new QAction(platformStyle->TextColorIcon(":/icons/receiving_addresses"), receiveCoinsAction->text(), this);
    receiveCoinsMenuAction->setStatusTip(receiveCoinsAction->statusTip());
    receiveCoinsMenuAction->setToolTip(receiveCoinsMenuAction->statusTip());

    historyAction = new QAction(platformStyle->SingleColorIcon(":/icons/history"), tr("&Transactions"), this);
    historyAction->setStatusTip(tr("Browse transaction history"));
    historyAction->setToolTip(historyAction->statusTip());
    historyAction->setCheckable(true);
    historyAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_4));
    tabGroup->addAction(historyAction);

    sidechainAction = new QAction(platformStyle->SingleColorIcon(":/icons/tx_inout"), tr("&Sidechains"), this);
    sidechainAction->setStatusTip(tr("Make sidechain transfers and manage sidechain settings"));
    sidechainAction->setToolTip(sidechainAction->statusTip());
    sidechainAction->setCheckable(true);
    sidechainAction->setShortcut(QKeySequence(Qt::ALT + Qt::Key_5));
    tabGroup->addAction(sidechainAction);

#ifdef ENABLE_WALLET
    // These showNormalIfMinimized are needed because Send Coins and Receive Coins
    // can be triggered from the tray menu, and need to show the GUI to be useful.
    connect(overviewAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(overviewAction, SIGNAL(triggered()), this, SLOT(gotoOverviewPage()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sendCoinsAction, SIGNAL(triggered()), this, SLOT(gotoSendCoinsPage()));
    connect(sendCoinsMenuAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sendCoinsMenuAction, SIGNAL(triggered()), this, SLOT(gotoSendCoinsPage()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(receiveCoinsAction, SIGNAL(triggered()), this, SLOT(gotoReceiveCoinsPage()));
    connect(receiveCoinsMenuAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(receiveCoinsMenuAction, SIGNAL(triggered()), this, SLOT(gotoReceiveCoinsPage()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(historyAction, SIGNAL(triggered()), this, SLOT(gotoHistoryPage()));
    connect(sidechainAction, SIGNAL(triggered()), this, SLOT(showNormalIfMinimized()));
    connect(sidechainAction, SIGNAL(triggered()), this, SLOT(gotoSidechainPage()));
#endif // ENABLE_WALLET

    quitAction = new QAction(platformStyle->TextColorIcon(":/icons/quit"), tr("E&xit"), this);
    quitAction->setStatusTip(tr("Quit application"));
    quitAction->setShortcut(QKeySequence(Qt::CTRL + Qt::Key_Q));
    quitAction->setMenuRole(QAction::QuitRole);
    aboutAction = new QAction(platformStyle->TextColorIcon(":/icons/about"), tr("&About %1").arg(tr(PACKAGE_NAME)), this);
    aboutAction->setStatusTip(tr("Show information about %1").arg(tr(PACKAGE_NAME)));
    aboutAction->setMenuRole(QAction::AboutRole);
    aboutAction->setEnabled(false);
    aboutQtAction = new QAction(platformStyle->TextColorIcon(":/icons/about_qt"), tr("About &Qt"), this);
    aboutQtAction->setStatusTip(tr("Show information about Qt"));
    aboutQtAction->setMenuRole(QAction::AboutQtRole);
    optionsAction = new QAction(platformStyle->TextColorIcon(":/icons/options"), tr("&Options"), this);
    optionsAction->setStatusTip(tr("Modify configuration options for %1").arg(tr(PACKAGE_NAME)));
    optionsAction->setMenuRole(QAction::PreferencesRole);
    optionsAction->setEnabled(false);
    toggleHideAction = new QAction(platformStyle->TextColorIcon(":/icons/about"), tr("&Show / Hide"), this);
    toggleHideAction->setStatusTip(tr("Show or hide the main Window"));

    encryptWalletAction = new QAction(platformStyle->TextColorIcon(":/icons/lock_closed"), tr("&Encrypt Wallet"), this);
    encryptWalletAction->setStatusTip(tr("Encrypt the private keys that belong to your wallet"));
    encryptWalletAction->setCheckable(true);
    backupWalletAction = new QAction(platformStyle->TextColorIcon(":/icons/filesave"), tr("&Backup Wallet"), this);
    backupWalletAction->setStatusTip(tr("Backup wallet to another location"));
    changePassphraseAction = new QAction(platformStyle->TextColorIcon(":/icons/key"), tr("&Change Passphrase"), this);
    changePassphraseAction->setStatusTip(tr("Change the passphrase used for wallet encryption"));
    signVerifyMessageAction = new QAction(platformStyle->TextColorIcon(":/icons/verify"), tr("Sign / Verify &Message"), this);

    signVerifyMessageAction->setStatusTip(tr("Sign or verify messages to prove ownership"));

    openRPCConsoleAction = new QAction(platformStyle->TextColorIcon(":/icons/debugwindow"), tr("&Debug window"), this);
    openRPCConsoleAction->setStatusTip(tr("Open debugging and diagnostic console"));
    // initially disable the debug window menu item
    openRPCConsoleAction->setEnabled(false);

    usedSendingAddressesAction = new QAction(platformStyle->TextColorIcon(":/icons/address-book"), tr("&Sending addresses"), this);
    usedSendingAddressesAction->setStatusTip(tr("Show the list of used sending addresses and labels"));
    usedReceivingAddressesAction = new QAction(platformStyle->TextColorIcon(":/icons/address-book"), tr("&Receiving addresses"), this);
    usedReceivingAddressesAction->setStatusTip(tr("Show the list of used receiving addresses and labels"));

    openAction = new QAction(platformStyle->TextColorIcon(":/icons/open"), tr("Open &URI Link"), this);
    openAction->setStatusTip(tr("Open a Skydoge: URI or payment request"));

    showHelpMessageAction = new QAction(platformStyle->TextColorIcon(":/icons/info"), tr("&Command-line options"), this);
    showHelpMessageAction->setMenuRole(QAction::NoRole);
    showHelpMessageAction->setStatusTip(tr("Show the %1 help message to get a list with possible Skydoge command-line options").arg(tr(PACKAGE_NAME)));

    showSidechainTableDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/history"), tr("&Sidechain Tables"), this);
    showSidechainTableDialogAction->setStatusTip(tr("Show Sidechain tables"));

    showMiningDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/tx_mined"), tr("&Solo Mine"), this);
    showMiningDialogAction->setStatusTip(tr("Show mining window"));

    showPaperWalletDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/print"), tr("&Paper Wallet"), this);
    showPaperWalletDialogAction->setStatusTip(tr("Show paper wallet window"));
    showPaperWalletDialogAction->setEnabled(false);

    showPaperCheckDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/check"), tr("&Write a Check"), this);
    showPaperCheckDialogAction->setStatusTip(tr("Show paper check window"));
    showPaperCheckDialogAction->setEnabled(false);

    showCreateWalletDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/createwallet"), tr("&Create New Wallet"), this);
    showCreateWalletDialogAction->setStatusTip(tr("Show create wallet window"));

    showRestoreWalletDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/restorewallet"), tr("&Restore My Wallet"), this);
    showRestoreWalletDialogAction->setStatusTip(tr("Show restore wallet window"));

    showHashCalcDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/calculator"), tr("&Hash Calculator"), this);
    showHashCalcDialogAction->setStatusTip(tr("Show hash calculator window"));

    showBlockExplorerDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/search"), tr("&Block Explorer"), this);
    showBlockExplorerDialogAction->setStatusTip(tr("Show block explorer window"));

    showSCDBDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/options"), tr("&Sidechain Withdrawal Admin"), this);
    showSCDBDialogAction->setStatusTip(tr("Show withdrawal vote settings & M4 explorer window"));

    showDenialDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/crosseye"), tr("&Deniability"), this);
    showDenialDialogAction->setStatusTip(tr("Show deniability window"));

    showBip47AddrDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/address-book"), tr("&Address Book"), this);
    showBip47AddrDialogAction->setStatusTip(tr("Show bip 47 address book window"));
    showBip47AddrDialogAction->setEnabled(false);

    showProofOfFundsDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/verify"), tr("&Proof of Funds"), this);
    showProofOfFundsDialogAction->setStatusTip(tr("Show proof of funds window"));
    showProofOfFundsDialogAction->setEnabled(false);

    showMerkleTreeDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/tree"), tr("&Merkle Tree"), this);
    showMerkleTreeDialogAction->setStatusTip(tr("Show merkle tree window"));
    showMerkleTreeDialogAction->setEnabled(false);

    showMultisigLoungeDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/lock_closed"), tr("&Multisig Lounge"), this);
    showMultisigLoungeDialogAction->setStatusTip(tr("Show multisig lounge window"));

    showSignaturesDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/edit"), tr("&Signatures"), this);
    showSignaturesDialogAction->setStatusTip(tr("Show signatures window"));
    showSignaturesDialogAction->setEnabled(false);

    showBase58DialogAction = new QAction(platformStyle->TextColorIcon(":/icons/synced"), tr("&Base58Check Decoder"), this);
    showBase58DialogAction->setStatusTip(tr("Show base58 tools window"));
    showBase58DialogAction->setEnabled(false);

    showGraffitiDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/spray"), tr("&OP_RETURN Graffiti"), this);
    showGraffitiDialogAction->setStatusTip(tr("Show graffiti window"));

    showMerchantsDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/scale"), tr("&Chain Merchants"), this);
    showMerchantsDialogAction->setStatusTip(tr("Show chain merchants window"));
    showMerchantsDialogAction->setEnabled(false);

    showTimestampDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/timer"), tr("&Timestamp File(s)"), this);
    showTimestampDialogAction->setStatusTip(tr("Show unforgeable timestamps window"));
    showTimestampDialogAction->setEnabled(false);

    showStorageDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/safe"), tr("&Permanent Encrypted File Backup"), this);
    showStorageDialogAction->setStatusTip(tr("Show undeletable data storage window"));
    showStorageDialogAction->setEnabled(false);

    showCoinNewsDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/broadcastnews"), tr("&Broadcast CoinNews"), this);
    showCoinNewsDialogAction->setStatusTip(tr("Show coin news window"));

    showMiningPoolsDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/pool"), tr("&Mining Pools"), this);
    showMiningPoolsDialogAction->setStatusTip(tr("Show mining pool window"));
    showMiningPoolsDialogAction->setEnabled(false);

    showNetworkDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/network"), tr("&Network Statistics"), this);
    showNetworkDialogAction->setStatusTip(tr("Show network status window"));
    showNetworkDialogAction->setEnabled(false);

    showAddRemoveSidechainDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/add"), tr("&Sidechain Activation"), this);
    showAddRemoveSidechainDialogAction->setStatusTip(tr("Show add/remove sidechain window"));

    showFileBroadcastDialogAction = new QAction(platformStyle->TextColorIcon(":/icons/broadcastnews"), tr("&Uncensorable File Broadcast"), this);
    showFileBroadcastDialogAction->setStatusTip(tr("Show file broadcast window"));
    showFileBroadcastDialogAction->setEnabled(false);

    showSidechainTransferAction = new QAction(platformStyle->TextColorIcon(":/icons/tx_inout"), tr("&Sidechains"), this);
    showSidechainTransferAction->setStatusTip(tr("Show sidechains tab"));

    showSendMoneyAction = new QAction(platformStyle->TextColorIcon(":/icons/send"), tr("&Send Money"), this);
    showSendMoneyAction->setStatusTip(tr("Show send money tab"));

    showReceiveMoneyAction = new QAction(platformStyle->TextColorIcon(":/icons/receiving_addresses"), tr("&Request Money"), this);
    showReceiveMoneyAction->setStatusTip(tr("Show receive money tab"));

    connect(quitAction, SIGNAL(triggered()), qApp, SLOT(quit()));
    connect(aboutAction, SIGNAL(triggered()), this, SLOT(aboutClicked()));
    connect(aboutQtAction, SIGNAL(triggered()), qApp, SLOT(aboutQt()));
    connect(optionsAction, SIGNAL(triggered()), this, SLOT(optionsClicked()));
    connect(toggleHideAction, SIGNAL(triggered()), this, SLOT(toggleHidden()));
    connect(showHelpMessageAction, SIGNAL(triggered()), this, SLOT(showHelpMessageClicked()));
    connect(openRPCConsoleAction, SIGNAL(triggered()), this, SLOT(showDebugWindow()));
    // prevents an open debug window from becoming stuck/unusable on client shutdown
    connect(quitAction, SIGNAL(triggered()), rpcConsole, SLOT(hide()));

#ifdef ENABLE_WALLET
    if(walletFrame)
    {
        connect(encryptWalletAction, SIGNAL(triggered(bool)), walletFrame, SLOT(encryptWallet(bool)));
        connect(backupWalletAction, SIGNAL(triggered()), walletFrame, SLOT(backupWallet()));
        connect(changePassphraseAction, SIGNAL(triggered()), walletFrame, SLOT(changePassphrase()));
        connect(signVerifyMessageAction, SIGNAL(triggered()), this, SLOT(gotoVerifyMessageTab()));
        connect(usedSendingAddressesAction, SIGNAL(triggered()), walletFrame, SLOT(usedSendingAddresses()));
        connect(usedReceivingAddressesAction, SIGNAL(triggered()), walletFrame, SLOT(usedReceivingAddresses()));
        connect(openAction, SIGNAL(triggered()), this, SLOT(openClicked()));
        connect(showSidechainTableDialogAction, SIGNAL(triggered()), this, SLOT(showSidechainTableDialog()));
        connect(showMiningDialogAction, SIGNAL(triggered()), this, SLOT(showMiningDialog()));
        connect(showPaperWalletDialogAction, SIGNAL(triggered()), this, SLOT(showPaperWalletDialog()));
        connect(showPaperCheckDialogAction, SIGNAL(triggered()), this, SLOT(showPaperCheckDialog()));
        connect(showCreateWalletDialogAction, SIGNAL(triggered()), this, SLOT(showCreateWalletDialog()));
        connect(showRestoreWalletDialogAction, SIGNAL(triggered()), this, SLOT(showRestoreWalletDialog()));
        connect(showHashCalcDialogAction, SIGNAL(triggered()), this, SLOT(showHashCalcDialog()));
        connect(showBlockExplorerDialogAction, SIGNAL(triggered()), this, SLOT(showBlockExplorerDialog()));
        connect(showSCDBDialogAction, SIGNAL(triggered()), this, SLOT(showSCDBDialog()));
        connect(showDenialDialogAction, SIGNAL(triggered()), this, SLOT(showDenialDialog()));
        connect(showBip47AddrDialogAction, SIGNAL(triggered()), this, SLOT(showBip47AddrDialog()));
        connect(showProofOfFundsDialogAction, SIGNAL(triggered()), this, SLOT(showProofOfFundsDialog()));
        connect(showMerkleTreeDialogAction, SIGNAL(triggered()), this, SLOT(showMerkleTreeDialog()));
        connect(showMultisigLoungeDialogAction, SIGNAL(triggered()), this, SLOT(showMultisigLoungeDialog()));
        connect(showSignaturesDialogAction, SIGNAL(triggered()), this, SLOT(showSignaturesDialog()));
        connect(showBase58DialogAction, SIGNAL(triggered()), this, SLOT(showBase58Dialog()));
        connect(showGraffitiDialogAction, SIGNAL(triggered()), this, SLOT(showGraffitiDialog()));
        connect(showMerchantsDialogAction, SIGNAL(triggered()), this, SLOT(showMerchantsDialog()));
        connect(showTimestampDialogAction, SIGNAL(triggered()), this, SLOT(showTimestampDialog()));
        connect(showStorageDialogAction, SIGNAL(triggered()), this, SLOT(showStorageDialog()));
        connect(showCoinNewsDialogAction, SIGNAL(triggered()), this, SLOT(showCoinNewsDialog()));
        connect(showMiningPoolsDialogAction, SIGNAL(triggered()), this, SLOT(showMiningPoolsDialog()));
        connect(showNetworkDialogAction, SIGNAL(triggered()), this, SLOT(showNetworkDialog()));
        connect(showAddRemoveSidechainDialogAction, SIGNAL(triggered()), this, SLOT(showAddRemoveSidechainDialog()));
        connect(showFileBroadcastDialogAction, SIGNAL(triggered()), this, SLOT(showFileBroadcastDialog()));
        connect(showSidechainTransferAction, SIGNAL(triggered()), this, SLOT(gotoSidechainPage()));
        connect(showSendMoneyAction, SIGNAL(triggered()), this, SLOT(gotoSendCoinsPage()));
        connect(showReceiveMoneyAction, SIGNAL(triggered()), this, SLOT(gotoReceiveCoinsPage()));
    }
#endif // ENABLE_WALLET

    new QShortcut(QKeySequence(Qt::CTRL + Qt::SHIFT + Qt::Key_C), this, SLOT(showDebugWindowActivateConsole()));
    new QShortcut(QKeySequence(Qt::CTRL + Qt::SHIFT + Qt::Key_D), this, SLOT(showDebugWindow()));
}

void BitcoinGUI::createMenuBar()
{
#ifdef Q_OS_MAC
    // Create a decoupled menu bar on Mac which stays even if the window is closed
    appMenuBar = new QMenuBar();
#else
    // Get the main window's menu bar on other platforms
    appMenuBar = menuBar();
#endif

    // Configure the menus
    QMenu *menuWallet = appMenuBar->addMenu(tr("&Your Wallet"));
    if(walletFrame)
    {
        menuWallet->addAction(showCreateWalletDialogAction);
        menuWallet->addAction(showRestoreWalletDialogAction);

        menuWallet->addSeparator();

        menuWallet->addAction(usedSendingAddressesAction);
        menuWallet->addAction(usedReceivingAddressesAction);
        menuWallet->addAction(backupWalletAction);

        menuWallet->addSeparator();

        menuWallet->addAction(encryptWalletAction);
        menuWallet->addAction(changePassphraseAction);
// old DC
        file->addAction(openAction);
        file->addAction(backupWalletAction);
        file->addSeparator();
        file->addAction(usedSendingAddressesAction);
        file->addAction(usedReceivingAddressesAction);
        file->addSeparator();
    }
    file->addAction(quitAction);

    QMenu *menuBanking = appMenuBar->addMenu(tr("&Banking"));
    if (walletFrame)
    {
        menuBanking->addAction(showSendMoneyAction);
        menuBanking->addAction(showReceiveMoneyAction);

        menuBanking->addAction(showBip47AddrDialogAction);
        menuBanking->addAction(openAction); // open uri

        menuBanking->addSeparator();

        menuBanking->addAction(showDenialDialogAction);
        menuBanking->addAction(showProofOfFundsDialogAction);
        menuBanking->addAction(showMultisigLoungeDialogAction);

        menuBanking->addSeparator();

        menuBanking->addAction(showPaperWalletDialogAction);
        menuBanking->addAction(showPaperCheckDialogAction);
    }

    QMenu *menuBitcoin = appMenuBar->addMenu(tr("&Use Bitcoin"));
    if(walletFrame)
    {
        menuBitcoin->addAction(showCoinNewsDialogAction);
        menuBitcoin->addAction(showTimestampDialogAction);

        // Sub menu
        QMenu *subMenuBitcoin = menuBitcoin->addMenu(tr("Blockchain Data Storage"));
        subMenuBitcoin->addAction(showGraffitiDialogAction);
        subMenuBitcoin->addAction(showFileBroadcastDialogAction);
        subMenuBitcoin->addAction(showStorageDialogAction);

        menuBitcoin->addSeparator();
        menuBitcoin->addAction(signVerifyMessageAction);
        menuBitcoin->addSeparator();

        menuBitcoin->addAction(showMerchantsDialogAction);
        menuBitcoin->addAction(showSidechainTransferAction);
// old DC
        tools->addAction(showMiningDialogAction);
        tools->addAction(showHashCalcDialogAction);
        tools->addAction(showBlockExplorerDialogAction);
        tools->addAction(signVerifyMessageAction);
    }

    QMenu *menuWork = appMenuBar->addMenu(tr("&Work for Bitcoin"));
    if(walletFrame)
    {
        menuWork->addAction(showMiningDialogAction);
        menuWork->addAction(showMiningPoolsDialogAction);
        menuWork->addAction(showNetworkDialogAction);
        menuWork->addAction(showAddRemoveSidechainDialogAction);
        menuWork->addAction(showSCDBDialogAction); // m4 explorer
// old DC
        settings->addAction(encryptWalletAction);
        settings->addAction(changePassphraseAction);
        settings->addSeparator();
    }
    settings->addAction(optionsAction);

    QMenu *menuTools = appMenuBar->addMenu(tr("&Crypto Tools"));
    if(walletFrame)
    {
        menuTools->addAction(showBlockExplorerDialogAction);
        menuTools->addAction(showHashCalcDialogAction);
        menuTools->addAction(showMerkleTreeDialogAction);
        menuTools->addAction(showSignaturesDialogAction);
        menuTools->addAction(showBase58DialogAction);
    }

    QMenu *menuNode = appMenuBar->addMenu(tr("&This Node"));
    if(walletFrame)
    {
        menuNode->addAction(openRPCConsoleAction);
        menuNode->addAction(optionsAction);
        menuNode->addAction(showHelpMessageAction);

        menuNode->addSeparator();

        menuNode->addAction(aboutAction);
        menuNode->addAction(aboutQtAction);

        menuNode->addSeparator();

        menuNode->addAction(quitAction);
// old DC
        help->addAction(openRPCConsoleAction);
        help->addAction(showSidechainTableDialogAction);
    }
    help->addAction(showHelpMessageAction);
    help->addSeparator();
    help->addAction(aboutAction);
    help->addAction(aboutQtAction);
}

void BitcoinGUI::createToolBars()
{
    if(walletFrame)
    {
        QToolBar *toolbar = addToolBar(tr("Tabs toolbar"));
        toolbar->setContextMenuPolicy(Qt::PreventContextMenu);
        toolbar->setMovable(false);
        toolbar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
        toolbar->addAction(overviewAction);
        toolbar->addAction(sendCoinsAction);
        toolbar->addAction(receiveCoinsAction);
        toolbar->addAction(historyAction);
        toolbar->addSeparator();
        toolbar->addAction(sidechainAction);
        toolbar->addSeparator();
        overviewAction->setChecked(true);
    }
}

void BitcoinGUI::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;
    if(_clientModel)
    {
        // Create system tray menu (or setup the dock menu) that late to prevent users from calling actions,
        // while the client has not yet fully loaded
        createTrayIconMenu();

        // Keep up to date with client
        updateNetworkState();
        connect(_clientModel, SIGNAL(numConnectionsChanged(int)), this, SLOT(setNumConnections(int)));
        connect(_clientModel, SIGNAL(networkActiveChanged(bool)), this, SLOT(setNetworkActive(bool)));

        setNumBlocks(_clientModel->getNumBlocks(), _clientModel->getLastBlockDate(), _clientModel->getVerificationProgress(nullptr), false);
        connect(_clientModel, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)), this, SLOT(setNumBlocks(int,QDateTime,double,bool)));

        // Receive and report messages from client model
        connect(_clientModel, SIGNAL(message(QString,QString,unsigned int)), this, SLOT(message(QString,QString,unsigned int)));

        // Show progress
        connect(_clientModel, SIGNAL(showProgress(QString,int)), this, SLOT(showProgress(QString,int)));

        modalOverlay->setKnownBestHeight(_clientModel->getHeaderTipHeight(), QDateTime::fromTime_t(clientModel->getHeaderTipTime()));

        rpcConsole->setClientModel(_clientModel);
#ifdef ENABLE_WALLET
        if(walletFrame)
        {
            walletFrame->setClientModel(_clientModel);
        }

        blockExplorerDialog->setClientModel(_clientModel);
        denialDialog->setClientModel(_clientModel);

#endif // ENABLE_WALLET
        OptionsModel* optionsModel = _clientModel->getOptionsModel();
        if(optionsModel)
        {
            // be aware of the tray icon disable state change reported by the OptionsModel object.
            connect(optionsModel,SIGNAL(hideTrayIconChanged(bool)),this,SLOT(setTrayIconVisible(bool)));

            // initialize the disable state of the tray icon with the current value in the model.
            setTrayIconVisible(optionsModel->getHideTrayIcon());

            // be aware of the theme changing
            connect(optionsModel, SIGNAL(themeChanged(int)), this, SLOT(updateTheme(int)));
        }
    } else {
        // Disable possibility to show main window via action
        toggleHideAction->setEnabled(false);
        if(trayIconMenu)
        {
            // Disable context menu on tray icon
            trayIconMenu->clear();
        }
        // Propagate cleared model to child objects
        rpcConsole->setClientModel(nullptr);
#ifdef ENABLE_WALLET
        if (walletFrame)
        {
            walletFrame->setClientModel(nullptr);
        }
#endif // ENABLE_WALLET
    }
}

void BitcoinGUI::setWithdrawalModel(SidechainWithdrawalTableModel *model)
{
    this->withdrawalModel = model;
    if(model)
    {
#ifdef ENABLE_WALLET
        if (walletFrame)
        {
            walletFrame->setWithdrawalModel(model);
            if (clientModel) {
                withdrawalModel->numBlocksChanged();
                connect(clientModel, SIGNAL(numBlocksChanged(int,QDateTime,double,bool)),
                        withdrawalModel, SLOT(numBlocksChanged()));
            }
        }
#endif // ENABLE_WALLET
    } else {
#ifdef ENABLE_WALLET
        if (walletFrame)
        {
            walletFrame->setWithdrawalModel(nullptr);
        }
#endif // ENABLE_WALLET
    }
}

void BitcoinGUI::setMemPoolModel(MemPoolTableModel *model)
{
    this->memPoolModel = model;
    if(model)
    {
#ifdef ENABLE_WALLET
        if (walletFrame)
        {
            walletFrame->setMemPoolModel(model);
        }
#endif // ENABLE_WALLET
    } else {
#ifdef ENABLE_WALLET
        if (walletFrame)
        {
            walletFrame->setMemPoolModel(nullptr);
        }
#endif // ENABLE_WALLET
    }
}

#ifdef ENABLE_WALLET
bool BitcoinGUI::addWallet(const QString& name, WalletModel *walletModel)
{
    if(!walletFrame)
        return false;
    setWalletActionsEnabled(true);
    return walletFrame->addWallet(name, walletModel);
}

bool BitcoinGUI::setCurrentWallet(const QString& name)
{
    if(!walletFrame)
        return false;
    return walletFrame->setCurrentWallet(name);
}

void BitcoinGUI::removeAllWallets()
{
    if(!walletFrame)
        return;
    setWalletActionsEnabled(false);
    walletFrame->removeAllWallets();
}
#endif // ENABLE_WALLET

void BitcoinGUI::setWalletActionsEnabled(bool enabled)
{
    overviewAction->setEnabled(enabled);
    sendCoinsAction->setEnabled(enabled);
    sendCoinsMenuAction->setEnabled(enabled);
    receiveCoinsAction->setEnabled(enabled);
    receiveCoinsMenuAction->setEnabled(enabled);
    historyAction->setEnabled(enabled);
    sidechainAction->setEnabled(enabled);
    encryptWalletAction->setEnabled(enabled);
    backupWalletAction->setEnabled(enabled);
    changePassphraseAction->setEnabled(enabled);
    signVerifyMessageAction->setEnabled(enabled);
    usedSendingAddressesAction->setEnabled(enabled);
    usedReceivingAddressesAction->setEnabled(enabled);
    openAction->setEnabled(enabled);
}

void BitcoinGUI::createTrayIcon(const NetworkStyle *networkStyle)
{
#ifndef Q_OS_MAC
    trayIcon = new QSystemTrayIcon(this);
    QString toolTip = tr("%1 client").arg(tr(PACKAGE_NAME)) + " " + networkStyle->getTitleAddText();
    trayIcon->setToolTip(toolTip);
    trayIcon->setIcon(networkStyle->getTrayAndWindowIcon());
    trayIcon->hide();
#endif

    notificator = new Notificator(QApplication::applicationName(), trayIcon, this);
}

void BitcoinGUI::createTrayIconMenu()
{
#ifndef Q_OS_MAC
    // return if trayIcon is unset (only on non-Mac OSes)
    if (!trayIcon)
        return;

    trayIconMenu = new QMenu(this);
    trayIcon->setContextMenu(trayIconMenu);

    connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)),
            this, SLOT(trayIconActivated(QSystemTrayIcon::ActivationReason)));
#else
    // Note: On Mac, the dock icon is used to provide the tray's functionality.
    MacDockIconHandler *dockIconHandler = MacDockIconHandler::instance();
    dockIconHandler->setMainWindow(static_cast<QMainWindow*>(this));
    trayIconMenu = dockIconHandler->dockMenu();
#endif

    // Configuration of the tray icon (or dock icon) icon menu
    trayIconMenu->addAction(toggleHideAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(sendCoinsMenuAction);
    trayIconMenu->addAction(receiveCoinsMenuAction);
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(optionsAction);
    trayIconMenu->addAction(openRPCConsoleAction);
    trayIconMenu->addAction(showSidechainTableDialogAction);
    trayIconMenu->addAction(showMiningDialogAction);
    trayIconMenu->addAction(showPaperWalletDialogAction);
    trayIconMenu->addAction(showPaperCheckDialogAction);
    trayIconMenu->addAction(showCreateWalletDialogAction);
    trayIconMenu->addAction(showRestoreWalletDialogAction);
    trayIconMenu->addAction(showHashCalcDialogAction);
    trayIconMenu->addAction(showBlockExplorerDialogAction);
    trayIconMenu->addAction(signVerifyMessageAction);
    trayIconMenu->addAction(showSCDBDialogAction);
    trayIconMenu->addAction(showDenialDialogAction);
    trayIconMenu->addAction(showBip47AddrDialogAction);
    trayIconMenu->addAction(showProofOfFundsDialogAction);
    trayIconMenu->addAction(showMerkleTreeDialogAction);
    trayIconMenu->addAction(showMultisigLoungeDialogAction);
    trayIconMenu->addAction(showSignaturesDialogAction);
    trayIconMenu->addAction(showBase58DialogAction);
    trayIconMenu->addAction(showGraffitiDialogAction);
    trayIconMenu->addAction(showMerchantsDialogAction);
    trayIconMenu->addAction(showTimestampDialogAction);
    trayIconMenu->addAction(showStorageDialogAction);
    trayIconMenu->addAction(showCoinNewsDialogAction);

#ifndef Q_OS_MAC // This is built-in on Mac
    trayIconMenu->addSeparator();
    trayIconMenu->addAction(quitAction);
#endif
}

#ifndef Q_OS_MAC
void BitcoinGUI::trayIconActivated(QSystemTrayIcon::ActivationReason reason)
{
    if(reason == QSystemTrayIcon::Trigger)
    {
        // Click on system tray icon triggers show/hide of the main window
        toggleHidden();
    }
}
#endif

void BitcoinGUI::optionsClicked()
{
    if(!clientModel || !clientModel->getOptionsModel())
        return;

    OptionsDialog dlg(this, enableWallet);
    dlg.setModel(clientModel->getOptionsModel());
    dlg.exec();
}

void BitcoinGUI::aboutClicked()
{
    if(!clientModel)
        return;

    HelpMessageDialog dlg(this, true);
    dlg.exec();
}

void BitcoinGUI::showDebugWindow()
{
    rpcConsole->showNormal();
    rpcConsole->show();
    rpcConsole->raise();
    rpcConsole->activateWindow();
}

void BitcoinGUI::showDebugWindowActivateConsole()
{
    rpcConsole->setTabFocus(RPCConsole::TAB_CONSOLE);
    showDebugWindow();
}

void BitcoinGUI::showHelpMessageClicked()
{
    helpMessageDialog->show();
}

#ifdef ENABLE_WALLET
void BitcoinGUI::showSidechainTableDialog()
{
    sidechainTableDialog->exec();
}

void BitcoinGUI::showMiningDialog()
{
    miningDialog->show();
}

void BitcoinGUI::showPaperWalletDialog()
{
    paperWalletDialog->show();
}

void BitcoinGUI::showPaperCheckDialog()
{

}

void BitcoinGUI::showCreateWalletDialog()
{
    createWalletDialog->SetCreateMode();
    createWalletDialog->show();
}

void BitcoinGUI::showRestoreWalletDialog()
{
    createWalletDialog->SetRestoreMode();
    createWalletDialog->show();
}

void BitcoinGUI::showHashCalcDialog()
{
    hashCalcDialog->show();
}

void BitcoinGUI::showBlockExplorerDialog()
{
    blockExplorerDialog->show();
    blockExplorerDialog->updateOnShow();
    blockExplorerDialog->scrollRight();
}

void BitcoinGUI::showDenialDialog()
{
    denialDialog->show();
    denialDialog->UpdateOnShow();
}

void BitcoinGUI::showSCDBDialog()
{
    if (walletFrame) walletFrame->showSCDBDialog();
}

void BitcoinGUI::showBip47AddrDialog()
{

}

void BitcoinGUI::showProofOfFundsDialog()
{

}

void BitcoinGUI::showMerkleTreeDialog()
{

}

void BitcoinGUI::showMultisigLoungeDialog()
{
    multisigLoungeDialog->show();
    multisigLoungeDialog->UpdateOnShow();
}

void BitcoinGUI::showSignaturesDialog()
{

}

void BitcoinGUI::showBase58Dialog()
{

}

void BitcoinGUI::showGraffitiDialog()
{
    if (walletFrame) walletFrame->showGraffitiDialog();
}

void BitcoinGUI::showMerchantsDialog()
{

}

void BitcoinGUI::showTimestampDialog()
{

}

void BitcoinGUI::showStorageDialog()
{

}

void BitcoinGUI::showCoinNewsDialog()
{
    if (walletFrame) walletFrame->showCoinNewsDialog();
}

void BitcoinGUI::showMiningPoolsDialog()
{

}

void BitcoinGUI::showNetworkDialog()
{

}

void BitcoinGUI::showAddRemoveSidechainDialog()
{
    if (walletFrame) walletFrame->showSidechainActivationDialog();
}

void BitcoinGUI::showFileBroadcastDialog()
{

}

void BitcoinGUI::openClicked()
{
    OpenURIDialog dlg(this);
    if(dlg.exec())
    {
        Q_EMIT receivedURI(dlg.getURI());
    }
}

void BitcoinGUI::gotoOverviewPage()
{
    overviewAction->setChecked(true);
    if (walletFrame) walletFrame->gotoOverviewPage();
}

void BitcoinGUI::gotoHistoryPage()
{
    historyAction->setChecked(true);
    if (walletFrame) walletFrame->gotoHistoryPage();
}

void BitcoinGUI::gotoReceiveCoinsPage()
{
    receiveCoinsAction->setChecked(true);
    if (walletFrame) walletFrame->gotoReceiveCoinsPage();
}

void BitcoinGUI::gotoSendCoinsPage(QString addr)
{
    sendCoinsAction->setChecked(true);
    if (walletFrame) walletFrame->gotoSendCoinsPage(addr);
}

void BitcoinGUI::gotoSendAllCoins()
{
    showNormalIfMinimized();
    sendCoinsAction->setChecked(true);
    if (walletFrame) {
        walletFrame->gotoSendCoinsPage("");
        walletFrame->requestUseAvailable();
    }
}

void BitcoinGUI::gotoSidechainPage()
{
    sidechainAction->setChecked(true);
    if (walletFrame) walletFrame->gotoSidechainPage();
}

void BitcoinGUI::gotoVerifyMessageTab(QString addr)
{
    if (walletFrame) walletFrame->gotoVerifyMessageTab(addr);
}
#endif // ENABLE_WALLET

void BitcoinGUI::updateNetworkState()
{
    int count = clientModel->getNumConnections();

    QString tooltip;

    bool fNetworking = clientModel->getNetworkActive();
    if (fNetworking) {
        tooltip = tr("%n active connection(s) to Skydoge network", "", count) + QString(".<br>");
    } else {
        tooltip = tr("Network activity disabled.") + QString("<br>") + tr("Click to enable network activity again.");
    }

    // Don't word-wrap this (fixed-width) tooltip
    tooltip = QString("<nobr>") + tooltip + QString("</nobr>");
    connectionsControl->setToolTip(tooltip);

    if (count == 1) {
        connectionsControl->setText(tr("%n peer", "", count));

    } else {
        connectionsControl->setText(tr("%n peers", "", count));
    }
}

void BitcoinGUI::setNumConnections(int count)
{
    updateNetworkState();
}

void BitcoinGUI::setNetworkActive(bool networkActive)
{
    updateNetworkState();
}

void BitcoinGUI::updateHeadersSyncProgressLabel()
{
    int64_t headersTipTime = clientModel->getHeaderTipTime();
    int headersTipHeight = clientModel->getHeaderTipHeight();
    int estHeadersLeft = (GetTime() - headersTipTime) / Params().GetConsensus().nPowTargetSpacing;
    if (estHeadersLeft > HEADER_HEIGHT_DELTA_SYNC) {
        QString reason = tr("Syncing Headers (%1%)...").arg(QString::number(100.0 / (headersTipHeight+estHeadersLeft)*headersTipHeight, 'f', 1));
        labelProgressReason->setText(reason);
    }
}

QFrame* BitcoinGUI::CreateVLine()
{
    QFrame *vline = new QFrame(this);
    vline->setFrameShape(QFrame::VLine);
    vline->setLineWidth(1);
    return vline;
}

void BitcoinGUI::setNumBlocks(int count, const QDateTime& blockDate, double nVerificationProgress, bool header)
{
    if (modalOverlay) {
        if (header)
            modalOverlay->setKnownBestHeight(count, blockDate);
        else
            modalOverlay->tipUpdate(count, blockDate, nVerificationProgress);
    }

    if (!clientModel)
        return;

    // Prevent orphan statusbar messages (e.g. hover Quit in main menu, wait until chain-sync starts -> garbled text)
    statusBar()->clearMessage();

    // Acquire current block source
    enum BlockSource blockSource = clientModel->getBlockSource();
    switch (blockSource) {
        case BLOCK_SOURCE_NETWORK:
            if (header) {
                updateHeadersSyncProgressLabel();
                return;
            }
            labelProgressReason->setText(tr("Synchronizing with network..."));
            updateHeadersSyncProgressLabel();
            break;
        case BLOCK_SOURCE_DISK:
            if (header) {
                labelProgressReason->setText(tr("Indexing blocks on disk..."));
            } else {
                labelProgressReason->setText(tr("Processing blocks on disk..."));
            }
            break;
        case BLOCK_SOURCE_REINDEX:
            labelProgressReason->setText(tr("Reindexing blocks on disk..."));
            break;
        case BLOCK_SOURCE_NONE:
            if (header) {
                return;
            }
            labelProgressReason->setText(tr("Connecting to peers..."));
            break;
    }

    QString tooltip;

    QDateTime currentDate = QDateTime::currentDateTime();
    qint64 secs = blockDate.secsTo(currentDate);
    QString timeBehindText = GUIUtil::formatNiceTimeOffset(secs);

    prevBlockTime = QDateTime(blockDate);

    tooltip = tr("Processed %n block(s) of transaction history.", "", count);

    // Set icon state: spinning if catching up, tick otherwise
    if(secs < 90*60)
    {
        tooltip = tr("Up to date") + QString(".<br>") + tooltip;

        labelBlocksIcon->setVisible(false);

#ifdef ENABLE_WALLET
        if(walletFrame)
        {
            walletFrame->showOutOfSyncWarning(false);
            modalOverlay->showHide(true, true);
        }
#endif // ENABLE_WALLET

        labelProgressReason->setVisible(false);
        labelProgressPercentage->setVisible(false);
    }
    else
    {
        labelBlocksIcon->setVisible(true);

        labelProgressReason->setVisible(true);
        labelProgressPercentage->setVisible(true);

        tooltip = tr("Catching up...") + QString("<br>") + tooltip;
        if(count != prevBlocks)
        {
            labelBlocksIcon->setPixmap(platformStyle->SingleColorIcon(QString(
                ":/movies/spinner-%1").arg(spinnerFrame, 3, 10, QChar('0')))
                .pixmap(STATUSBAR_ICONSIZE, STATUSBAR_ICONSIZE));
            spinnerFrame = (spinnerFrame + 1) % SPINNER_FRAMES;
        }
        prevBlocks = count;

#ifdef ENABLE_WALLET
        if(walletFrame)
        {
            walletFrame->showOutOfSyncWarning(true);
            modalOverlay->showHide();
        }
#endif // ENABLE_WALLET

        tooltip += QString("<br>");
        tooltip += tr("Last received block was generated %1 ago.").arg(timeBehindText);
        tooltip += QString("<br>");
        tooltip += tr("Transactions after this will not yet be visible.");
    }

    // Don't word-wrap this (fixed-width) tooltip
    tooltip = QString("<nobr>") + tooltip + QString("</nobr>");

    labelBlocksIcon->setToolTip(tooltip);
    labelProgressReason->setToolTip(tooltip);
    labelProgressPercentage->setToolTip(tooltip);

    // Display number of blocks
    labelNumBlocks->setText(tr("%n blocks", "", count));

    // Display last block time
    labelLastBlock->setText(tr("Last block: %1 ago").arg(timeBehindText));
}

void BitcoinGUI::message(const QString &title, const QString &message, unsigned int style, bool *ret)
{
    QString strTitle = tr("Skydoge"); // default title
    // Default to information icon
    int nMBoxIcon = QMessageBox::Information;
    int nNotifyIcon = Notificator::Information;

    QString msgType;

    // Prefer supplied title over style based title
    if (!title.isEmpty()) {
        msgType = title;
    }
    else {
        switch (style) {
        case CClientUIInterface::MSG_ERROR:
            msgType = tr("Error");
            break;
        case CClientUIInterface::MSG_WARNING:
            msgType = tr("Warning");
            break;
        case CClientUIInterface::MSG_INFORMATION:
            msgType = tr("Information");
            break;
        default:
            break;
        }
    }
    // Append title to "Bitcoin - "
    if (!msgType.isEmpty())
        strTitle += " - " + msgType;

    // Check for error/warning icon
    if (style & CClientUIInterface::ICON_ERROR) {
        nMBoxIcon = QMessageBox::Critical;
        nNotifyIcon = Notificator::Critical;
    }
    else if (style & CClientUIInterface::ICON_WARNING) {
        nMBoxIcon = QMessageBox::Warning;
        nNotifyIcon = Notificator::Warning;
    }

    // Display message
    if (style & CClientUIInterface::MODAL) {
        // Check for buttons, use OK as default, if none was supplied
        QMessageBox::StandardButton buttons;
        if (!(buttons = (QMessageBox::StandardButton)(style & CClientUIInterface::BTN_MASK)))
            buttons = QMessageBox::Ok;

        showNormalIfMinimized();
        QMessageBox mBox(static_cast<QMessageBox::Icon>(nMBoxIcon), strTitle, message, buttons, this);
        int r = mBox.exec();
        if (ret != nullptr)
            *ret = r == QMessageBox::Ok;
    }
    else
        notificator->notify(static_cast<Notificator::Class>(nNotifyIcon), strTitle, message);
}

void BitcoinGUI::changeEvent(QEvent *e)
{
    QMainWindow::changeEvent(e);
#ifndef Q_OS_MAC // Ignored on Mac
    if(e->type() == QEvent::WindowStateChange)
    {
        if(clientModel && clientModel->getOptionsModel() && clientModel->getOptionsModel()->getMinimizeToTray())
        {
            QWindowStateChangeEvent *wsevt = static_cast<QWindowStateChangeEvent*>(e);
            if(!(wsevt->oldState() & Qt::WindowMinimized) && isMinimized())
            {
                QTimer::singleShot(0, this, SLOT(hide()));
                e->ignore();
            }
        }
    }
#endif
}

void BitcoinGUI::closeEvent(QCloseEvent *event)
{
#ifndef Q_OS_MAC // Ignored on Mac
    if(clientModel && clientModel->getOptionsModel())
    {
        if(!clientModel->getOptionsModel()->getMinimizeOnClose())
        {
            // close rpcConsole in case it was open to make some space for the shutdown window
            rpcConsole->close();

            QApplication::quit();
        }
        else
        {
            QMainWindow::showMinimized();
            event->ignore();
        }
    }
#else
    QMainWindow::closeEvent(event);
#endif
}

void BitcoinGUI::showEvent(QShowEvent *event)
{
    // enable the debug window when the main window shows up
    openRPCConsoleAction->setEnabled(true);
    aboutAction->setEnabled(true);
    optionsAction->setEnabled(true);
}

#ifdef ENABLE_WALLET
void BitcoinGUI::incomingTransaction(const QString& date, int unit, const CAmount& amount, const QString& type, const QString& address, const QString& label)
{
    // On new transaction, make an info balloon
    QString msg = tr("Date: %1\n").arg(date) +
                  tr("Amount: %1\n").arg(BitcoinUnits::formatWithUnit(unit, amount, true)) +
                  tr("Type: %1\n").arg(type);
    if (!label.isEmpty())
        msg += tr("Label: %1\n").arg(label);
    else if (!address.isEmpty())
        msg += tr("Address: %1\n").arg(address);
    message((amount)<0 ? tr("Sent transaction") : tr("Incoming transaction"),
             msg, CClientUIInterface::MSG_INFORMATION);
}
#endif // ENABLE_WALLET

void BitcoinGUI::dragEnterEvent(QDragEnterEvent *event)
{
    // Accept only URIs
    if(event->mimeData()->hasUrls())
        event->acceptProposedAction();
}

void BitcoinGUI::dropEvent(QDropEvent *event)
{
    if(event->mimeData()->hasUrls())
    {
        for (const QUrl &uri : event->mimeData()->urls())
        {
            Q_EMIT receivedURI(uri.toString());
        }
    }
    event->acceptProposedAction();
}

bool BitcoinGUI::eventFilter(QObject *object, QEvent *event)
{
    // Catch status tip events
    if (event->type() == QEvent::StatusTip)
    {
        // Prevent adding text from setStatusTip(), if we currently use the status bar for displaying other stuff
        if (labelProgressReason->isVisible() || labelProgressPercentage->isVisible())
            return true;
    }
    return QMainWindow::eventFilter(object, event);
}

#ifdef ENABLE_WALLET
bool BitcoinGUI::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    // URI has to be valid
    if (walletFrame && walletFrame->handlePaymentRequest(recipient))
    {
        showNormalIfMinimized();
        gotoSendCoinsPage();
        return true;
    }
    return false;
}

void BitcoinGUI::setEncryptionStatus(int status)
{
    switch(status)
    {
    case WalletModel::Unencrypted:
        labelWalletEncryptionIcon->hide();
        encryptWalletAction->setChecked(false);
        changePassphraseAction->setEnabled(false);
        encryptWalletAction->setEnabled(true);
        break;
    case WalletModel::Unlocked:
        labelWalletEncryptionIcon->show();
        labelWalletEncryptionIcon->setPixmap(platformStyle->SingleColorIcon(":/icons/lock_open").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        labelWalletEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>unlocked</b>"));
        encryptWalletAction->setChecked(true);
        changePassphraseAction->setEnabled(true);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        break;
    case WalletModel::Locked:
        labelWalletEncryptionIcon->show();
        labelWalletEncryptionIcon->setPixmap(platformStyle->SingleColorIcon(":/icons/lock_closed").pixmap(STATUSBAR_ICONSIZE,STATUSBAR_ICONSIZE));
        labelWalletEncryptionIcon->setToolTip(tr("Wallet is <b>encrypted</b> and currently <b>locked</b>"));
        encryptWalletAction->setChecked(true);
        changePassphraseAction->setEnabled(true);
        encryptWalletAction->setEnabled(false); // TODO: decrypt currently not supported
        break;
    }
}
#endif // ENABLE_WALLET

void BitcoinGUI::showNormalIfMinimized(bool fToggleHidden)
{
    if(!clientModel)
        return;

    // activateWindow() (sometimes) helps with keyboard focus on Windows
    if (isHidden())
    {
        show();
        activateWindow();
    }
    else if (isMinimized())
    {
        showNormal();
        activateWindow();
    }
    else if (GUIUtil::isObscured(this))
    {
        raise();
        activateWindow();
    }
    else if(fToggleHidden)
        hide();
}

void BitcoinGUI::toggleHidden()
{
    showNormalIfMinimized(true);
}

void BitcoinGUI::detectShutdown()
{
    if (ShutdownRequested())
    {
        if(rpcConsole)
            rpcConsole->hide();
        qApp->quit();
    }
}

void BitcoinGUI::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0)
    {
        labelProgressReason->setVisible(true);
        labelProgressPercentage->setVisible(true);
        labelProgressReason->setText(title);
        labelProgressPercentage->setText(tr("%n\%", "", nProgress));

    }
    else if (nProgress == 100)
    {
        labelProgressReason->setVisible(false);
        labelProgressPercentage->setVisible(false);
    }
    else
    {
        labelProgressPercentage->setText(tr("%n\%", "", nProgress));
    }
}

void BitcoinGUI::setTrayIconVisible(bool fHideTrayIcon)
{
    if (trayIcon)
    {
        trayIcon->setVisible(!fHideTrayIcon);
    }
}

void BitcoinGUI::showModalOverlay()
{
    if (modalOverlay)
        modalOverlay->toggleVisibility();
}

static bool ThreadSafeMessageBox(BitcoinGUI *gui, const std::string& message, const std::string& caption, unsigned int style)
{
    bool modal = (style & CClientUIInterface::MODAL);
    // The SECURE flag has no effect in the Qt GUI.
    // bool secure = (style & CClientUIInterface::SECURE);
    style &= ~CClientUIInterface::SECURE;
    bool ret = false;
    // In case of modal message, use blocking connection to wait for user to click a button
    QMetaObject::invokeMethod(gui, "message",
                               modal ? GUIUtil::blockingGUIThreadConnection() : Qt::QueuedConnection,
                               Q_ARG(QString, QString::fromStdString(caption)),
                               Q_ARG(QString, QString::fromStdString(message)),
                               Q_ARG(unsigned int, style),
                               Q_ARG(bool*, &ret));
    return ret;
}

void BitcoinGUI::subscribeToCoreSignals()
{
    // Connect signals to client
    uiInterface.ThreadSafeMessageBox.connect(boost::bind(ThreadSafeMessageBox, this, _1, _2, _3));
    uiInterface.ThreadSafeQuestion.connect(boost::bind(ThreadSafeMessageBox, this, _1, _3, _4));
}

void BitcoinGUI::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    uiInterface.ThreadSafeMessageBox.disconnect(boost::bind(ThreadSafeMessageBox, this, _1, _2, _3));
    uiInterface.ThreadSafeQuestion.disconnect(boost::bind(ThreadSafeMessageBox, this, _1, _3, _4));
}

void BitcoinGUI::toggleNetworkActive()
{
    if (clientModel) {
        clientModel->setNetworkActive(!clientModel->getNetworkActive());
    }
}

void BitcoinGUI::updateTheme(int nTheme)
{
    // TODO error messages if we cannot find theme resources for some reason
    if (nTheme == THEME_DEFAULT) {
        // Reset style sheet so that Qt will revert to system or default theme
        qApp->setStyleSheet("");
    }
    else
    if (nTheme == THEME_DARK) {
        QFile file(":/qdarkstyle/darkstyle");
        file.open(QFile::ReadOnly | QFile::Text);
        QTextStream stream(&file);

        qApp->setStyleSheet(stream.readAll());
    }
}

void BitcoinGUI::initTheme()
{
    if (clientModel)
    {
        int nTheme = clientModel->getOptionsModel()->getTheme();
        updateTheme(nTheme);
    }
}

void BitcoinGUI::updateBlockTime()
{
    if (prevBlockTime.isNull())
        return;

    QDateTime currentDate = QDateTime::currentDateTime();
    qint64 secs = prevBlockTime.secsTo(currentDate);
    QString timeBehindText = GUIUtil::formatNiceTimeOffset(secs);

    // Display last block time
    labelLastBlock->setText(tr("Last block: %1 ago").arg(timeBehindText));
}
