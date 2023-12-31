// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_BITCOINGUI_H
#define BITCOIN_QT_BITCOINGUI_H

#if defined(HAVE_CONFIG_H)
#include <config/skydoge-config.h>
#endif

#include <amount.h>

#include <QDateTime>
#include <QLabel>
#include <QMainWindow>
#include <QMap>
#include <QMenu>
#include <QPoint>
#include <QSystemTrayIcon>

class ClientModel;
class NetworkStyle;
class Notificator;
class OptionsModel;
class PlatformStyle;
class RPCConsole;
class SendCoinsRecipient;
class SidechainTableDialog;
class SidechainPage;
class SidechainWithdrawalTableModel;
class MemPoolTableModel;
class MiningDialog;
class MultisigLoungeDialog;
class PaperWalletDialog;
class WalletFrame;
class WalletModel;
class HelpMessageDialog;
class ModalOverlay;
class HashCalcDialog;
class BlockExplorer;
class CreateWalletDialog;
class DenialDialog;

QT_BEGIN_NAMESPACE
class QAction;
class QTimer;
QT_END_NAMESPACE

/**
  Bitcoin GUI main class. This class represents the main window of the Bitcoin UI. It communicates with both the client and
  wallet models to give the user an up-to-date view of the current core state.
*/
class BitcoinGUI : public QMainWindow
{
    Q_OBJECT

public:
    static const QString DEFAULT_WALLET;
    static const std::string DEFAULT_UIPLATFORM;

    explicit BitcoinGUI(const PlatformStyle *platformStyle, const NetworkStyle *networkStyle, QWidget *parent = 0);
    ~BitcoinGUI();

    /** Set the client model.
        The client model represents the part of the core that communicates with the P2P network, and is wallet-agnostic.
    */
    void setClientModel(ClientModel *clientModel);

    void setWithdrawalModel(SidechainWithdrawalTableModel *model);
    void setMemPoolModel(MemPoolTableModel *model);

#ifdef ENABLE_WALLET
    /** Set the wallet model.
        The wallet model represents a bitcoin wallet, and offers access to the list of transactions, address book and sending
        functionality.
    */
    bool addWallet(const QString& name, WalletModel *walletModel);
    bool setCurrentWallet(const QString& name);
    void removeAllWallets();
#endif // ENABLE_WALLET
    bool enableWallet;

protected:
    void changeEvent(QEvent *e);
    void closeEvent(QCloseEvent *event);
    void showEvent(QShowEvent *event);
    void dragEnterEvent(QDragEnterEvent *event);
    void dropEvent(QDropEvent *event);
    bool eventFilter(QObject *object, QEvent *event);

private:
    ClientModel *clientModel;
    WalletFrame *walletFrame;
    SidechainWithdrawalTableModel *withdrawalModel;
    MemPoolTableModel *memPoolModel;

    QLabel *labelWalletEncryptionIcon;
    QLabel *connectionsControl;
    QLabel *labelBlocksIcon;
    QLabel *labelProgressReason;
    QLabel *labelProgressPercentage;
    QLabel *labelNumBlocks;
    QLabel *labelLastBlock;

    QMenuBar *appMenuBar;
    QAction *overviewAction;
    QAction *historyAction;
    QAction *quitAction;
    QAction *sendCoinsAction;
    QAction *sidechainAction;
    QAction *sendCoinsMenuAction;
    QAction *usedSendingAddressesAction;
    QAction *usedReceivingAddressesAction;
    QAction *signVerifyMessageAction;
    QAction *aboutAction;
    QAction *receiveCoinsAction;
    QAction *receiveCoinsMenuAction;
    QAction *optionsAction;
    QAction *toggleHideAction;
    QAction *encryptWalletAction;
    QAction *backupWalletAction;
    QAction *changePassphraseAction;
    QAction *aboutQtAction;
    QAction *openRPCConsoleAction;
    QAction *openAction;
    QAction *showHelpMessageAction;
    QAction *showSidechainTableDialogAction;
    QAction *showMiningDialogAction;
    QAction *showPaperWalletDialogAction;
    QAction *showPaperCheckDialogAction;
    QAction *showCreateWalletDialogAction;
    QAction *showRestoreWalletDialogAction;
    QAction *showHashCalcDialogAction;
    QAction *showBlockExplorerDialogAction;
    QAction *showSCDBDialogAction;
    QAction *showDenialDialogAction;
    QAction *showBip47AddrDialogAction;
    QAction *showProofOfFundsDialogAction;
    QAction *showMerkleTreeDialogAction;
    QAction *showMultisigLoungeDialogAction;
    QAction *showSignaturesDialogAction;
    QAction *showBase58DialogAction;
    QAction *showGraffitiDialogAction;
    QAction *showMerchantsDialogAction;
    QAction *showTimestampDialogAction;
    QAction *showStorageDialogAction;
    QAction *showCoinNewsDialogAction;
    QAction *showMiningPoolsDialogAction;
    QAction *showNetworkDialogAction;
    QAction *showAddRemoveSidechainDialogAction;
    QAction *showFileBroadcastDialogAction;
    QAction *showSidechainTransferAction;
    QAction *showSendMoneyAction;
    QAction *showReceiveMoneyAction;

    QSystemTrayIcon *trayIcon;
    QMenu *trayIconMenu;
    Notificator *notificator;
    RPCConsole *rpcConsole;
    HelpMessageDialog *helpMessageDialog;
    ModalOverlay *modalOverlay = nullptr;

    QTimer *pollTimer;

#ifdef ENABLE_WALLET
    /** Sidechain table dialog (for testing) */
    SidechainTableDialog *sidechainTableDialog;
    /** Mining dialog */
    MiningDialog *miningDialog;
    /** Paper Wallet dialog */
    PaperWalletDialog *paperWalletDialog;
    /** Create / restore Wallet dialog */
    CreateWalletDialog *createWalletDialog;
    /** Hash calculator dialog */
    HashCalcDialog *hashCalcDialog;
    /** Block explorer dialog */
    BlockExplorer *blockExplorerDialog;
    /** Denial dialog */
    DenialDialog *denialDialog;
    /** Multisig Lounge dialog */
    MultisigLoungeDialog *multisigLoungeDialog;
#endif

    /** Keep track of previous number of blocks, to detect progress */
    int prevBlocks;
    int spinnerFrame;
    QDateTime prevBlockTime;

    const PlatformStyle *platformStyle;

    /** Create the main UI actions. */
    void createActions();
    /** Create the menu bar and sub-menus. */
    void createMenuBar();
    /** Create the toolbars */
    void createToolBars();
    /** Create system tray icon and notification */
    void createTrayIcon(const NetworkStyle *networkStyle);
    /** Create system tray menu (or setup the dock menu) */
    void createTrayIconMenu();

    /** Enable or disable all wallet-related actions */
    void setWalletActionsEnabled(bool enabled);

    /** Connect core signals to GUI client */
    void subscribeToCoreSignals();
    /** Disconnect core signals from GUI client */
    void unsubscribeFromCoreSignals();

    /** Update UI with latest network info from model. */
    void updateNetworkState();

    void updateHeadersSyncProgressLabel();

    QFrame* CreateVLine();

Q_SIGNALS:
    /** Signal raised when a URI was entered or dragged to the GUI */
    void receivedURI(const QString &uri);

public Q_SLOTS:
    /** Set number of connections shown in the UI */
    void setNumConnections(int count);
    /** Set network state shown in the UI */
    void setNetworkActive(bool networkActive);
    /** Set number of blocks and last block date shown in the UI */
    void setNumBlocks(int count, const QDateTime& blockDate, double nVerificationProgress, bool headers);

    /** Special high performance version for IBD */
    void setNumBlocksIBD(int count, double nVerificationProgress);

    /** Notify the user of an event from the core network or transaction handling code.
       @param[in] title     the message box / notification title
       @param[in] message   the displayed text
       @param[in] style     modality and style definitions (icon and used buttons - buttons only for message boxes)
                            @see CClientUIInterface::MessageBoxFlags
       @param[in] ret       pointer to a bool that will be modified to whether Ok was clicked (modal only)
    */
    void message(const QString &title, const QString &message, unsigned int style, bool *ret = nullptr);

    /** Set the theme to the user's setting during init */
    void initTheme();

#ifdef ENABLE_WALLET
    /** Set the encryption status as shown in the UI.
       @param[in] status            current encryption status
       @see WalletModel::EncryptionStatus
    */
    void setEncryptionStatus(int status);

    bool handlePaymentRequest(const SendCoinsRecipient& recipient);

    /** Show incoming transaction notification for new transactions. */
    void incomingTransaction(const QString& date, int unit, const CAmount& amount, const QString& type, const QString& address, const QString& label);
#endif // ENABLE_WALLET

private Q_SLOTS:
#ifdef ENABLE_WALLET
    /** Switch to overview (home) page */
    void gotoOverviewPage();
    /** Switch to history (transactions) page */
    void gotoHistoryPage();
    /** Switch to Sidechain page */
    void gotoSidechainPage();
    /** Switch to receive coins page */
    void gotoReceiveCoinsPage();
    /** Switch to send coins page */
    void gotoSendCoinsPage(QString addr = "");

    /** Show Sign/Verify Message dialog and switch to verify message tab */
    void gotoVerifyMessageTab(QString addr = "");

    /** Show open dialog */
    void openClicked();

    /** Show sidechain table dialog */
    void showSidechainTableDialog();

    /** Show mining dialog */
    void showMiningDialog();

    /** Show paper wallet dialog */
    void showPaperWalletDialog();

    /** Show paper check dialog */
    void showPaperCheckDialog();

    /** Show create wallet dialog */
    void showCreateWalletDialog();

    /** Show restore wallet dialog */
    void showRestoreWalletDialog();

    /** Show hash calculator dialog */
    void showHashCalcDialog();

    /** Show block explorer dialog */
    void showBlockExplorerDialog();

    /** Show SCDB M4 dialog */
    void showSCDBDialog();

    /** Show denial dialog */
    void showDenialDialog();

    /** Show Bip47Addr dialog */
    void showBip47AddrDialog();

    /** Show Proof Of Funds dialog */
    void showProofOfFundsDialog();

    /** Show MultisigLounge dialog */
    void showMultisigLoungeDialog();

    /** Show Merkle tree dialog */
    void showMerkleTreeDialog();

    /** Show Signatures dialog */
    void showSignaturesDialog();

    /** Show Base58 dialog */
    void showBase58Dialog();

    /** Show Graffiti dialog */
    void showGraffitiDialog();

    /** Show Merchants dialog */
    void showMerchantsDialog();

    /** Show Timestamp dialog */
    void showTimestampDialog();

    /** Show Storage dialog */
    void showStorageDialog();

    /** Show Coin News dialog */
    void showCoinNewsDialog();

    /** Go to the send coins page & click on use available balance */
    void gotoSendAllCoins();

    /** Show mining pool dialog */
    void showMiningPoolsDialog();

    /** Show network stats dialog */
    void showNetworkDialog();

    /** Show add / remove sidechain dialog */
    void showAddRemoveSidechainDialog();

    /** Show file broadcast dialog */
    void showFileBroadcastDialog();

#endif // ENABLE_WALLET
    /** Show configuration dialog */
    void optionsClicked();
    /** Show about dialog */
    void aboutClicked();
    /** Show debug window */
    void showDebugWindow();
    /** Show debug window and set focus to the console */
    void showDebugWindowActivateConsole();
    /** Show help message dialog */
    void showHelpMessageClicked();
#ifndef Q_OS_MAC
    /** Handle tray icon clicked */
    void trayIconActivated(QSystemTrayIcon::ActivationReason reason);
#endif

    /** Show window if hidden, unminimize when minimized, rise when obscured or show if hidden and fToggleHidden is true */
    void showNormalIfMinimized(bool fToggleHidden = false);
    /** Simply calls showNormalIfMinimized(true) for use in SLOT() macro */
    void toggleHidden();

    /** called by a timer to check if fRequestShutdown has been set **/
    void detectShutdown();

    /** Show progress dialog e.g. for verifychain */
    void showProgress(const QString &title, int nProgress);

    void showModalOverlay();

    /** When hideTrayIcon setting is changed in OptionsModel hide or show the icon accordingly. */
    void setTrayIconVisible(bool);

    /** Toggle networking */
    void toggleNetworkActive();

    /** Update the theme */
    void updateTheme(int nTheme);

    /** Refresh the last block time */
    void updateBlockTime();
};

#endif // BITCOIN_QT_BITCOINGUI_H
