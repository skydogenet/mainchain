// Copyright (c) 2011-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/clientmodel.h>

#include <qt/bantablemodel.h>
#include <qt/guiconstants.h>
#include <qt/guiutil.h>
#include <qt/peertablemodel.h>

#include <chain.h>
#include <chainparams.h>
#include <checkpoints.h>
#include <clientversion.h>
#include <validation.h>
#include <net.h>
#include <txmempool.h>
#include <ui_interface.h>
#include <util.h>
#include <warnings.h>

#include <stdint.h>

#include <QDebug>
#include <QTimer>

#include <boost/bind/placeholders.hpp>

using namespace boost::placeholders;

class CBlockIndex;

static int64_t nLastHeaderTipUpdateNotification = 0;
static int64_t nLastBlockTipUpdateNotification = 0;

ClientModel::ClientModel(OptionsModel *_optionsModel, QObject *parent) :
    QObject(parent),
    optionsModel(_optionsModel),
    peerTableModel(0),
    banTableModel(0),
    pollTimer(0),
    ignoredBlockChangeTimer(0)
{
    cachedBestHeaderHeight = -1;
    cachedBestHeaderTime = -1;
    cachedNumBlocks = -1;
    cachedTipBlockTime = -1;
    cachedVerificationProgress = 0.0;
    peerTableModel = new PeerTableModel(this);
    banTableModel = new BanTableModel(this);
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(updateTimer()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    lastIgnoredBlockChange.clear();

    // Starting the timer to check for ignored block updates now. The timer
    // will be stopped once a block is passed to BlockTipChanged with
    // fInitialSync set false.
    ignoredBlockChangeTimer = new QTimer(this);
    connect(ignoredBlockChangeTimer, SIGNAL(timeout()), this, SLOT(updateIgnoredBlockChanges()));
    ignoredBlockChangeTimer->start(MODEL_UPDATE_DELAY * 2);

    subscribeToCoreSignals();
}

ClientModel::~ClientModel()
{
    unsubscribeFromCoreSignals();
}

int ClientModel::getNumConnections(unsigned int flags) const
{
    CConnman::NumConnections connections = CConnman::CONNECTIONS_NONE;

    if(flags == CONNECTIONS_IN)
        connections = CConnman::CONNECTIONS_IN;
    else if (flags == CONNECTIONS_OUT)
        connections = CConnman::CONNECTIONS_OUT;
    else if (flags == CONNECTIONS_ALL)
        connections = CConnman::CONNECTIONS_ALL;

    if(g_connman)
         return g_connman->GetNodeCount(connections);
    return 0;
}

int ClientModel::getNumBlocks() const
{
    // Served from a cache kept fresh by BlockTipChanged. Only take the lock to
    // seed the cache the first time, and even then never block the GUI thread:
    // if cs_main is busy (e.g. mid-IBD) report the cached value and let the
    // next tip notification fill it in.
    if (cachedNumBlocks == -1) {
        TRY_LOCK(cs_main, lockMain);
        if (lockMain)
            cachedNumBlocks = chainActive.Height();
    }
    return cachedNumBlocks;
}

int ClientModel::getHeaderTipHeight() const
{
    if (cachedBestHeaderHeight == -1) {
        // make sure we initially populate the cache, but without blocking the
        // GUI thread; otherwise we just wait for the next tip update
        TRY_LOCK(cs_main, lockMain);
        if (lockMain && pindexBestHeader) {
            cachedBestHeaderHeight = pindexBestHeader->nHeight;
            cachedBestHeaderTime = pindexBestHeader->GetBlockTime();
        }
    }
    return cachedBestHeaderHeight;
}

int64_t ClientModel::getHeaderTipTime() const
{
    if (cachedBestHeaderTime == -1) {
        TRY_LOCK(cs_main, lockMain);
        if (lockMain && pindexBestHeader) {
            cachedBestHeaderHeight = pindexBestHeader->nHeight;
            cachedBestHeaderTime = pindexBestHeader->GetBlockTime();
        }
    }
    return cachedBestHeaderTime;
}

quint64 ClientModel::getTotalBytesRecv() const
{
    if(!g_connman)
        return 0;
    return g_connman->GetTotalBytesRecv();
}

quint64 ClientModel::getTotalBytesSent() const
{
    if(!g_connman)
        return 0;
    return g_connman->GetTotalBytesSent();
}

QDateTime ClientModel::getLastBlockDate() const
{
    // Served from the tip cache kept fresh by BlockTipChanged. Seed it once
    // without blocking the GUI thread on cs_main.
    if (cachedTipBlockTime != -1)
        return QDateTime::fromTime_t(cachedTipBlockTime);

    TRY_LOCK(cs_main, lockMain);
    if (lockMain && chainActive.Tip()) {
        cachedTipBlockTime = chainActive.Tip()->GetBlockTime();
        return QDateTime::fromTime_t(cachedTipBlockTime);
    }

    return QDateTime::fromTime_t(Params().GenesisBlock().GetBlockTime()); // Genesis block's time of current network
}

long ClientModel::getMempoolSize() const
{
    return mempool.size();
}

size_t ClientModel::getMempoolDynamicUsage() const
{
    return mempool.DynamicMemoryUsage();
}

double ClientModel::getVerificationProgress(const CBlockIndex *tipIn) const
{
    CBlockIndex *tip = const_cast<CBlockIndex *>(tipIn);
    if (!tip)
    {
        // Never block the GUI thread here; the tip is normally supplied by the
        // caller (BlockTipChanged / numBlocksChanged), so a busy cs_main just
        // means we briefly report the last known progress.
        TRY_LOCK(cs_main, lockMain);
        if (!lockMain)
            return cachedVerificationProgress;
        tip = chainActive.Tip();
    }
    double progress = GuessVerificationProgress(Params().TxData(), tip);
    cachedVerificationProgress = progress;
    return progress;
}

void ClientModel::updateTimer()
{
    // The block-count/date/progress caches are seeded opportunistically with a
    // TRY_LOCK so the GUI thread never blocks on cs_main. If that first attempt
    // loses the race the cache still holds its sentinel, and the widgets that
    // were drawn once at start-up would keep showing "Block -1" until the next
    // tip notification (a minute or more on mainnet). Retry here, and announce
    // the values as soon as they become available.
    if (cachedNumBlocks == -1) {
        const int nBlocks = getNumBlocks();
        if (nBlocks != -1)
            Q_EMIT numBlocksChanged(nBlocks, getLastBlockDate(), getVerificationProgress(nullptr), false);
    }

    // no locking required at this point
    // the following calls will acquire the required lock
    Q_EMIT mempoolSizeChanged(getMempoolSize(), getMempoolDynamicUsage());
    Q_EMIT bytesChanged(getTotalBytesRecv(), getTotalBytesSent());
}

void ClientModel::updateNumConnections(int numConnections)
{
    Q_EMIT numConnectionsChanged(numConnections);
}

void ClientModel::updateNetworkActive(bool networkActive)
{
    Q_EMIT networkActiveChanged(networkActive);
}

void ClientModel::updateAlert()
{
    Q_EMIT alertsChanged(getStatusBarWarnings());
}

bool ClientModel::inInitialBlockDownload() const
{
    return IsInitialBlockDownload();
}

enum BlockSource ClientModel::getBlockSource() const
{
    if (fReindex)
        return BLOCK_SOURCE_REINDEX;
    else if (fImporting)
        return BLOCK_SOURCE_DISK;
    else if (getNumConnections() > 0)
        return BLOCK_SOURCE_NETWORK;

    return BLOCK_SOURCE_NONE;
}

void ClientModel::setNetworkActive(bool active)
{
    if (g_connman) {
         g_connman->SetNetworkActive(active);
    }
}

bool ClientModel::getNetworkActive() const
{
    if (g_connman) {
        return g_connman->GetNetworkActive();
    }
    return false;
}

QString ClientModel::getStatusBarWarnings() const
{
    return QString::fromStdString(GetWarnings("gui"));
}

OptionsModel *ClientModel::getOptionsModel()
{
    return optionsModel;
}

PeerTableModel *ClientModel::getPeerTableModel()
{
    return peerTableModel;
}

BanTableModel *ClientModel::getBanTableModel()
{
    return banTableModel;
}

QString ClientModel::formatFullVersion() const
{
    return QString::fromStdString(FormatFullVersion());
}

QString ClientModel::formatSubVersion() const
{
    return QString::fromStdString(strSubVersion);
}

bool ClientModel::isReleaseVersion() const
{
    return CLIENT_VERSION_IS_RELEASE;
}

QString ClientModel::formatClientStartupTime() const
{
    return QDateTime::fromTime_t(GetStartupTime()).toString();
}

QString ClientModel::dataDir() const
{
    return GUIUtil::boostPathToQString(GetDataDir());
}

void ClientModel::UpdateBlockCountLater(const int count, const QDateTime& date,
        const double nVerificationProgress, const bool fHeader)
{
    std::lock_guard<std::mutex> lock(blockChangeMutex);

    lastIgnoredBlockChange.count = count;
    lastIgnoredBlockChange.date = date;
    lastIgnoredBlockChange.nVerificationProgress = nVerificationProgress;
    lastIgnoredBlockChange.fHeader = fHeader;

    // When the ignoredBlockChangeTimer expires and calls
    // updateIgnoredBlockChanges it will decide whether to
    // send this ignored block update
}

void ClientModel::StopIgnoredBlockChangeTimer()
{
    ignoredBlockChangeTimer->stop();
}

void ClientModel::updateIgnoredBlockChanges()
{
    // Check if any block count updates were held back and send it now unless
    // the current state is newer. The held update is written from the
    // validation thread under blockChangeMutex; date is implicitly shared, so
    // reading or clearing it without the same lock races the writer. Snapshot
    // and clear under the lock, and emit only after releasing it so no slot
    // ever runs while the validation thread is blocked on the mutex.
    int count;
    QDateTime date;
    double nVerificationProgress;
    bool fHeader;
    {
        std::lock_guard<std::mutex> lock(blockChangeMutex);
        const bool fSend = cachedBestHeaderHeight > 0 &&
                lastIgnoredBlockChange.count == cachedBestHeaderHeight;
        count = lastIgnoredBlockChange.count;
        date = lastIgnoredBlockChange.date;
        nVerificationProgress = lastIgnoredBlockChange.nVerificationProgress;
        fHeader = lastIgnoredBlockChange.fHeader;
        lastIgnoredBlockChange.clear();
        if (!fSend)
            return;
    }

    Q_EMIT numBlocksChanged(count, date, nVerificationProgress, fHeader);
}

void ClientModel::updateBanlist()
{
    banTableModel->refresh();
}

// Handlers for core signals
static void ShowProgress(ClientModel *clientmodel, const std::string &title, int nProgress)
{
    // emits signal "showProgress"
    QMetaObject::invokeMethod(clientmodel, "showProgress", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(title)),
                              Q_ARG(int, nProgress));
}

static void NotifyNumConnectionsChanged(ClientModel *clientmodel, int newNumConnections)
{
    // Too noisy: qDebug() << "NotifyNumConnectionsChanged: " + QString::number(newNumConnections);
    QMetaObject::invokeMethod(clientmodel, "updateNumConnections", Qt::QueuedConnection,
                              Q_ARG(int, newNumConnections));
}

static void NotifyNetworkActiveChanged(ClientModel *clientmodel, bool networkActive)
{
    QMetaObject::invokeMethod(clientmodel, "updateNetworkActive", Qt::QueuedConnection,
                              Q_ARG(bool, networkActive));
}

static void NotifyAlertChanged(ClientModel *clientmodel)
{
    qDebug() << "NotifyAlertChanged";
    QMetaObject::invokeMethod(clientmodel, "updateAlert", Qt::QueuedConnection);
}

static void BannedListChanged(ClientModel *clientmodel)
{
    qDebug() << QString("%1: Requesting update for peer banlist").arg(__func__);
    QMetaObject::invokeMethod(clientmodel, "updateBanlist", Qt::QueuedConnection);
}

static void BlockTipChanged(ClientModel *clientmodel, bool initialSync, const CBlockIndex *pIndex, bool fHeader)
{

    int64_t now = 0;
    if (initialSync)
        now = GetTimeMillis();

    // Keep the active-tip caches fresh on every block-tip notification (this
    // runs off the GUI thread with the tip already in hand), so the GUI-thread
    // getters can serve height/time/progress without ever taking cs_main.
    if (!fHeader) {
        clientmodel->cachedNumBlocks = pIndex->nHeight;
        clientmodel->cachedTipBlockTime = pIndex->GetBlockTime();
    }

    int64_t& nLastUpdateNotification = fHeader ? nLastHeaderTipUpdateNotification : nLastBlockTipUpdateNotification;

    if (initialSync && !fHeader) {
        if (now - nLastUpdateNotification > MODEL_UPDATE_DELAY) {
            QMetaObject::invokeMethod(clientmodel, "numBlocksChangedIBD", Qt::QueuedConnection,
                    Q_ARG(int, pIndex->nHeight),
                    Q_ARG(double, clientmodel->getVerificationProgress(pIndex)));

            nLastUpdateNotification = now;
        } else {
            // Hold the update for the timer rather than dropping it, as the
            // out-of-sync path below already does. The last block of a sync or
            // a reindex arrives while this is still the initial-sync path, and
            // if it lands inside the throttle window its update was discarded.
            // Nothing then replaced it: the interface only recomputes whether
            // the node is caught up when a new tip arrives, so on a chain that
            // is not currently producing blocks it went on reporting a sync in
            // progress indefinitely, for a node that was in fact at the tip.
            // The timer's own condition - that the held count has reached the
            // best header - is what decides whether this gets delivered.
            clientmodel->UpdateBlockCountLater(pIndex->nHeight,
                    QDateTime::fromTime_t(pIndex->GetBlockTime()),
                    clientmodel->getVerificationProgress(pIndex),
                    fHeader);
        }
        return;
    }

    if (initialSync && fHeader) {
        // Record the header tip before returning. Throttling the *notification*
        // during initial sync is deliberate - headers arrive far faster than the
        // interface can usefully repaint - but returning before the cache is
        // written left the getter serving whatever value it was seeded with on
        // its first call, so the interface reported a header height frozen near
        // where the sync began while the node had in fact fetched the entire
        // header chain. Update the cache, then throttle.
        clientmodel->cachedBestHeaderHeight = pIndex->nHeight;
        clientmodel->cachedBestHeaderTime = pIndex->GetBlockTime();
        return;
    }


    // Once we are synchronized we can stop the ignored block changes timer.
    //
    // Queued, not called directly. This function runs on the validation thread
    // - which is why every other hand-off below goes through invokeMethod - and
    // ignoredBlockChangeTimer belongs to the GUI thread. Qt refuses to stop a
    // timer from any other thread: the call did nothing except print
    // "QObject::killTimer: Timers cannot be stopped from another thread", so
    // the timer in fact kept running for the life of the process, and this
    // touched a QObject across threads on every block after the node caught up.
    if (!initialSync)
        QMetaObject::invokeMethod(clientmodel, "StopIgnoredBlockChangeTimer", Qt::QueuedConnection);


    if (fHeader) {
        // cache best headers time and height to reduce future cs_main locks
        clientmodel->cachedBestHeaderHeight = pIndex->nHeight;
        clientmodel->cachedBestHeaderTime = pIndex->GetBlockTime();
    }
    // if we are in-sync, update the UI regardless of last update time
    if (!initialSync || now - nLastUpdateNotification > MODEL_UPDATE_DELAY) {
        //pass an async signal to the UI thread
        QMetaObject::invokeMethod(clientmodel, "numBlocksChanged", Qt::QueuedConnection,
                                  Q_ARG(int, pIndex->nHeight),
                                  Q_ARG(QDateTime, QDateTime::fromTime_t(pIndex->GetBlockTime())),
                                  Q_ARG(double, clientmodel->getVerificationProgress(pIndex)),
                                  Q_ARG(bool, fHeader));
        nLastUpdateNotification = now;
    } else {
        // If the update was ignored because it happened too soon after the last
        // update, cache it and send the update signal later
        clientmodel->UpdateBlockCountLater(pIndex->nHeight,
                QDateTime::fromTime_t(pIndex->GetBlockTime()),
                clientmodel->getVerificationProgress(pIndex),
                fHeader);
    }
}

void ClientModel::subscribeToCoreSignals()
{
    // Connect signals to client
    uiInterface.ShowProgress.connect(boost::bind(ShowProgress, this, _1, _2));
    uiInterface.NotifyNumConnectionsChanged.connect(boost::bind(NotifyNumConnectionsChanged, this, _1));
    uiInterface.NotifyNetworkActiveChanged.connect(boost::bind(NotifyNetworkActiveChanged, this, _1));
    uiInterface.NotifyAlertChanged.connect(boost::bind(NotifyAlertChanged, this));
    uiInterface.BannedListChanged.connect(boost::bind(BannedListChanged, this));
    uiInterface.NotifyBlockTip.connect(boost::bind(BlockTipChanged, this, _1, _2, false));
    uiInterface.NotifyHeaderTip.connect(boost::bind(BlockTipChanged, this, _1, _2, true));
}

void ClientModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    uiInterface.ShowProgress.disconnect(boost::bind(ShowProgress, this, _1, _2));
    uiInterface.NotifyNumConnectionsChanged.disconnect(boost::bind(NotifyNumConnectionsChanged, this, _1));
    uiInterface.NotifyNetworkActiveChanged.disconnect(boost::bind(NotifyNetworkActiveChanged, this, _1));
    uiInterface.NotifyAlertChanged.disconnect(boost::bind(NotifyAlertChanged, this));
    uiInterface.BannedListChanged.disconnect(boost::bind(BannedListChanged, this));
    uiInterface.NotifyBlockTip.disconnect(boost::bind(BlockTipChanged, this, _1, _2, false));
    uiInterface.NotifyHeaderTip.disconnect(boost::bind(BlockTipChanged, this, _1, _2, true));
}
