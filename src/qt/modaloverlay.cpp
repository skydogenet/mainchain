// Copyright (c) 2016-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/modaloverlay.h>
#include <qt/forms/ui_modaloverlay.h>

#include <qt/guiutil.h>

#include <chainparams.h>

#include <QResizeEvent>
#include <QPropertyAnimation>

ModalOverlay::ModalOverlay(QWidget *parent) :
QWidget(parent),
ui(new Ui::ModalOverlay),
layerIsVisible(false),
userClosed(false)
{
    ui->setupUi(this);

    if (parent) {
        parent->installEventFilter(this);
        raise();
    }

    ui->labelProgress->setVisible(false);

    setVisible(false);
}

ModalOverlay::~ModalOverlay()
{
    delete ui;
}

bool ModalOverlay::eventFilter(QObject * obj, QEvent * ev) {
    if (obj == parent()) {
        if (ev->type() == QEvent::Resize) {
            QResizeEvent * rev = static_cast<QResizeEvent*>(ev);
            resize(rev->size());
            if (!layerIsVisible)
                setGeometry(0, height(), width(), height());

        }
        else if (ev->type() == QEvent::ChildAdded) {
            raise();
        }
    }
    return QWidget::eventFilter(obj, ev);
}

//! Tracks parent widget changes
bool ModalOverlay::event(QEvent* ev) {
    if (ev->type() == QEvent::ParentAboutToChange) {
        if (parent()) parent()->removeEventFilter(this);
    }
    else if (ev->type() == QEvent::ParentChange) {
        if (parent()) {
            parent()->installEventFilter(this);
            raise();
        }
    }
    return QWidget::event(ev);
}

void ModalOverlay::setProgress(int height, int headerHeight, double nVerificationProgress)
{
    if (nVerificationProgress >= 0.01)
        ui->labelProgress->setVisible(true);

    // nVerificationProgress is a fraction in [0,1]; render it as a real
    // percentage with two decimals so it advances smoothly (the old code took
    // the last two chars of the formatted fraction — whole percents only, and
    // "00" at 100%).
    QString text = "Progress: ";
    text += QString::number(nVerificationProgress * 100.0, 'f', 2);
    text += "%";

    // Lead with the count of blocks still to connect. The percentage is
    // measured against the whole chain, so on a mature one it is pinned near
    // 100 and barely moves: a node a day behind catching up 1,835 blocks
    // crawled from 99.88% to 100.00% over nearly two minutes and read as
    // frozen. Blocks remaining counts down visibly the entire time, which is
    // the number that shows the node is working.
    const int nRemaining = (headerHeight > height) ? headerHeight - height : 0;
    if (nRemaining > 0) {
        ui->labelProgress->setText(
            tr("%n block(s) remaining", "", nRemaining) + QString(" — ") + text);
    } else {
        ui->labelProgress->setText(text);
    }
}

void ModalOverlay::toggleVisibility()
{
    showHide(layerIsVisible, true);
    if (!layerIsVisible)
        userClosed = true;
}

void ModalOverlay::showHide(bool hide, bool userRequested)
{
    if ( (layerIsVisible && !hide) || (!layerIsVisible && hide) || (!hide && userClosed && !userRequested))
        return;

    if (!isVisible() && !hide)
        setVisible(true);

    setGeometry(0, hide ? 0 : height(), width(), height());

    QPropertyAnimation* animation = new QPropertyAnimation(this, "pos");
    animation->setDuration(300);
    animation->setStartValue(QPoint(0, hide ? 0 : this->height()));
    animation->setEndValue(QPoint(0, hide ? this->height() : 0));
    animation->setEasingCurve(QEasingCurve::OutQuad);
    animation->start(QAbstractAnimation::DeleteWhenStopped);
    layerIsVisible = !hide;
}

void ModalOverlay::on_pushButtonHide_clicked()
{
    showHide(true);
    userClosed = true;
}
