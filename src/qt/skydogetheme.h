// Copyright (c) 2022- The Bitcoin Core developers
// Copyright (c) 2026 The Drivechain developers
// Copyright (c) 2026 The Skydoge developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SKYDOGETHEME_H
#define BITCOIN_QT_SKYDOGETHEME_H

#include <QColor>
#include <QList>
#include <QString>

/** Selectable style sheet based themes for the GUI.
 */
namespace SkydogeTheme
{
    struct Info {
        QString id;
        QString name;
        QString resource;
    };

    // List of the available themes in display order
    const QList<Info>& All();

    // Identifier of the default (system) theme
    QString DefaultId();

    // Read the style sheet of the theme with the given identifier.
    // Returns an empty string for the default theme and unknown identifiers.
    QString StyleSheet(const QString& id);

    // Set the application style sheet to the theme with the given identifier
    void Apply(const QString& id);

    // Accent colour of the given theme, used to tint toolbar icons so they
    // match the active theme instead of the platform's default highlight.
    QColor Accent(const QString& id);
}

#endif // BITCOIN_QT_SKYDOGETHEME_H
