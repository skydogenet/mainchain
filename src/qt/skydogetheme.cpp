// Copyright (c) 2022- The Bitcoin Core developers
// Copyright (c) 2026 The Drivechain developers
// Copyright (c) 2026 The Skydoge developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <qt/skydogetheme.h>

#include <QApplication>
#include <QColor>
#include <QFile>
#include <QObject>
#include <QTextStream>

namespace SkydogeTheme
{

const QList<Info>& All()
{
    static const QList<Info> themes = QList<Info>()
        << Info{"default", QObject::tr("System default"), ""}
        << Info{"qdark", QObject::tr("Dark (legacy)"), ":/qdarkstyle/darkstyle"}
        << Info{"classic", QObject::tr("Classic"), ":/themes/classic"}
        << Info{"light", QObject::tr("Light"), ":/themes/light"}
        << Info{"dark", QObject::tr("Dark"), ":/themes/dark"}
        << Info{"midnight", QObject::tr("Midnight Money"), ":/themes/midnight"}
        << Info{"neon", QObject::tr("Neon Terminal"), ":/themes/neon"}
        << Info{"glass", QObject::tr("Glass Neobank"), ":/themes/glass"}
        << Info{"wow", QObject::tr("Borealis"), ":/themes/wow"}
        << Info{"matrix", QObject::tr("Matrix Green"), ":/themes/matrix"}
        << Info{"nord", QObject::tr("Nord Frost"), ":/themes/nord"}
        << Info{"ocean", QObject::tr("Ocean Teal"), ":/themes/ocean"}
        << Info{"amethyst", QObject::tr("Amethyst Royal"), ":/themes/amethyst"}
        << Info{"dracula", QObject::tr("Dracula"), ":/themes/dracula"}
        << Info{"solar", QObject::tr("Solar Gold"), ":/themes/solar"}
        << Info{"crimson", QObject::tr("Crimson Ember"), ":/themes/crimson"}
        << Info{"rose", QObject::tr("Rose Quartz"), ":/themes/rose"}
        << Info{"sepia", QObject::tr("Sepia Parchment"), ":/themes/sepia"};
    return themes;
}

QString DefaultId()
{
    return "default";
}

QString StyleSheet(const QString& id)
{
    QString resource;
    for (const Info& info : All()) {
        if (info.id == id) {
            resource = info.resource;
            break;
        }
    }

    // The default theme and unknown themes have no style sheet
    if (resource.isEmpty())
        return QString();

    QFile file(resource);
    if (!file.open(QFile::ReadOnly | QFile::Text))
        return QString();

    QTextStream stream(&file);
    return stream.readAll();
}

void Apply(const QString& id)
{
    qApp->setStyleSheet(StyleSheet(id));
}

QColor Accent(const QString& id)
{
    if (id == "midnight") return QColor(0x00, 0xd6, 0x8f);
    if (id == "neon")     return QColor(0x00, 0xe5, 0xff);
    if (id == "glass")    return QColor(0x7b, 0x93, 0xff);
    if (id == "classic")  return QColor(0x1f, 0x4e, 0x79);
    if (id == "light")    return QColor(0x0a, 0xa4, 0x6b);
    if (id == "dark")     return QColor(0x4d, 0x9f, 0xff);
    if (id == "wow")      return QColor(0xe9, 0x3c, 0xac); // Borealis
    if (id == "qdark")    return QColor(0xc8, 0xc8, 0xc8);
    if (id == "matrix")   return QColor(0x00, 0xff, 0x41);
    if (id == "nord")     return QColor(0x88, 0xc0, 0xd0);
    if (id == "ocean")    return QColor(0x14, 0xb8, 0xa6);
    if (id == "amethyst") return QColor(0xa8, 0x55, 0xf7);
    if (id == "dracula")  return QColor(0xbd, 0x93, 0xf9);
    if (id == "solar")    return QColor(0xff, 0xb3, 0x00);
    if (id == "crimson")  return QColor(0xff, 0x5a, 0x3c);
    if (id == "rose")     return QColor(0xe0, 0x63, 0x7f);
    if (id == "sepia")    return QColor(0x8b, 0x5e, 0x34);
    // Default / unknown theme: a neutral tone that reads on any background
    return QColor(0x9a, 0xa0, 0xaa);
}

}
