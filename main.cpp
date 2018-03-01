/*
 *  STM32Programming
 *
 *  Copyright 2015 - 2020 yangfuyuan
 *  
 * 
 */
#include <QApplication>
#include <cstdio>
#include <cstdlib>


#include "mainwindow.h"


int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationDisplayName(VER);
    app.setAttribute(Qt::AA_UseDesktopOpenGL);

    QFile file(":/qss/scroll.qss");
    file.open(QFile::ReadOnly);
    QString styleSheet = QString::fromLatin1(file.readAll());
    qApp->setStyleSheet(styleSheet);
    file.close();

    MainWindow* mainwindow = MainWindow::getInstance();
    mainwindow->show();
    mainwindow->move((QApplication::desktop()->width() - mainwindow->width())/2,
               (QApplication::desktop()->height() - mainwindow->height())/2);
    return app.exec();
}
