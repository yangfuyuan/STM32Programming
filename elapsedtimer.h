/*
 *  STM32Programming
 *
 *  Copyright 2015 - 2020 yangfuyuan
 *
 *
 */

#ifndef ELAPSEDTIMER_H
#define ELAPSEDTIMER_H
#include <QtWidgets>
#include <QLabel>
#include <QTime>
#include <QString>

class ElapsedTimer : public QLabel
{
    Q_OBJECT

public:
    explicit ElapsedTimer(QWidget *parent = 0);
    ~ElapsedTimer();
    int ms();
    void update(unsigned long long progress, unsigned long long total);
    void start();
    void stop();

private:
//    QLabel *lDisplay;
    QTime *timer;
    static const unsigned short MS_PER_SEC = 1000;
    static const unsigned short SECS_PER_MIN = 60;
    static const unsigned short MINS_PER_HOUR = 60;
    static const unsigned short SECS_PER_HOUR = (SECS_PER_MIN * MINS_PER_HOUR);
};

#endif // ELAPSEDTIMER_H
