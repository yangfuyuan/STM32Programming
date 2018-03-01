/*
 *  STM32Programming
 *
 *  Copyright 2015 - 2020 yangfuyuan
 *  
 * 
 */

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtWidgets>
#include "ui_mainwindow.h"
#include <QSerialPortInfo>
#include <stm32_bootloader.h>

class ElapsedTimer;

using namespace stm32;

class MainWindow : public QMainWindow, public Ui::MainWindow
{
    Q_OBJECT
    public:
        static MainWindow* getInstance() {
            // !NOT thread safe  - first call from main only
            if (!instance)
                instance = new MainWindow();
            return instance;
        }

        enum MessageLevel
           {
             INFO = 0,
             WARNING = 1,
             CRITICAL = 2
           };

        enum actions {
            ACT_NONE,
            ACT_READ,
            ACT_WRITE,
            ACT_WRITE_UNPROTECT,
            ACT_READ_PROTECT,
            ACT_READ_UNPROTECT,
            ACT_ERASE_ONLY,
            ACT_CRC
        };

        ~MainWindow();
        void closeEvent(QCloseEvent *event);
        enum Status {STATUS_IDLE=0, STATUS_READING, STATUS_WRITING, STATUS_VERIFYING, STATUS_EXIT, STATUS_CANCELED};

    protected slots:
        void on_tbBrowse_clicked();
        void on_bCancel_clicked();
        void on_bWrite_clicked();
        void on_bRead_clicked();
private slots:
        void on_UpdateBtn_clicked();

        void on_ClearBtn_clicked();

        void on_SaveBtn_clicked();

        void on_deleteBtn_clicked();

        void on_ConnectBtn_clicked(bool checked);

        void on_bVerfiy_toggled(bool checked);

        void on_bSkip_toggled(bool checked);

        void on_bRun_toggled(bool checked);

protected:
        MainWindow(QWidget* = NULL);

private:
        static MainWindow* instance;
        // find attached devices
        void setReadWriteButtonState(bool state);
        void logMessage(QString str,QString tag, MessageLevel level);
        void loginfo(std::string info, int level);
        void enabled(bool enable);
        void bootloader();

        int status;
        QTime update_timer;
        ElapsedTimer *elapsed_timer = NULL;
        enum actions	m_action;

        stm32_info stm;

        int		npages;
        int             spage;
        bool             no_erase;
        bool		verify;
        int		retry;
        bool		exec_flag;
        uint32_t	execute;
        char		init_flag;
        char		force_binary;
        char		reset_flag;
        uint32_t	start_addr;
        uint32_t	readwrite_len;

};

#endif // MAINWINDOW_H
