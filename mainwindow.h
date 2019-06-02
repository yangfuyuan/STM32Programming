/*
 *  STM32Programming
 *
 *  Copyright 2015 - 2020 yangfuyuan
 *
 *
 */

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include "sdk/include/stm32_bootloader.h"
#include <QMainWindow>
#include <QTime>
#include <QSerialPortInfo>
#if QT_VERSION >= 0x050000
#include <QtConcurrent/QtConcurrentMap>
#include <QtConcurrent/QtConcurrentRun>
#else
#include <QtConcurrentMap>
#include <QtConcurrentRun>
#endif

#include "elapsedtimer.h"

using namespace stm32;

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow {
  Q_OBJECT
 public:

  enum AppState {
    IDLE = 0,
    INITIALED = 1,
    READING = 2,
    WRITING = 3,
    VERIFYING = 4,
    CANCELED = 5,
    EXIT = 6,
  };

  enum MessageLevel {
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

  MainWindow(QWidget * = NULL);
  ~MainWindow();
  void closeEvent(QCloseEvent *event);

  void initialParamters();
  void initialObject();
  void initialSignalSlot();

 protected slots:
  void on_tbBrowse_clicked();
  void on_bCancel_clicked();
  void on_bWrite_clicked();
  void on_bRead_clicked();
 private slots:
  void on_bDevice_clicked();

  void on_ClearBtn_clicked();

  void on_SaveBtn_clicked();

  void on_deleteBtn_clicked();

  void on_ConnectBtn_clicked(bool checked);

  void on_bVerfiy_toggled(bool checked);

  void on_bSkip_toggled(bool checked);

  void on_bRun_toggled(bool checked);

  void userOperator(const QString &filename);

 signals:
  void logView(const QString &info, int level);
  void dataProcessSignal(int value, int total);
  void taskFininshedSignal();

 private:
  void wait_ms(unsigned long time);
 private:
  // find attached devices
  void setReadWriteButtonState(bool state);
  void setConnectButtonState(bool state);
  void loginfo(const std::string &info, int level);
  void logMessage(QString str, QString tag, MessageLevel level);
  void enabled(bool enable);
  void bootloader(const QString &filename);

 private slots:
  void logInfoSlot(const QString &info, int level);
  void dataProcessSlot(int value, int total);
  void taskFininshed();

 private:
  Ui::MainWindow *ui;
  AppState m_state;

  ElapsedTimer *elapsed_timer;
  enum actions	m_action;
  stm32_info stm;
  QMutex operator_mutex;

  int		  npages;
  int     spage;
  bool    no_erase;
  bool		verify;
  int		  retry;
  bool		exec_flag;
  uint32_t	execute;
  char		init_flag;
  char		force_binary;
  char		reset_flag;
  uint32_t	start_addr;
  uint32_t	readwrite_len;

};

#endif // MAINWINDOW_H
