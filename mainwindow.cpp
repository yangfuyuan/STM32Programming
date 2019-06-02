/*
 *  STM32Programming
 *
 *  Copyright 2015 - 2020 yangfuyuan
 *
 *
 */

#include <sdk/src/common.h>
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileInfo>
#include <QGroupBox>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent),
  ui(new Ui::MainWindow) {
  ui->setupUi(this);
  initialParamters();
  initialObject();
  initialSignalSlot();

}

MainWindow::~MainWindow() {
  if (stm.cmd) {
    free(stm.cmd);
  }

  operator_mutex.tryLock(1000);
  operator_mutex.unlock();

  if (elapsed_timer != NULL) {
    delete elapsed_timer;
    elapsed_timer = NULL;
  }

  if (STM32BootLoader::singleton()) {
    STM32BootLoader::singleton()->sig.disconnect_all();
    STM32BootLoader::singleton()->disconnect();
    STM32BootLoader::singleton()->done();
  }
}

void MainWindow::initialParamters() {
  m_state = AppState::IDLE;
  stm.cmd = NULL;
  npages		= 0;
  spage           = 0;
  no_erase        = false;
  verify		= false;
  retry		= 10;
  exec_flag	= false;
  execute		= 0;
  init_flag	= 1;
  force_binary	= 0;
  reset_flag	= 0;
  start_addr	= 0;
  readwrite_len	= 0;
  m_action = ACT_NONE;
  ui->statusbar->showMessage(tr("Waiting for a task."));
  setReadWriteButtonState(false);
  ui->filepath->setCurrentText(QCoreApplication::applicationDirPath() +
                               "/temp.bin");
  QList<QSerialPortInfo> ports = QSerialPortInfo::availablePorts();

  Q_FOREACH (QSerialPortInfo info, ports) {
    QString name = info.portName();
    ui->bDevice->addItem(name);
  }

  stm.cmd = (stm32_cmd *)malloc(sizeof(stm32_cmd));
  memset(stm.cmd, STM32_CMD_ERR, sizeof(stm32_cmd));

}

void MainWindow::initialObject() {
  elapsed_timer = new ElapsedTimer();
  ui->statusbar->addPermanentWidget(
    elapsed_timer);   // "addpermanent" puts it on the RHS of the statusbar

  ui->progressbar->reset();

}

void MainWindow::initialSignalSlot() {
  connect(this, SIGNAL(logView(QString, int)), this,
          SLOT(logInfoSlot(QString, int)));
  connect(this, SIGNAL(dataProcessSignal(int, int)), this,
          SLOT(dataProcessSlot(int, int)));
  connect(this, SIGNAL(taskFininshedSignal()), this, SLOT(taskFininshed()));

}


void MainWindow::setReadWriteButtonState(bool state) {
  ui->bWrite->setEnabled(state);
  ui->bRead->setEnabled(state);
}

void MainWindow::setConnectButtonState(bool state) {
  ui->ConnectBtn->setEnabled(state);
  ui->bCancel->setEnabled(state);
  ui->bExit->setEnabled(state);
}

void MainWindow::closeEvent(QCloseEvent *event) {
  if (m_state == READING) {
    if (QMessageBox::warning(this, tr("Exit?"),
                             tr("Exiting now will result in a corrupt bin file.\n"
                                "Are you sure you want to exit?"),
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes) {
      m_state = EXIT;
    }

    event->ignore();
  } else if (m_state == WRITING) {
    if (QMessageBox::warning(this, tr("Exit?"),
                             tr("Exiting now will result in a corrupt bin.\n"
                                "Are you sure you want to exit?"),
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes) {
      m_state = EXIT;
    }

    event->ignore();
  } else if (m_state == VERIFYING) {
    if (QMessageBox::warning(this, tr("Exit?"),
                             tr("Exiting now will cancel verifying bin.\n"
                                "Are you sure you want to exit?"),
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes) {
      m_state = EXIT;
    }

    event->ignore();
  }
}

void MainWindow::on_tbBrowse_clicked() {
  QString fileType;
  fileType.append(tr("Bin File (*.bin);;Hex File (*.hex)"));
  // create a generic FileDialog
  QFileDialog dialog(this, tr("Select a Binary File"));
  dialog.setNameFilter(fileType);
  dialog.setFileMode(QFileDialog::AnyFile);
  dialog.setViewMode(QFileDialog::Detail);
  dialog.setConfirmOverwrite(false);
  dialog.selectFile(QCoreApplication::applicationDirPath());


  if (dialog.exec()) {
    // selectedFiles returns a QStringList - we just want 1 filename,
    //	so use the zero'th element from that list as the filename
    QString fileLocation = (dialog.selectedFiles())[0];

    if (!fileLocation.isNull()) {
      ui->filepath->setCurrentText(fileLocation);
    }
  }
}


void MainWindow::on_bCancel_clicked() {
  if ((m_state == READING) || (m_state == WRITING)) {
    if (QMessageBox::warning(this, tr("Cancel?"),
                             tr("Canceling now will result in a corrupt destination.\n"
                                "Are you sure you want to cancel?"),
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes) {
      m_state = CANCELED;
    }
  } else if (m_state == VERIFYING) {
    if (QMessageBox::warning(this, tr("Cancel?"), tr("Cancel Verify.\n"
                             "Are you sure you want to cancel?"),
                             QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes) {
      m_state = CANCELED;
    }

  }
}

void MainWindow::on_bWrite_clicked() {
  m_action = ACT_WRITE;
  QString filename = ui->filepath->currentText();
  QFileInfo f(filename);

  if (!filename.contains(".bin") && !filename.contains(".hex")) {
    emit logView("file format is error!!", CRITICAL);
    return;
  } else if (filename.isEmpty()) {
    emit logView("file is empty, please select file!!", CRITICAL);
    return;
  } else if (!f.exists()) {
    emit logView("file is not exist!!", CRITICAL);
    return;
  }

  if (!ui->StartAddress->currentText().contains("0x")) {
    emit logView("start address format error!!", CRITICAL);
    return;
  }

  setReadWriteButtonState(false);
  bool ok;
  start_addr = ui->StartAddress->currentText().toInt(&ok, 16);
  readwrite_len = f.size();
  m_state = WRITING;
  userOperator(filename);
}

void MainWindow::on_bRead_clicked() {
  m_action = ACT_READ;
  QString filename = ui->filepath->currentText();

  if (!filename.contains(".bin")) {
    emit logView("file format is error!!", CRITICAL);
    return;

  } else if (filename.isEmpty()) {
    emit logView("file is empty, please select file!!", CRITICAL);
    return;
  }

  if (!ui->StartAddress->currentText().contains("0x")) {
    emit logView("start address format error!!", CRITICAL);
    return;
  }

  setReadWriteButtonState(false);
  bool ok;
  start_addr = ui->StartAddress->currentText().toInt(&ok, 16);

  if (ui->leSize->text().contains("0x")) {
    readwrite_len =  ui->leSize->text().toInt(&ok, 16);
  } else {
    readwrite_len =  ui->leSize->text().toInt();

  }

  m_state = READING;
  userOperator(filename);

}

void MainWindow::enabled(bool enable) {
  ui->bType->setEnabled(enable);
  ui->bDevice->setEnabled(enable);
  ui->bBaudrate->setEnabled(enable);
  ui->bDatabits->setEnabled(enable);
  ui->bStopbits->setEnabled(enable);
  ui->bParity->setEnabled(enable);
  ui->bFlowControl->setEnabled(enable);
}

void MainWindow::logMessage(QString str, QString tag, MessageLevel level) {
  if (ui->level_1->isChecked()) {

    QString flag;

    if (level == INFO) {
      flag = "INFO";
    } else if (level == WARNING) {
      flag = "WARNING";

    } else if (level == CRITICAL) {
      flag = "ERROR";

    }

    QListWidgetItem *item = new QListWidgetItem(tr("%1[%2]:%23").arg(tag).arg(
          flag).arg(str));

    ui->loglist->addItem(item);

    switch (level) {
      case INFO:
        item->setBackgroundColor(Qt::white);
        break;

      case WARNING:
        item->setBackgroundColor(Qt::yellow);
        break;

      case CRITICAL:
        item->setBackgroundColor(Qt::red);
        break;

      default:
        break;
    }
  } else if (ui->level_2->isChecked()) {
    if (level == WARNING) {
      QListWidgetItem *item = new QListWidgetItem(tr("%1[WARNING]:%2").arg(tag).arg(
            str));
      ui->loglist->addItem(item);
      item->setBackgroundColor(Qt::yellow);
    }

  } else if (ui->level_3->isChecked()) {
    if (level == CRITICAL) {
      QListWidgetItem *item = new QListWidgetItem(tr("%1[ERROR]:%2").arg(tag).arg(
            str));
      ui->loglist->addItem(item);
      item->setBackgroundColor(Qt::red);
    }

  }

  ui->loglist->setCurrentRow(ui->loglist->count() - 1);
}

void MainWindow::loginfo(const string &info, int level) {
  emit logView(QString::fromStdString(info), level);
  //QCoreApplication::processEvents();
}

void MainWindow::logInfoSlot(const QString &info, int level) {
  logMessage(info,
             QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),
             (MessageLevel)level);
}

void MainWindow::dataProcessSlot(int value, int total) {
  ui->progressbar->setValue(value);
  elapsed_timer->update(value, total);
}

void MainWindow::taskFininshed() {
  ui->statusbar->showMessage(tr("disconnected."));
  enabled(true);
  ui->ConnectBtn->setChecked(false);
  setReadWriteButtonState(false);
  ui->lDevice->setText("-");
  ui->lType->setText("-");
  ui->lDeviceID->setText("-");
  ui->lCPU->setText("-");
  ui->ConnectBtn->setText("Connect");
}

void MainWindow::on_bDevice_clicked() {

  if (STM32BootLoader::singleton()) {
    STM32BootLoader::singleton()->sig.disconnect_all();
    STM32BootLoader::singleton()->disconnect();
    STM32BootLoader::singleton()->done();
  }

  ui->bDevice->clear();
  QList<QSerialPortInfo> ports = QSerialPortInfo::availablePorts();

  Q_FOREACH (QSerialPortInfo info, ports) {
    QString name = info.portName();
    ui->bDevice->addItem(name);
  }

}

void MainWindow::on_ClearBtn_clicked() {
  ui->loglist->clear();

}

void MainWindow::on_SaveBtn_clicked() {

}

void MainWindow::on_deleteBtn_clicked() {

}


void MainWindow::on_ConnectBtn_clicked(bool checked) {

  if (!operator_mutex.tryLock()) {
    return;
  }

  setConnectButtonState(false);

  if (!ui->bDevice->currentText().isEmpty() && checked) {
    if (!STM32BootLoader::singleton()) {
      STM32BootLoader::initDriver();
      STM32BootLoader::singleton()->sig.connect(this, &MainWindow::loginfo);
    }

    ui->progressbar->setMaximum(0);
    ui->progressbar->setValue(-1);
    ui->progressbar->show();
    elapsed_timer->start();
    ui->statusbar->showMessage(tr("connecting to device."));
    QCoreApplication::processEvents();

    QString port = ui->bDevice->currentText();
#ifdef Q_OS_LINUX
    port = "/dev/" + port;
#endif
    serial::bytesize_t _bytesize = (serial::bytesize_t)
                                   ui->bDatabits->currentText().toInt();
    serial::stopbits_t _stopbits = (serial::stopbits_t)
                                   ui->bStopbits->currentText().toInt();
    serial::parity_t _parity = serial::parity_even;

    switch (ui->bParity->currentIndex()) {
      case 0:
        _parity = serial::parity_even;
        break;

      case 1:
        _parity = serial::parity_odd;
        break;

      case 2:
        _parity = serial::parity_none;
        break;

      default:
        break;
    }

    serial::flowcontrol_t _flowcontrol = serial::flowcontrol_none;

    switch (ui->bFlowControl->currentIndex()) {
      case 0:
        _flowcontrol = serial::flowcontrol_none;
        break;

      case 1:
        _flowcontrol = serial::flowcontrol_software;
        break;

      case 2:
        _flowcontrol = serial::flowcontrol_hardware;
        break;

      default:
        break;
    }

    if (STM32BootLoader::singleton()->connect(port.toStdString().c_str(),
        ui->bBaudrate->currentText().toInt(), _bytesize, _parity, _stopbits,
        _flowcontrol) != STM32_ERR_OK) {
      emit logView(QString("connect to %1 failed").arg(port), CRITICAL);
      ui->ConnectBtn->setChecked(false);
    } else {
      emit logView(QString("connected to %1 successfully").arg(port), INFO);

      if (STM32BootLoader::singleton()->stm32_init(stm, init_flag) == STM32_ERR_OK) {
        fprintf(stdout, "Version      : 0x%02x\n", stm.bl_version);
        fprintf(stdout, "Option 1     : 0x%02x\n", stm.option1);
        fprintf(stdout, "Option 2     : 0x%02x\n", stm.option2);
        fprintf(stdout, "Device ID    : 0x%04x (%s)\n", stm.pid, stm.dev->name);
        fprintf(stdout, "- RAM        : %dKiB  (%db reserved by bootloader)\n",
                (stm.dev->ram_end - 0x20000000) / 1024, stm.dev->ram_start - 0x20000000);
        fprintf(stdout, "- Flash      : %dKiB (size first sector: %dx%d)\n",
                (stm.dev->fl_end - stm.dev->fl_start) / 1024, stm.dev->fl_pps,
                stm.dev->fl_ps[0]);
        fprintf(stdout, "- Option RAM : %db\n",
                stm.dev->opt_end - stm.dev->opt_start + 1);
        fprintf(stdout, "- System RAM : %dKiB\n",
                (stm.dev->mem_end - stm.dev->mem_start) / 1024);
        fflush(stdout);
        ui->lDevice->setText(QString::fromStdString(stm.dev->name));
        ui->lType->setText("MCU");
        ui->lDeviceID->setText(QString::number(stm.pid, 16).toUpper());
        QString name = QString::fromStdString(stm.dev->name);

        if (name.contains("F0")) {
          ui->lCPU->setText("Cortex-M0");
        } else if (name.contains("F1") || name.contains("F2") || name.contains("L1")) {
          ui->lCPU->setText("Cortex-M3");

        } else if (name.contains("F3") || name.contains("F4") || name.contains("F7") ||
                   name.contains("L4")) {
          ui->lCPU->setText("Cortex-M4");

        } else if (name.contains("L0")) {
          ui->lCPU->setText("Cortex-M0+");
        }

        ui->statusbar->showMessage(tr("connected."));
        ui->ConnectBtn->setText("disonnect");
        enabled(false);
        setReadWriteButtonState(true);



      } else {
        if (STM32BootLoader::singleton()) {
          STM32BootLoader::singleton()->disconnect();
          emit logView(QString("disconnected"), INFO);
        }

        ui->statusbar->showMessage(tr("disconnected."));
        enabled(true);
        ui->ConnectBtn->setChecked(false);
        setReadWriteButtonState(false);


      }

    }

    ui->progressbar->setMaximum(100);
    ui->progressbar->setValue(0);
    ui->progressbar->reset();
    elapsed_timer->stop();


  } else if (!checked) {
    if (STM32BootLoader::singleton()) {
      STM32BootLoader::singleton()->disconnect();
      emit logView(QString("disconnected"), INFO);
    }

    ui->lDevice->setText("-");
    ui->lType->setText("-");
    ui->lDeviceID->setText("-");
    ui->lCPU->setText("-");
    ui->ConnectBtn->setText("Connect");
    ui->statusbar->showMessage(tr("disconnected."));
    enabled(true);
    setReadWriteButtonState(false);
  }

  setConnectButtonState(true);
  operator_mutex.unlock();

}

void MainWindow::on_bVerfiy_toggled(bool checked) {
  verify = checked;

}

void MainWindow::on_bSkip_toggled(bool checked) {
  no_erase = checked;
}

void MainWindow::on_bRun_toggled(bool checked) {
  exec_flag = checked;
}

