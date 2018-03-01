/*
 *  STM32Programming
 *
 *  Copyright 2015 - 2020 yangfuyuan
 *  
 * 
 */


#include <QtWidgets>
#include <QCoreApplication>
#include <QFileInfo>
#include <cstdio>
#include <cstdlib>
#include <QGroupBox>
#include <iostream>
#include <sstream>

#include "mainwindow.h"
#include "elapsedtimer.h"

MainWindow* MainWindow::instance = NULL;

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent)
{
    setupUi(this);
    elapsed_timer = new ElapsedTimer();
    statusbar->addPermanentWidget(elapsed_timer);   // "addpermanent" puts it on the RHS of the statusbar
    status = STATUS_IDLE;
    progressbar->reset();

    statusbar->showMessage(tr("Waiting for a task."));

    setReadWriteButtonState(false);

    filepath->setCurrentText(QCoreApplication::applicationDirPath()+"/temp.bin");

    QList<QSerialPortInfo> ports = QSerialPortInfo::availablePorts();
    Q_FOREACH(QSerialPortInfo info, ports){
        QString name = info.portName();
        bDevice->addItem(name);
    }

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

}

MainWindow::~MainWindow()
{

    if(stm.cmd){
        free(stm.cmd);
    }

    if (elapsed_timer != NULL)
    {
        delete elapsed_timer;
        elapsed_timer = NULL;
    }

    if(STM32BootLoader::singleton()){
        STM32BootLoader::singleton()->sig.disconnect_all();
        STM32BootLoader::singleton()->disconnect();
        STM32BootLoader::singleton()->done();
    }

}



void MainWindow::setReadWriteButtonState(bool state)
{
    bWrite->setEnabled(state);
    bRead->setEnabled(state);
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (status == STATUS_READING)
    {
        if (QMessageBox::warning(this, tr("Exit?"), tr("Exiting now will result in a corrupt bin file.\n"
                                                       "Are you sure you want to exit?"),
                                 QMessageBox::Yes|QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
        {
            status = STATUS_EXIT;
        }
        event->ignore();
    }
    else if (status == STATUS_WRITING)
    {
        if (QMessageBox::warning(this, tr("Exit?"), tr("Exiting now will result in a corrupt bin.\n"
                                                       "Are you sure you want to exit?"),
                                 QMessageBox::Yes|QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
        {
            status = STATUS_EXIT;
        }
        event->ignore();
    }
    else if (status == STATUS_VERIFYING)
    {
        if (QMessageBox::warning(this, tr("Exit?"), tr("Exiting now will cancel verifying bin.\n"
                                                       "Are you sure you want to exit?"),
                                 QMessageBox::Yes|QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
        {
            status = STATUS_EXIT;
        }
        event->ignore();
    }
}

void MainWindow::on_tbBrowse_clicked()
{
    QString fileType;
    fileType.append(tr("Bin File (*.bin);;Hex File (*.hex)"));
    // create a generic FileDialog
    QFileDialog dialog(this, tr("Select a Binary File"));
    dialog.setNameFilter(fileType);
    dialog.setFileMode(QFileDialog::AnyFile);
    dialog.setViewMode(QFileDialog::Detail);
    dialog.setConfirmOverwrite(false); 
    dialog.selectFile(QCoreApplication::applicationDirPath());


    if (dialog.exec())
    {
        // selectedFiles returns a QStringList - we just want 1 filename,
        //	so use the zero'th element from that list as the filename
        QString fileLocation = (dialog.selectedFiles())[0];

        if (!fileLocation.isNull())
        {
            filepath->setCurrentText(fileLocation);
        }
    }
}


void MainWindow::on_bCancel_clicked()
{
    if ( (status == STATUS_READING) || (status == STATUS_WRITING) )
    {
        if (QMessageBox::warning(this, tr("Cancel?"), tr("Canceling now will result in a corrupt destination.\n"
                                                         "Are you sure you want to cancel?"),
                                 QMessageBox::Yes|QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
        {
            status = STATUS_CANCELED;
        }
    }
    else if (status == STATUS_VERIFYING)
    {
        if (QMessageBox::warning(this, tr("Cancel?"), tr("Cancel Verify.\n"
                                                         "Are you sure you want to cancel?"),
                                 QMessageBox::Yes|QMessageBox::No, QMessageBox::No) == QMessageBox::Yes)
        {
            status = STATUS_CANCELED;
        }

    }
}

void MainWindow::on_bWrite_clicked()
{

    m_action = ACT_WRITE;
    QString filename = filepath->currentText();
    QFileInfo f(filename);
    if(!filename.contains(".bin")&&!filename.contains(".hex") ){
        logMessage("file format is error!!", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
        return;

    }else if(filename.isEmpty()){
        logMessage("file is empty, please select file!!", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
        return;
    }else if(!f.exists()){
        logMessage("file is not exist!!", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
        return;
    }
    if(!StartAddress->currentText().contains("0x")){
        logMessage("start address format error!!", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
        return;
    }
    setReadWriteButtonState(false);
    bool ok;
    start_addr = StartAddress->currentText().toInt(&ok,16);
    readwrite_len = f.size();
    status = STATUS_WRITING;
    progressbar->reset();
    progressbar->setMaximum(100);
    elapsed_timer->start();

    bootloader();
    if (status == STATUS_EXIT)
    {
        close();
    }
    status = STATUS_IDLE;
    elapsed_timer->stop();
    setReadWriteButtonState(true);

}

void MainWindow::on_bRead_clicked()
{
    m_action = ACT_READ;

    QString filename = filepath->currentText();
    if(!filename.contains(".bin")){
        logMessage("file format is error!!", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
        return;

    }else if(filename.isEmpty()){
        logMessage("file is empty, please select file!!", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
        return;
    }

    if(!StartAddress->currentText().contains("0x")){
        logMessage("start address format error!!", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
        return;
    }
    setReadWriteButtonState(false);

    bool ok;
    start_addr = StartAddress->currentText().toInt(&ok,16);
    if(leSize->text().contains("0x")){
        readwrite_len =  leSize->text().toInt(&ok,16);
    }else{
        readwrite_len =  leSize->text().toInt();

    }
    status = STATUS_READING;
    progressbar->reset();
    progressbar->setMaximum(100);
    elapsed_timer->start();
    bootloader();
    if (status == STATUS_EXIT)
    {
        close();
    }
    status = STATUS_IDLE;
    elapsed_timer->stop();
    setReadWriteButtonState(true);



}

void MainWindow::bootloader(){


    QString filename = filepath->currentText();
    if(filename.isEmpty()){
        logMessage("file is empty, please select file!!", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
        return;
    }

    binary_t *p_st		= NULL;
    hex_t *h_st         =NULL;
    parser_err_t perr;
    bool is_hex =false;

    if(m_action == ACT_WRITE){
        if (filename.contains(".hex")) {
            is_hex = true;

            h_st = hex_init();
            if (!h_st) {
                fprintf(stderr, "Raw HEX ERROR Parser failed to initialize\n");
                logMessage("Raw HEX ERROR Parser failed to initialize", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
                return;
            }
            perr = hex_open(h_st, filename.toStdString().c_str(), 0);

            /* if still have an error, fail */
            if (perr != PARSER_ERR_OK) {
                fprintf(stderr, "Raw BINARY ERROR: %s\n", parser_errstr(perr));
                fflush(stderr);
                logMessage(tr("Raw BINARY ERROR: %1").arg(QString::fromStdString(parser_errstr(perr))), QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
                if (perr == PARSER_ERR_SYSTEM) perror(filename.toStdString().c_str());

                hex_close(h_st);
                h_st = NULL;
                return;
            }

            fprintf(stdout, "Using Parser : Raw BINARY\n");
        }

    }


    if(!is_hex){
        /* now try binary */
        p_st = binary_init();
        if (!p_st) {
            logMessage("Raw BINARY ERROR Parser failed to initialize", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
            return;
        }
        perr = binary_open(p_st, filename.toStdString().c_str(), m_action==ACT_WRITE?0:1);

        /* if still have an error, fail */
        if (perr != PARSER_ERR_OK) {
            fprintf(stderr, "Raw BINARY ERROR: %s\n", parser_errstr(perr));
            fflush(stderr);
            logMessage(tr("Raw BINARY ERROR: %1").arg(QString::fromStdString(parser_errstr(perr))), QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
                        if (perr == PARSER_ERR_SYSTEM) perror(filename.toStdString().c_str());

            binary_close(p_st);
            p_st = NULL;
            return;
        }

        fprintf(stderr, "Using Parser : Raw BINARY\n");
    }

    logMessage("Using Parser : Raw BINARY", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);


    uint8_t		buffer[256];
    uint32_t	addr, start, end;
    unsigned int	len;
    int		failed = 0;
    int		first_page, num_pages;
    int ret = 1;

    stm32_err_t s_err;
    /*
     * Cleanup addresses:
     *
     * Starting from options
     *	start_addr, readwrite_len, spage, npages
     * and using device memory size, compute
     *	start, end, first_page, num_pages
     */
    if (start_addr || readwrite_len) {
        start = start_addr;

        if (is_addr_in_flash(stm,start))
            end = stm.dev->fl_end;
        else {
            no_erase = 1;
            if (is_addr_in_ram(stm,start))
                end = stm.dev->ram_end;
            else
                end = start + sizeof(uint32_t);
        }

        if (readwrite_len && (end > start + readwrite_len))
            end = start + readwrite_len;

        first_page = flash_addr_to_page_floor(stm,start);
        if (!first_page && end == stm.dev->fl_end)
            num_pages = STM32_MASS_ERASE;
        else
            num_pages = flash_addr_to_page_ceil(stm,end) - first_page;
    } else if (!spage && !npages) {
        start = stm.dev->fl_start;
        end = stm.dev->fl_end;
        first_page = 0;
        num_pages = STM32_MASS_ERASE;
    } else {
        first_page = spage;
        start = flash_page_to_addr(stm,first_page);
        if (start > stm.dev->fl_end) {
            fprintf(stderr, "Address range exceeds flash size.\n");
            logMessage("Address range exceeds flash size.", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),WARNING);
            if(p_st){
                binary_close(p_st);
                p_st = NULL;
            }

            if(h_st){
                hex_close(h_st);
                h_st = NULL;

            }

            return;
        }

        if (npages) {
            num_pages = npages;
            end = flash_page_to_addr(stm,first_page + num_pages);
            if (end > stm.dev->fl_end)
                end = stm.dev->fl_end;
        } else {
            end = stm.dev->fl_end;
            num_pages = flash_addr_to_page_ceil(stm,end) - first_page;
        }

        if (!first_page && end == stm.dev->fl_end)
            num_pages = STM32_MASS_ERASE;
    }



    switch (m_action) {
    case ACT_NONE:

        break;
    case ACT_READ:{
        unsigned int max_len = STM32_MAX_RX_FRAME;

        fprintf(stdout, "Memory read\n");
        logMessage("Memory read.", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);

        fflush(stdout);
        addr = start;
        while(addr < end) {
            uint32_t left	= end - addr;
            len		= max_len > left ? left : max_len;
            s_err = STM32BootLoader::singleton()->stm32_read_memory(stm, addr, buffer, len);
            if (s_err != STM32_ERR_OK) {
                logMessage(tr("Failed to read memory at address 0x%1, target write-protected?").arg(QString::number(addr,16)), QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);

                fprintf(stderr, "Failed to read memory at address 0x%08x, target write-protected?\n", addr);
                fflush(stderr);
                if(p_st){
                    binary_close(p_st);
                    p_st = NULL;
                }
               return;
            }


            if (binary_write(p_st, buffer, len) != PARSER_ERR_OK)
            {
                logMessage("Raw BINARY ERROR Failed to write data to file", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
                fprintf(stderr, "Failed to write data to file\n");
                if(p_st){
                    binary_close(p_st);
                    p_st = NULL;
                }
                return;
            }
            addr += len;

            progressbar->setValue((100.0f / (float)(end - start)) * (float)(addr - start));
            elapsed_timer->update((100.0f / (float)(end - start)) * (float)(addr - start),100);
            logMessage(tr("Read address 0x%1 (%2%)").arg(QString::number(addr,16)).arg((100.0f / (float)(end - start)) * (float)(addr - start)), QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);
            QCoreApplication::processEvents();//避免界面冻结
            fprintf(stdout,
                "\rRead address 0x%08x (%.2f%%) ",
                addr,
                (100.0f / (float)(end - start)) * (float)(addr - start)
            );
            fflush(stdout);
        }
        ret = 0;
        fprintf(stdout,	"Done.\n");
        logMessage("read memory Done", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);



    }
        break;
    case ACT_WRITE:{
        fprintf(stdout, "Write to memory\n");
        logMessage("Write to memory", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);


        off_t 	offset = 0;
        ssize_t r;
        unsigned int size;
        unsigned int max_wlen, max_rlen;
        max_wlen = STM32_MAX_TX_FRAME - 2;	/* skip len and crc */
        max_wlen &= ~3;	/* 32 bit aligned */


        max_rlen = STM32_MAX_RX_FRAME;
        max_rlen = max_rlen < max_wlen ? max_rlen : max_wlen;

                /* Assume data from stdin is whole device */
        if (filename.toStdString().c_str()[0] == '-' && filename.toStdString().c_str()[1] == '\0')
            size = end - start;
        else{
            if(p_st)
                size = binary_size(p_st);
            else if(h_st)
                size = hex_size(h_st);
        }

                // TODO: It is possible to write to non-page boundaries, by reading out flash
                //       from partial pages and combining with the input data
                // if ((start % stm->dev->fl_ps[i]) != 0 || (end % stm->dev->fl_ps[i]) != 0) {
                //	fprintf(stderr, "Specified start & length are invalid (must be page aligned)\n");
                //	goto close;
                // }

                // TODO: If writes are not page aligned, we should probably read out existing flash
                //       contents first, so it can be preserved and combined with new data

        if (!no_erase && num_pages) {
            fprintf(stdout, "Erasing memory\n");
            s_err = STM32BootLoader::singleton()->stm32_erase_memory(stm, first_page, num_pages);
            if (s_err != STM32_ERR_OK) {
                logMessage("Failed to erase memory", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);

                fprintf(stderr, "Failed to erase memory\n");
                fflush(stderr);
                return;
            }

        }


        fflush(stdout);
        addr = start;

        while(addr < end && offset < size) {

            uint32_t left	= end - addr;
            len		= max_wlen > left ? left : max_wlen;
            len		= len > size - offset ? size - offset : len;

            if (p_st && binary_read(p_st, buffer, &len) != PARSER_ERR_OK){
                logMessage("Failed to read file buffer", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);

                if(p_st){
                    binary_close(p_st);
                    p_st = NULL;
                }

                return;
            }

            if (h_st && hex_read(h_st, buffer, &len) != PARSER_ERR_OK){
                logMessage("Failed to read file buffer", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
                if(h_st){
                    hex_close(h_st);
                    h_st = NULL;

                }

               return;
            }


            if (len == 0) {
                if (filename.toStdString().c_str()[0] == '-') {
                    return;
                } else {
                    logMessage("Raw BINARY ERROR Failed to read input file", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);

                    fprintf(stderr, "Failed to read input file\n");
                    fflush(stderr);


                    if(p_st){
                        binary_close(p_st);
                        p_st = NULL;
                    }

                    if(h_st){
                        hex_close(h_st);
                        h_st = NULL;

                    }

                    return;

                }
            }

            again:
            s_err = STM32BootLoader::singleton()->stm32_write_memory(stm, addr, buffer, len);
            if (s_err != STM32_ERR_OK) {
                logMessage(tr("Failed to write memory at address 0x%1").arg(QString::number(addr,16)), QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);

                fprintf(stderr, "Failed to write memory at address 0x%08x\n", addr);
                fflush(stderr);
                if(p_st){
                    binary_close(p_st);
                    p_st = NULL;
                }

                if(h_st){
                    hex_close(h_st);
                    h_st = NULL;

                }
                return;

            }
            if (verify) {
                uint8_t compare[len];
                unsigned int offset, rlen;

                offset = 0;
                while (offset < len) {
                    rlen = len - offset;
                    rlen = rlen < max_rlen ? rlen : max_rlen;
                    s_err = STM32BootLoader::singleton()->stm32_read_memory(stm, addr + offset, compare + offset, rlen);
                    if (s_err != STM32_ERR_OK) {
                        fprintf(stderr, "Failed to read memory at address 0x%08x\n", addr + offset);
                        logMessage(tr("Failed to write memory at address 0x%1").arg(QString::number(addr + offset,16)), QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
                        return;
                    }
                    offset += rlen;
                    QCoreApplication::processEvents();//避免界面冻结

                }


                for(r = 0; r < len; ++r){
                    if (buffer[r] != compare[r]) {
                        if (failed == retry) {
                            logMessage(tr("Failed to verify at address 0x%1, expected 0x%2 and found 0x%3").arg(QString::number((uint32_t)(addr + r),16)).arg(QString::number(buffer[r])).arg(QString::number(compare[r])), QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
                            fprintf(stderr, "Failed to verify at address 0x%08x, expected 0x%02x and found 0x%02x\n",(uint32_t)(addr + r),buffer[r],compare[r]);
                            fflush(stderr);
                            return;
                        }
                        ++failed;
                        goto again;

                    }
                }
                failed = 0;
            }


            addr	+= len;
            offset	+= len;
            progressbar->setValue((100.0f / size) * offset);
            elapsed_timer->update((100.0f / size) * offset,100);
            logMessage(tr("Wrote %1address 0x%2 (%3%)").arg(verify ? "and verified " : "").arg(QString::number(addr,16)).arg((100.0f / size) * offset), QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);
            QCoreApplication::processEvents();//避免界面冻结
            fprintf(stdout,
                        "\rWrote %saddress 0x%08x (%.2f%%) ",
                        verify ? "and verified " : "",
                        addr,
                        (100.0f / size) * offset
                    );
            fflush(stdout);
        }

        fprintf(stdout,	"Done.\n");
        ret = 0;
        logMessage("Write Memery Done", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);

    }
        break;

    case ACT_WRITE_UNPROTECT:{

        fprintf(stdout, "Write-unprotecting flash\n");
        logMessage("Write-unprotecting flash", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);
        /* the device automatically performs a reset after the sending the ACK */
        reset_flag = 0;
        STM32BootLoader::singleton()->stm32_wunprot_memory(stm);
        fprintf(stdout,	"Done.\n");
        logMessage("Write-unprotecting Done", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);

        ret = 0;


    }
        break;
    case ACT_READ_PROTECT:{
        fprintf(stdout, "Read-Protecting flash\n");
        logMessage("Read-Protecting flash", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);

        /* the device automatically performs a reset after the sending the ACK */
        reset_flag = 0;
        STM32BootLoader::singleton()->stm32_readprot_memory(stm);
        fprintf(stdout,	"Done.\n");
        logMessage("Read-Protecting Done", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);



    }
        break;
    case ACT_READ_UNPROTECT:{
        fprintf(stdout, "Read-UnProtecting flash\n");
        logMessage("Read-UnProtecting flash", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);

        /* the device automatically performs a reset after the sending the ACK */
        reset_flag = 0;
        STM32BootLoader::singleton()->stm32_runprot_memory(stm);
        fprintf(stdout,	"Done.\n");
        logMessage("Read-UnProtecting Done", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);



    }
        break;
    case ACT_ERASE_ONLY:{
        fprintf(stdout, "Erasing flash\n");
        logMessage("Erasing flash", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);

        if (num_pages != STM32_MASS_ERASE &&(start != flash_page_to_addr(stm,first_page)|| end != flash_page_to_addr(stm,first_page + num_pages))) {
            fprintf(stderr, "Specified start & length are invalid (must be page aligned)\n");
            logMessage("Specified start & length are invalid (must be page aligned)", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
            break;

        }


        s_err = STM32BootLoader::singleton()->stm32_erase_memory(stm, first_page, num_pages);
        if (s_err != STM32_ERR_OK) {
            fprintf(stderr, "Failed to erase memory\n");
            logMessage("Failed to erase memory", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
            break;
        }
        ret = 0;


    }
        break;
    case ACT_CRC:{
        uint32_t crc_val = 0;
        fprintf(stdout, "CRC computation\n");
        logMessage("CRC computation", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);

        s_err = STM32BootLoader::singleton()->stm32_crc_wrapper(stm, start, end - start, &crc_val);
        if (s_err != STM32_ERR_OK) {
            logMessage("Failed to read CRC", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);

            fprintf(stderr, "Failed to read CRC\n");
            fflush(stderr);
            break;
        }
        ret = 0;

        fprintf(stdout, "CRC(0x%08x-0x%08x) = 0x%08x\n", start, end,crc_val);
        logMessage(tr("CRC(0x%1-0x%2) = 0x%3").arg(QString::number(start,16)).arg(QString::number(end,16)).arg(QString::number(crc_val,16)), QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);


    }
        break;
    default:
        break;
    }



    if ( exec_flag && ret == 0) {
        if (execute == 0)
            execute = stm.dev->fl_start;

        logMessage(tr("Starting execution at address 0x%1...").arg(QString::number(execute,16)), QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);
        fprintf(stdout, "\nStarting execution at address 0x%08x... ", execute);
        fflush(stdout);
        if (STM32BootLoader::singleton()->stm32_go(stm, execute) == STM32_ERR_OK) {
            reset_flag = 0;
            fprintf(stdout, "starting execution done.\n");
            logMessage("starting execution Done", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);
            QCoreApplication::processEvents();
            QThread::sleep(1);
            if(STM32BootLoader::singleton()){
                STM32BootLoader::singleton()->disconnect();
                logMessage(QString("disconnected"),QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);
            }
            statusbar->showMessage(tr("disconnected."));
            enabled(true);
            ConnectBtn->setChecked(false);
            setReadWriteButtonState(false);
            lDevice->setText("-");
            lType->setText("-");
            lDeviceID->setText("-");
            lCPU->setText("-");
            ConnectBtn->setText("Connect");
        } else{
            fprintf(stdout, "starting execution failed.\n");
            logMessage("starting execution failed", QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
        }
        fflush(stdout);
    }

    if(p_st){
        binary_close(p_st);
        p_st = NULL;
    }
    if(h_st){
        hex_close(h_st);
        h_st = NULL;

    }



}


void MainWindow::enabled(bool enable){
    bDevice->setEnabled(enable);
    UpdateBtn->setEnabled(enable);
    bBaudrate->setEnabled(enable);
    bDatabits->setEnabled(enable);
    bStopbits->setEnabled(enable);
    bParity->setEnabled(enable);
    bFlowControl->setEnabled(enable);
}

void MainWindow::logMessage(QString str, QString tag, MessageLevel level){
    if(level_1->isChecked()){

        QString flag;
        if(level == INFO){
            flag = "INFO";
        }else if(level == WARNING){
            flag = "WARNING";

        }else if(level == CRITICAL){
            flag = "ERROR";

        }
        QListWidgetItem * item = new QListWidgetItem (tr("%1[%2]:%23").arg(tag).arg(flag).arg(str));

        loglist->addItem(item);
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
    }else if(level_2->isChecked()){
        if(level == WARNING){
            QListWidgetItem * item = new QListWidgetItem (tr("%1[WARNING]:%2").arg(tag).arg(str));
            loglist->addItem(item);
            item->setBackgroundColor(Qt::yellow);
        }

    }else if(level_3->isChecked()){
        if(level == CRITICAL){
            QListWidgetItem * item = new QListWidgetItem (tr("%1[ERROR]:%2").arg(tag).arg(str));
            loglist->addItem(item);
            item->setBackgroundColor(Qt::red);
        }

    }

    loglist->setCurrentRow(loglist->count() -1);
}

void MainWindow::loginfo(string info, int level)
{
    logMessage(QString::fromStdString(info),QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),(MessageLevel)level);
}

void MainWindow::on_UpdateBtn_clicked()
{
    bDevice->clear();
    QList<QSerialPortInfo> ports = QSerialPortInfo::availablePorts();
    Q_FOREACH(QSerialPortInfo info, ports){
        QString name = info.portName();
        bDevice->addItem(name);
    }

}

void MainWindow::on_ClearBtn_clicked()
{
    loglist->clear();

}

void MainWindow::on_SaveBtn_clicked()
{

}

void MainWindow::on_deleteBtn_clicked()
{

}


void MainWindow::on_ConnectBtn_clicked(bool checked)
{
    if(!bDevice->currentText().isEmpty()&&checked){
        if(!STM32BootLoader::singleton()){
            STM32BootLoader::initDriver();
            STM32BootLoader::singleton()->sig.connect(this, &MainWindow::loginfo);
        }
        progressbar->setMaximum(0);
        progressbar->setValue(-1);
        progressbar->show();
        elapsed_timer->start();
        statusbar->showMessage(tr("connecting to device."));
        QCoreApplication::processEvents();

        QString port = bDevice->currentText();
#ifdef Q_OS_LINUX
        port = "/dev/"+port;
#endif
        serial::bytesize_t _bytesize = (serial::bytesize_t)bDatabits->currentText().toInt();
        serial::stopbits_t _stopbits = (serial::stopbits_t)bStopbits->currentText().toInt();
        serial::parity_t _parity = serial::parity_even;
        switch (bParity->currentIndex()) {
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
        switch (bFlowControl->currentIndex()) {
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

        if(STM32BootLoader::singleton()->connect(port.toStdString().c_str(), bBaudrate->currentText().toInt(),_bytesize,_parity, _stopbits,_flowcontrol ) != STM32_ERR_OK){
            logMessage(QString("connect to %1 failed").arg(port),QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),CRITICAL);
            ConnectBtn->setChecked(false);
        }else{
            logMessage(QString("connected to %1 successfully").arg(port),QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);

            if(STM32BootLoader::singleton()->stm32_init(stm, init_flag) == STM32_ERR_OK){
                fprintf(stdout, "Version      : 0x%02x\n", stm.bl_version);
                fprintf(stdout, "Option 1     : 0x%02x\n", stm.option1);
                fprintf(stdout, "Option 2     : 0x%02x\n", stm.option2);
                fprintf(stdout, "Device ID    : 0x%04x (%s)\n", stm.pid, stm.dev->name);
                fprintf(stdout, "- RAM        : %dKiB  (%db reserved by bootloader)\n", (stm.dev->ram_end - 0x20000000) / 1024, stm.dev->ram_start - 0x20000000);
                fprintf(stdout, "- Flash      : %dKiB (size first sector: %dx%d)\n", (stm.dev->fl_end - stm.dev->fl_start ) / 1024, stm.dev->fl_pps, stm.dev->fl_ps[0]);
                fprintf(stdout, "- Option RAM : %db\n", stm.dev->opt_end - stm.dev->opt_start + 1);
                fprintf(stdout, "- System RAM : %dKiB\n", (stm.dev->mem_end - stm.dev->mem_start) / 1024);
                fflush(stdout);
                lDevice->setText(QString::fromStdString(stm.dev->name));
                lType->setText("MCU");
                lDeviceID->setText(QString::number(stm.pid, 16).toUpper());
                QString name = QString::fromStdString(stm.dev->name);

                if(name.contains("F0")){
                    lCPU->setText("Cortex-M0");
                }else if(name.contains("F1")|| name.contains("F2")||name.contains("L1")){
                    lCPU->setText("Cortex-M3");

                }else if(name.contains("F3")|| name.contains("F4")||name.contains("F7")||name.contains("L4")){
                    lCPU->setText("Cortex-M4");

                }else if(name.contains("L0")){
                    lCPU->setText("Cortex-M0+");
                }
                statusbar->showMessage(tr("connected."));
                ConnectBtn->setText("disonnect");
                enabled(false);
                setReadWriteButtonState(true);



            }else{
                if(STM32BootLoader::singleton()){
                    STM32BootLoader::singleton()->disconnect();
                    logMessage(QString("disconnected"),QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);
                }
                statusbar->showMessage(tr("disconnected."));
                enabled(true);
                ConnectBtn->setChecked(false);
                setReadWriteButtonState(false);


            }

        }

        progressbar->setMaximum(100);
        progressbar->setValue(0);
        progressbar->reset();
        elapsed_timer->stop();


    }else if(!checked){
        if(STM32BootLoader::singleton()){
            STM32BootLoader::singleton()->disconnect();
            logMessage(QString("disconnected"),QDateTime::currentDateTime().toString("yyyy-MM-dd hh:mm:ss"),INFO);
        }

        lDevice->setText("-");
        lType->setText("-");
        lDeviceID->setText("-");
        lCPU->setText("-");
        ConnectBtn->setText("Connect");
        statusbar->showMessage(tr("disconnected."));
        enabled(true);
        setReadWriteButtonState(false);
    }

}

void MainWindow::on_bVerfiy_toggled(bool checked)
{
    verify = checked;

}

void MainWindow::on_bSkip_toggled(bool checked)
{
    no_erase = checked;
}

void MainWindow::on_bRun_toggled(bool checked)
{
    exec_flag = checked;
}

