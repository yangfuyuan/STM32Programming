/*
 *  STM32Programming
 *
 *  Copyright 2015 - 2020 yangfuyuan
 *
 *
 */
#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFileInfo>
#include <QGroupBox>

//simple wait routine
void MainWindow::wait_ms(unsigned long time)
{
    QWaitCondition wc;
    QMutex mutex;
    QMutexLocker locker(&mutex);
    wc.wait(&mutex, time);
}


void MainWindow::userOperator(const QString &filename)
{
    ui->progressbar->reset();
    ui->progressbar->setMaximum(100);
    elapsed_timer->start();
    bootloader(filename);
    m_state = IDLE;
    elapsed_timer->stop();
    setReadWriteButtonState(true);
}

void MainWindow::bootloader(const QString &filename)
{

    if (filename.isEmpty())
    {
        emit logView("file is empty, please select file!!", CRITICAL);
        return;
    }

    binary_t *p_st		= NULL;
    hex_t *h_st         = NULL;
    parser_err_t perr;
    bool is_hex = false;

    if (m_action == ACT_WRITE)
    {
        if (filename.contains(".hex"))
        {
            is_hex = true;

            h_st = hex_init();

            if (!h_st)
            {
                fprintf(stderr, "Raw HEX ERROR Parser failed to initialize\n");
                emit logView("Raw HEX ERROR Parser failed to initialize", CRITICAL);
                return;
            }

            perr = hex_open(h_st, filename.toStdString().c_str(), 0);

            /* if still have an error, fail */
            if (perr != PARSER_ERR_OK)
            {
                fprintf(stderr, "Raw BINARY ERROR: %s\n", parser_errstr(perr));
                fflush(stderr);
                emit logView(tr("Raw BINARY ERROR: %1").arg(QString::fromStdString(
                                 parser_errstr(perr))), CRITICAL);

                if (perr == PARSER_ERR_SYSTEM)
                {
                    perror(filename.toStdString().c_str());
                }

                hex_close(h_st);
                h_st = NULL;
                return;
            }

            fprintf(stdout, "Using Parser : Raw BINARY\n");
        }

    }


    if (!is_hex)
    {
        /* now try binary */
        p_st = binary_init();

        if (!p_st)
        {
            emit logView("Raw BINARY ERROR Parser failed to initialize", CRITICAL);
            return;
        }

        perr = binary_open(p_st, filename.toStdString().c_str(),
                           m_action == ACT_WRITE ? 0 : 1);

        /* if still have an error, fail */
        if (perr != PARSER_ERR_OK)
        {
            fprintf(stderr, "Raw BINARY ERROR: %s\n", parser_errstr(perr));
            fflush(stderr);
            emit logView(tr("Raw BINARY ERROR: %1").arg(QString::fromStdString(
                             parser_errstr(
                                 perr))), CRITICAL);

            if (perr == PARSER_ERR_SYSTEM)
            {
                perror(filename.toStdString().c_str());
            }

            binary_close(p_st);
            p_st = NULL;
            return;
        }

        fprintf(stdout, "Using Parser : Raw BINARY\n");
    }

    emit logView("Using Parser : Raw BINARY", INFO);


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
    if (start_addr || readwrite_len)
    {
        start = start_addr;

        if (is_addr_in_flash(stm, start))
        {
            end = stm.dev->fl_end;
        }
        else
        {
            no_erase = 1;

            if (is_addr_in_ram(stm, start))
            {
                end = stm.dev->ram_end;
            }
            else
            {
                end = start + sizeof(uint32_t);
            }
        }

        if (readwrite_len && (end > start + readwrite_len))
        {
            end = start + readwrite_len;
        }

        first_page = flash_addr_to_page_floor(stm, start);

        if (!first_page && end == stm.dev->fl_end)
        {
            num_pages = STM32_MASS_ERASE;
        }
        else
        {
            num_pages = flash_addr_to_page_ceil(stm, end) - first_page;
        }
    }
    else if (!spage && !npages)
    {
        start = stm.dev->fl_start;
        end = stm.dev->fl_end;
        first_page = 0;
        num_pages = STM32_MASS_ERASE;
    }
    else
    {
        first_page = spage;
        start = flash_page_to_addr(stm, first_page);

        if (start > stm.dev->fl_end)
        {
            fprintf(stderr, "Address range exceeds flash size.\n");
            emit logView("Address range exceeds flash size.", WARNING);

            if (p_st)
            {
                binary_close(p_st);
                p_st = NULL;
            }

            if (h_st)
            {
                hex_close(h_st);
                h_st = NULL;

            }

            return;
        }

        if (npages)
        {
            num_pages = npages;
            end = flash_page_to_addr(stm, first_page + num_pages);

            if (end > stm.dev->fl_end)
            {
                end = stm.dev->fl_end;
            }
        }
        else
        {
            end = stm.dev->fl_end;
            num_pages = flash_addr_to_page_ceil(stm, end) - first_page;
        }

        if (!first_page && end == stm.dev->fl_end)
        {
            num_pages = STM32_MASS_ERASE;
        }
    }



    switch (m_action)
    {
    case ACT_NONE:

        break;

    case ACT_READ:
    {
        unsigned int max_len = STM32_MAX_RX_FRAME;

        fprintf(stdout, "Memory read\n");
        emit logView("Memory read.", INFO);

        fflush(stdout);
        addr = start;

        while (addr < end)
        {
            uint32_t left	= end - addr;
            len		= max_len > left ? left : max_len;
            s_err = STM32BootLoader::singleton()->stm32_read_memory(stm, addr, buffer, len);

            if (s_err != STM32_ERR_OK)
            {
                emit logView(
                    tr("Failed to read memory at address 0x%1, target write-protected?").arg(
                        QString::number(addr, 16)), CRITICAL);

                fprintf(stderr,
                        "Failed to read memory at address 0x%08x, target write-protected?\n", addr);
                fflush(stderr);

                if (p_st)
                {
                    binary_close(p_st);
                    p_st = NULL;
                }

                return;
            }


            if (binary_write(p_st, buffer, len) != PARSER_ERR_OK)
            {
                emit logView("Raw BINARY ERROR Failed to write data to file", CRITICAL);
                fprintf(stderr, "Failed to write data to file\n");

                if (p_st)
                {
                    binary_close(p_st);
                    p_st = NULL;
                }

                m_state = IDLE;
                return;
            }

            addr += len;

            emit dataProcessSlot((100.0f / (float)(end - start)) * (float)(
                                     addr - start), 100);
            emit logView(tr("Read address 0x%1 (%2%)").arg(QString::number(addr,
                         16)).arg((100.0f / (float)(end - start)) * (float)(addr - start)), INFO);
            fprintf(stdout,
                    "\rRead address 0x%08x (%.2f%%) ",
                    addr,
                    (100.0f / (float)(end - start)) * (float)(addr - start)
                   );
            fflush(stdout);
        }

        ret = 0;
        fprintf(stdout,	"Done.\n");
        emit logView("read memory Done", INFO);



    }
    break;

    case ACT_WRITE:
    {
        fprintf(stdout, "Write to memory\n");
        emit logView("Write to memory", INFO);


        off_t 	offset = 0;
        ssize_t r;
        unsigned int size;
        unsigned int max_wlen, max_rlen;
        max_wlen = STM32_MAX_TX_FRAME - 2;	/* skip len and crc */
        max_wlen &= ~3;	/* 32 bit aligned */


        max_rlen = STM32_MAX_RX_FRAME;
        max_rlen = max_rlen < max_wlen ? max_rlen : max_wlen;

        /* Assume data from stdin is whole device */
        if (filename.toStdString().c_str()[0] == '-' &&
                filename.toStdString().c_str()[1] == '\0')
        {
            size = end - start;
        }
        else
        {
            if (p_st)
            {
                size = binary_size(p_st);
            }
            else if (h_st)
            {
                size = hex_size(h_st);
            }
        }

        // TODO: It is possible to write to non-page boundaries, by reading out flash
        //       from partial pages and combining with the input data
        // if ((start % stm->dev->fl_ps[i]) != 0 || (end % stm->dev->fl_ps[i]) != 0) {
        //	fprintf(stderr, "Specified start & length are invalid (must be page aligned)\n");
        //	goto close;
        // }

        // TODO: If writes are not page aligned, we should probably read out existing flash
        //       contents first, so it can be preserved and combined with new data

        if (!no_erase && num_pages)
        {
            fprintf(stdout, "Erasing memory\n");
            s_err = STM32BootLoader::singleton()->stm32_erase_memory(stm, first_page,
                    num_pages);

            if (s_err != STM32_ERR_OK)
            {
                emit logView("Failed to erase memory", CRITICAL);

                fprintf(stderr, "Failed to erase memory\n");
                fflush(stderr);
                m_state = IDLE;
                return;
            }

        }


        fflush(stdout);
        addr = start;

        while (addr < end && offset < size)
        {

            uint32_t left	= end - addr;
            len		= max_wlen > left ? left : max_wlen;
            len		= len > size - offset ? size - offset : len;

            if (p_st && binary_read(p_st, buffer, &len) != PARSER_ERR_OK)
            {
                emit logView("Failed to read file buffer", CRITICAL);

                if (p_st)
                {
                    binary_close(p_st);
                    p_st = NULL;
                }

                m_state = IDLE;
                return;
            }

            if (h_st && hex_read(h_st, buffer, &len) != PARSER_ERR_OK)
            {
                emit logView("Failed to read file buffer", CRITICAL);

                if (h_st)
                {
                    hex_close(h_st);
                    h_st = NULL;

                }

                m_state = IDLE;
                return;
            }


            if (len == 0)
            {
                if (filename.toStdString().c_str()[0] == '-')
                {
                    return;
                }
                else
                {
                    emit logView("Raw BINARY ERROR Failed to read input file", CRITICAL);

                    fprintf(stderr, "Failed to read input file\n");
                    fflush(stderr);


                    if (p_st)
                    {
                        binary_close(p_st);
                        p_st = NULL;
                    }

                    if (h_st)
                    {
                        hex_close(h_st);
                        h_st = NULL;

                    }

                    m_state = IDLE;
                    return;

                }
            }

again:
            s_err = STM32BootLoader::singleton()->stm32_write_memory(stm, addr, buffer,
                    len);

            if (s_err != STM32_ERR_OK)
            {
                emit logView(tr("Failed to write memory at address 0x%1").arg(QString::number(
                                 addr, 16)), CRITICAL);

                fprintf(stderr, "Failed to write memory at address 0x%08x\n", addr);
                fflush(stderr);

                if (p_st)
                {
                    binary_close(p_st);
                    p_st = NULL;
                }

                if (h_st)
                {
                    hex_close(h_st);
                    h_st = NULL;

                }

                m_state = IDLE;
                return;

            }

            if (verify)
            {
                uint8_t compare[len];
                unsigned int offset, rlen;

                offset = 0;

                while (offset < len)
                {
                    rlen = len - offset;
                    rlen = rlen < max_rlen ? rlen : max_rlen;
                    s_err = STM32BootLoader::singleton()->stm32_read_memory(stm, addr + offset,
                            compare + offset, rlen);

                    if (s_err != STM32_ERR_OK)
                    {
                        fprintf(stderr, "Failed to read memory at address 0x%08x\n", addr + offset);
                        emit logView(tr("Failed to write memory at address 0x%1").arg(QString::number(
                                         addr + offset, 16)), CRITICAL);
                        m_state = IDLE;
                        return;
                    }

                    offset += rlen;
                }


                for (r = 0; r < len; ++r)
                {
                    if (buffer[r] != compare[r])
                    {
                        if (failed == retry)
                        {
                            emit logView(
                                tr("Failed to verify at address 0x%1, expected 0x%2 and found 0x%3").arg(
                                    QString::number((uint32_t)(addr + r),
                                                    16)).arg(QString::number(buffer[r])).arg(QString::number(compare[r])),
                                CRITICAL);
                            fprintf(stderr,
                                    "Failed to verify at address 0x%08x, expected 0x%02x and found 0x%02x\n",
                                    (uint32_t)(addr + r), buffer[r], compare[r]);
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
            emit dataProcessSignal((100.0f / size) * offset, 100);
            emit logView(tr("Wrote %1address 0x%2 (%3%)").arg(verify ? "and verified " :
                         "").arg(QString::number(addr, 16)).arg((100.0f / size) * offset), INFO);
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
        emit logView("Write Memery Done", INFO);

    }
    break;

    case ACT_WRITE_UNPROTECT:
    {

        fprintf(stdout, "Write-unprotecting flash\n");
        emit logView("Write-unprotecting flash", INFO);
        /* the device automatically performs a reset after the sending the ACK */
        reset_flag = 0;
        STM32BootLoader::singleton()->stm32_wunprot_memory(stm);
        fprintf(stdout,	"Done.\n");
        emit logView("Write-unprotecting Done", INFO);

        ret = 0;


    }
    break;

    case ACT_READ_PROTECT:
    {
        fprintf(stdout, "Read-Protecting flash\n");
        emit logView("Read-Protecting flash", INFO);

        /* the device automatically performs a reset after the sending the ACK */
        reset_flag = 0;
        STM32BootLoader::singleton()->stm32_readprot_memory(stm);
        fprintf(stdout,	"Done.\n");
        emit logView("Read-Protecting Done", INFO);



    }
    break;

    case ACT_READ_UNPROTECT:
    {
        fprintf(stdout, "Read-UnProtecting flash\n");
        emit logView("Read-UnProtecting flash", INFO);

        /* the device automatically performs a reset after the sending the ACK */
        reset_flag = 0;
        STM32BootLoader::singleton()->stm32_runprot_memory(stm);
        fprintf(stdout,	"Done.\n");
        emit logView("Read-UnProtecting Done", INFO);



    }
    break;

    case ACT_ERASE_ONLY:
    {
        fprintf(stdout, "Erasing flash\n");
        emit logView("Erasing flash", INFO);

        if (num_pages != STM32_MASS_ERASE &&
                (start != flash_page_to_addr(stm, first_page) ||
                 end != flash_page_to_addr(stm, first_page + num_pages)))
        {
            fprintf(stderr,
                    "Specified start & length are invalid (must be page aligned)\n");
            emit logView("Specified start & length are invalid (must be page aligned)",
                         CRITICAL);
            break;

        }


        s_err = STM32BootLoader::singleton()->stm32_erase_memory(stm, first_page,
                num_pages);

        if (s_err != STM32_ERR_OK)
        {
            fprintf(stderr, "Failed to erase memory\n");
            emit logView("Failed to erase memory", CRITICAL);
            break;
        }

        ret = 0;


    }
    break;

    case ACT_CRC:
    {
        uint32_t crc_val = 0;
        fprintf(stdout, "CRC computation\n");
        emit logView("CRC computation", INFO);

        s_err = STM32BootLoader::singleton()->stm32_crc_wrapper(stm, start, end - start,
                &crc_val);

        if (s_err != STM32_ERR_OK)
        {
            emit logView("Failed to read CRC", CRITICAL);

            fprintf(stderr, "Failed to read CRC\n");
            fflush(stderr);
            break;
        }

        ret = 0;

        fprintf(stdout, "CRC(0x%08x-0x%08x) = 0x%08x\n", start, end, crc_val);
        emit logView(tr("CRC(0x%1-0x%2) = 0x%3").arg(QString::number(start,
                     16)).arg(QString::number(end, 16)).arg(QString::number(crc_val, 16)), INFO);


    }
    break;

    default:
        break;
    }



    if (exec_flag && ret == 0)
    {
        if (execute == 0)
        {
            execute = stm.dev->fl_start;
        }

        emit logView(tr("Starting execution at address 0x%1...").arg(QString::number(
                         execute, 16)),  INFO);
        fprintf(stdout, "\nStarting execution at address 0x%08x... ", execute);
        fflush(stdout);

        if (STM32BootLoader::singleton()->stm32_go(stm, execute) == STM32_ERR_OK)
        {
            reset_flag = 0;
            fprintf(stdout, "starting execution done.\n");
            fflush(stdout);
            emit logView("starting execution Done", INFO);
            wait_ms(2000);

            if (STM32BootLoader::singleton())
            {
                STM32BootLoader::singleton()->disconnect();
                emit logView(QString("disconnected"), INFO);
            }

            emit taskFininshedSignal();

        }
        else
        {
            fprintf(stdout, "starting execution failed.\n");
            emit logView("starting execution failed", CRITICAL);
        }

        fflush(stdout);
    }

    if (p_st)
    {
        binary_close(p_st);
        p_st = NULL;
    }

    if (h_st)
    {
        hex_close(h_st);
        h_st = NULL;

    }

    m_state = IDLE;
}
