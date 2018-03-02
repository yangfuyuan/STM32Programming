/*
 *  STM32Programming
 *
 *  Copyright 2015 - 2020 yangfuyuan
 *  
 * 
 */
#include "common.h"
#include "stm32_bootloader.h"
#include <math.h>
#include <stdio.h>
using namespace impl;







namespace stm32{

	STM32BootLoader* STM32BootLoader::_impl = NULL;

	STM32BootLoader::STM32BootLoader():
	_serial(0) {
		isConnected = false;
		_baudrate = 115200;
        _parity   = serial::parity_none;
        _bytesize = serial::eightbits;
        _stopbits = serial::stopbits_one;
        _flowcontrol = serial::flowcontrol_none;
        m_flags = PORT_BYTE | PORT_GVR_ETX | PORT_CMD_INIT | PORT_RETRY;
	}

	STM32BootLoader::~STM32BootLoader(){
        ScopedLocker lock(serial_lock);
		if(_serial){
			if(_serial->isOpen()){
				_serial->close();
			}
		}
		if(_serial){
			delete _serial;
			_serial = NULL;
		}
	}


    stm32_err_t STM32BootLoader::connect(const char *port_path, uint32_t baudrate, bytesize_t bytesize, parity_t parity, stopbits_t stopbits, flowcontrol_t flowcontrol) {
		_baudrate = baudrate;
        _bytesize = bytesize;
		_parity   = parity;
        _stopbits = stopbits;
        _flowcontrol = flowcontrol;
        {
        	ScopedLocker lock(serial_lock);
			if(!_serial){
                _serial = new serial::Serial(port_path, _baudrate, serial::Timeout::simpleTimeout(DEFAULT_TIMEOUT));
			}
        }


		{
			ScopedLocker lock(_lock);
			if(!_serial->open()){
                return STM32_ERR_UNKNOWN;
			}
            _serial->setParity(parity);
            _serial->setBytesize(bytesize);
            _serial->setStopbits(stopbits);
            _serial->setFlowcontrol(flowcontrol);
            _serial->setDTR(1);
		}



        {
            isConnected = true;
        }


        return STM32_ERR_OK;
	}


	void STM32BootLoader::disconnect() {
		if (!isConnected){
			return ;
		}
        ScopedLocker lock(serial_lock);
		if(_serial){
			if(_serial->isOpen()){
				_serial->close();
			}
		}
		isConnected = false;
	}


    stm32_err_t STM32BootLoader::sendData(const uint8_t * data, size_t size) {
        {
		if (!isConnected) {
            return STM32_ERR_UNKNOWN;
		}
        }

		if (data == NULL || size ==0) {
            return STM32_ERR_UNKNOWN;
		}
        size_t r;
        while (size) {
            {
                ScopedLocker lock(serial_lock);
                r = _serial->write(data, size);
            }

            if (r < 1)
                return STM32_ERR_UNKNOWN;
            size -= r;
            data += r;
        }
        return STM32_ERR_OK;
	}

    stm32_err_t STM32BootLoader::getData(uint8_t * data, size_t size) {
        {
		if (!isConnected) {
            return STM32_ERR_UNKNOWN;
		}
        }
        size_t r;
        while (size) {
            {
                ScopedLocker lock(serial_lock);
                r = _serial->read(data, size);
            }
            if (r == 0)
                return STM32_ERR_TIMEOUT;
            if (r < 0)
                return STM32_ERR_UNKNOWN;
            size -= r;
            data += r;

        }
        return STM32_ERR_OK;
	}


    stm32_err_t STM32BootLoader::waitForData(size_t data_count, uint32_t timeout, size_t * returned_size) {
		size_t length = 0;
		if (returned_size==NULL) {
			returned_size=(size_t *)&length;
		}
        ScopedLocker lock(serial_lock);
        int ret = _serial->waitfordata(data_count, timeout, returned_size);
        if(ret ==0){
            return STM32_ERR_OK;
        }else if(ret ==-1){
            return STM32_ERR_TIMEOUT;
        }else{
            return STM32_ERR_UNKNOWN;
        }
	}

    std::string STM32BootLoader::getSDKVersion(){
		return SDKVerision;
	}

	
    

    //stm32 bootloader

    stm32_err_t STM32BootLoader::stm32_send_init_seq(uint32_t timeout){
            stm32_err_t ret;
            if (!isConnected) {
                return STM32_ERR_UNKNOWN;
            }
            uint8_t byte, cmd = STM32_CMD_INIT;

            {
                ScopedLocker lock(_lock);
                if(sendData(&cmd, 1) != STM32_ERR_OK){
                     fprintf(stderr, "Failed to send command\n");
                     return STM32_ERR_UNKNOWN;
                 }
            }
            ret = getData(&byte, 1);
            if (ret == STM32_ERR_OK && byte == STM32_ACK)
                return STM32_ERR_OK;

            if (ret == STM32_ERR_OK && byte == STM32_NACK) {
                /* We could get error later, but let's continue, for now. */
                fprintf(stderr,"Warning: the interface was not closed properly.\n");
                sig("Warning: the interface was not closed properly.",1);
                return STM32_ERR_OK;
            }
            if (ret != STM32_ERR_TIMEOUT) {
                fprintf(stderr, "Failed to init device.\n");
                return STM32_ERR_UNKNOWN;
            }

            /*
             * Check if previous STM32_CMD_INIT was taken as first byte
             * of a command. Send a new byte, we should get back a NACK.
             */

            {
                ScopedLocker lock(_lock);
                if(sendData(&cmd, 1) != STM32_ERR_OK){
                     fprintf(stderr, "Failed to send command\n");
                     return STM32_ERR_UNKNOWN;
                 }
            }
            ret = getData(&byte, 1);
            if (ret == STM32_ERR_OK && byte == STM32_NACK)
                return STM32_ERR_OK;
            fprintf(stderr, "Failed to init device.\n");
             sig("Failed to init device.",2);
            return STM32_ERR_UNKNOWN;
    }

    stm32_err_t STM32BootLoader::stm32_send_command(const uint8_t cmd)
    {
        return stm32_send_command_timeout(cmd, 0);
    }

    stm32_err_t STM32BootLoader::stm32_send_command_timeout(const uint8_t cmd, uint32_t timeout)
    {
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        stm32_err_t ret;
        uint8_t buf[2];


        buf[0] = cmd;
        buf[1] = cmd ^ 0xFF;
        {
            ScopedLocker lock(_lock);
            if(sendData(buf, 2) != STM32_ERR_OK){
                fprintf(stderr, "Failed to send command\n");
                return STM32_ERR_UNKNOWN;
            }
        }

        ret = stm32_get_ack_timeout(timeout);
        if (ret == STM32_ERR_OK)
            return STM32_ERR_OK;
        if (ret == STM32_ERR_TIMEOUT){
            fprintf(stderr, "Got NACK from device on command 0x%02x\n", cmd);
            char str[256];
            sprintf(str, "0x%02x.", cmd);
            sig("ot NACK from device on command " + string(str),1);

        }else{
            char str[256];
            sprintf(str, "0x%02x.", cmd);
            fprintf(stderr, "Unexpected reply from device on command 0x%02x\n", cmd);
            sig("Unexpected reply from device on command "+ string(str),2);
        }
        return STM32_ERR_UNKNOWN;
    }

    stm32_err_t STM32BootLoader::stm32_send_command_adj(const uint8_t cmd, uint32_t timeout)
    {
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }
        stm32_err_t ret;
        uint8_t buf[2];

        buf[0] = cmd;
        buf[1] = cmd ^ 0xFF;
        {
            ScopedLocker lock(_lock);
            if(sendData(buf, 2) != STM32_ERR_OK){
                fprintf(stderr, "Failed to send command\n");
                return STM32_ERR_UNKNOWN;
            }
        }

        ret = stm32_get_ack_timeout(timeout);
        if (ret == STM32_ERR_OK)
            return STM32_ERR_OK;

        return STM32_ERR_UNKNOWN;
    }

    stm32_err_t STM32BootLoader::stm32_get_version(stm32_info& info,uint32_t current_speed, uint32_t timeout)
    {
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        uint8_t len, buf[3];
        if(stm32_send_command_adj(STM32_CMD_GVR, 0) == STM32_ERR_OK) {
                printf("succefful ACK/NACK at speed = %d\n", current_speed);
                /* From AN, only UART bootloader returns 3 bytes */
                len = (m_flags & PORT_GVR_ETX) ? 3 : 1;
                if (getData(buf, len) != STM32_ERR_OK)
                    return STM32_ERR_UNKNOWN;
                info.version = buf[0];
                info.option1 = (m_flags & PORT_GVR_ETX) ? buf[1] : 0;
                info.option2 = (m_flags & PORT_GVR_ETX) ? buf[2] : 0;
                if (stm32_get_ack() != STM32_ERR_OK) {
                    return STM32_ERR_UNKNOWN;
                }
            return STM32_ERR_OK;
        }else
           return STM32_ERR_UNKNOWN;
    }

    stm32_err_t STM32BootLoader::stm32_get_ack()
    {
        return stm32_get_ack_timeout(0);
    }


    stm32_err_t STM32BootLoader::stm32_get_ack_timeout(uint32_t timeout)
    {
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }
        uint8_t byte;
        stm32_err_t ans;
        uint32_t startTs;
        uint32_t waitTime;

        if (!(m_flags & PORT_RETRY))
                timeout = 0;

        if(timeout)
            startTs = getms();

        do{
            size_t remainSize = 1;
            size_t recvSize;
            if(timeout)
                    ans = waitForData(remainSize, timeout - waitTime, &recvSize);

            if (ans == STM32_ERR_TIMEOUT&& timeout){
                if((waitTime=(getms() - startTs)) <= timeout)
                    continue;
            }else if(ans == STM32_ERR_UNKNOWN){
                return STM32_ERR_UNKNOWN;
            }

            ans = getData(&byte, 1);

            if (ans == STM32_ERR_UNKNOWN){
                return STM32_ERR_UNKNOWN;
            }

            if (byte == STM32_ACK)
                return STM32_ERR_OK;

            if (byte == STM32_NACK)
                return STM32_ERR_NACK;

            if (byte != STM32_BUSY) {
                return STM32_ERR_UNKNOWN;
            }

            return STM32_ERR_UNKNOWN;


        }while ((waitTime=(getms() - startTs)) <= timeout);

    }


    stm32_err_t STM32BootLoader::stm32_init(stm32_info &info,const char init, uint32_t timeout)
    {
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        info.cmd = (stm32_cmd*)malloc(sizeof(stm32_cmd));
        memset(info.cmd, STM32_CMD_ERR, sizeof(stm32_cmd));

        uint8_t len, val, buf[257];
        int new_cmds;

        if ((m_flags & PORT_CMD_INIT) && init)
            if (stm32_send_init_seq() != STM32_ERR_OK){
                printf("VM: stm32_send_init_seq failed\n");
                sig("stm32_send_init_seq failed.",2);

            }

        /* get the version and read protection status  */
        if (stm32_send_command(STM32_CMD_GVR) != STM32_ERR_OK) {
                return STM32_ERR_UNKNOWN;
        }

        /* From AN, only UART bootloader returns 3 bytes */
        len = (m_flags & PORT_GVR_ETX) ? 3 : 1;

        stm32_err_t ans = getData(buf, len);
        if(ans != STM32_ERR_OK)
            return STM32_ERR_UNKNOWN;

        info.version = buf[0];
        info.option1 = (m_flags & PORT_GVR_ETX) ? buf[1] : 0;
        info.option2 = (m_flags & PORT_GVR_ETX) ? buf[2] : 0;

        if (stm32_get_ack() != STM32_ERR_OK) {
            return STM32_ERR_UNKNOWN;

        }


        /* get the bootloader information */
        len = STM32_CMD_GET_LENGTH;

        if (stm32_guess_len_cmd(STM32_CMD_GET, buf, len) != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

        len = buf[0] + 1;
        info.bl_version = buf[1];
        new_cmds = 0;

        for (int i = 1; i < len; i++) {
                val = buf[i + 1];
                switch (val) {
                case STM32_CMD_GET:
                    info.cmd->get = val; break;
                case STM32_CMD_GVR:
                    info.cmd->gvr = val; break;
                case STM32_CMD_GID:
                    info.cmd->gid = val; break;
                case STM32_CMD_RM:
                    info.cmd->rm = val; break;
                case STM32_CMD_GO:
                    info.cmd->go = val; break;
                case STM32_CMD_WM:
                case STM32_CMD_WM_NS:
                    info.cmd->wm = newer(info.cmd->wm, val);
                    break;
                case STM32_CMD_ER:
                case STM32_CMD_EE:
                case STM32_CMD_EE_NS:
                    info.cmd->er = newer(info.cmd->er, val);
                    break;
                case STM32_CMD_WP:
                case STM32_CMD_WP_NS:
                    info.cmd->wp = newer(info.cmd->wp, val);
                    break;
                case STM32_CMD_UW:
                case STM32_CMD_UW_NS:
                    info.cmd->uw = newer(info.cmd->uw, val);
                    break;
                case STM32_CMD_RP:
                case STM32_CMD_RP_NS:
                    info.cmd->rp = newer(info.cmd->rp, val);
                    break;
                case STM32_CMD_UR:
                case STM32_CMD_UR_NS:
                    info.cmd->ur = newer(info.cmd->ur, val);
                    break;
                case STM32_CMD_CRC:
                    info.cmd->crc = newer(info.cmd->crc, val);
                    break;
                default:
                    if (new_cmds++ == 0)
                        fprintf(stderr,"GET returns unknown commands (0x%2x",val);
                    else
                        fprintf(stderr, ", 0x%2x", val);
                }
            }


        if (new_cmds)
            fprintf(stderr, ")\n");

        if (stm32_get_ack() != STM32_ERR_OK) {
            return STM32_ERR_UNKNOWN;

        }

            if (info.cmd->get == STM32_CMD_ERR|| info.cmd->gvr == STM32_CMD_ERR|| info.cmd->gid == STM32_CMD_ERR) {
                fprintf(stderr, "Error: bootloader did not returned correct information from GET command\n");
                sig("bootloader did not returned correct information from GET command.",2);

                return STM32_ERR_UNKNOWN;
            }

            /* get the device ID */
            if (stm32_guess_len_cmd(info.cmd->gid, buf, 1) != STM32_ERR_OK) {
                return STM32_ERR_UNKNOWN;
            }
            len = buf[0] + 1;
            if (len < 2) {
                fprintf(stderr, "Only %d bytes sent in the PID, unknown/unsupported device\n", len);
                sig("Only %d bytes sent in the PID, unknown/unsupported device.",2);
                return STM32_ERR_UNKNOWN;
            }
            info.pid = (buf[1] << 8) | buf[2];
            if (len > 2) {
                fprintf(stderr, "This bootloader returns %d extra bytes in PID:", len);
                for (int i = 2; i <= len ; i++)
                    fprintf(stderr, " %02x", buf[i]);
                fprintf(stderr, "\n");
            }
            if (stm32_get_ack() != STM32_ERR_OK) {
                return STM32_ERR_UNKNOWN;
            }

            info.dev = devices;
            while (info.dev->id != 0x00 && info.dev->id != info.pid)
                ++info.dev;

            if (!info.dev->id) {
                fprintf(stderr, "Unknown/unsupported device (Device ID: 0x%03x)\n", info.pid);
                char str[255];
                sprintf(str, "0x%03x).", info.pid);
                sig("Unknown/unsupported device (Device ID: " + string(str),2);
                return STM32_ERR_UNKNOWN;
            }

            return STM32_ERR_OK;




    }

    stm32_err_t STM32BootLoader::stm32_guess_len_cmd(uint8_t cmd, uint8_t *data, unsigned int len, uint32_t timeout)
    {
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        if (stm32_send_command(cmd) != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

        stm32_err_t ret;
        if (m_flags & PORT_BYTE) {
            /* interface is UART-like */
            ret =getData(data, 1);
            if (ret != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            len = data[0];
            ret = getData(data + 1, len + 1);
            if (ret != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            return STM32_ERR_OK;

        }

        ret = getData( data, len + 2);
        if (ret == STM32_ERR_OK && len == data[0])
            return STM32_ERR_OK;
        if (ret != STM32_ERR_OK) {
            /* restart with only one byte */
            if (stm32_resync(STM32_RESYNC_TIMEOUT*1000) != STM32_ERR_OK)
                    return STM32_ERR_UNKNOWN;
            if (stm32_send_command(cmd) != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            ret = getData(data, 1);
            if (ret != STM32_ERR_OK)
                    return STM32_ERR_UNKNOWN;

        }


        fprintf(stderr, "Re sync (len = %d)\n", data[0]);

        if (stm32_resync(STM32_RESYNC_TIMEOUT*1000) != STM32_ERR_OK)
            return STM32_ERR_UNKNOWN;

        len = data[0];
        if (stm32_send_command( cmd) != STM32_ERR_OK)
            return STM32_ERR_UNKNOWN;
        ret = getData( data, len + 2);
        if (ret != STM32_ERR_OK)
            return STM32_ERR_UNKNOWN;

        return STM32_ERR_OK;
    }

    stm32_err_t STM32BootLoader::stm32_resync(uint32_t timeout)
    {
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        stm32_err_t ret;
        uint8_t buf[2], ack;

        buf[0] = STM32_CMD_ERR;
        buf[1] = STM32_CMD_ERR ^ 0xFF;

            uint32_t startTs = getms();
            uint32_t waitTime;
            while ((waitTime=(getms() - startTs)) <= timeout) {
                {
                    ScopedLocker lock(_lock);
                    if(sendData(buf, 2) != STM32_ERR_OK){
                        fprintf(stderr, "Failed to send command\n");
                        usleep(500000);
                        continue;
                    }
                }
                ret = getData(&ack,1);

                if (ret != STM32_ERR_OK) {
                    continue;
                }
                if (ack == STM32_NACK)
                    return STM32_ERR_OK;


            }
            return STM32_ERR_UNKNOWN;
    }

    stm32_err_t STM32BootLoader::stm32_read_memory(const stm32_info& info,uint32_t address,uint8_t *data, unsigned int len,uint32_t timeout){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        uint8_t buf[5];

            if (!len)
                return STM32_ERR_OK;

            if (len > 256) {
                fprintf(stderr, "Error: READ length limit at 256 bytes\n");
                sig("READ length limit at 256 bytes.",2);

                return STM32_ERR_UNKNOWN;
            }

            if (info.cmd->rm == STM32_CMD_ERR) {
                fprintf(stderr, "Error: READ command not implemented in bootloader.\n");
                sig("READ command not implemented in bootloader.",2);
                return STM32_ERR_NO_CMD;
            }

            if (stm32_send_command(info.cmd->rm) != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            buf[0] = address >> 24;
            buf[1] = (address >> 16) & 0xFF;
            buf[2] = (address >> 8) & 0xFF;
            buf[3] = address & 0xFF;
            buf[4] = buf[0] ^ buf[1] ^ buf[2] ^ buf[3];

            {
                ScopedLocker lock(_lock);
                if(sendData( buf, 5) != STM32_ERR_OK){
                    fprintf(stderr, "Failed to send command\n");
                    return STM32_ERR_UNKNOWN;
                }
            }

            if (stm32_get_ack() != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            if (stm32_send_command(len - 1) != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            {

                if (getData( data, len) != STM32_ERR_OK)
                    return STM32_ERR_UNKNOWN;
            }


            return STM32_ERR_OK;

    }

    stm32_err_t STM32BootLoader::stm32_write_memory(const stm32_info& info,uint32_t address,const uint8_t *data, unsigned int len,uint32_t timeout){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        uint8_t cs, buf[256 + 2];
            unsigned int i, aligned_len;
            stm32_err_t s_err;

            if (!len)
                return STM32_ERR_OK;

            if (len > 256) {
                sig("READ length limit at 256 bytes.",2);
                fprintf(stderr, "Error: READ length limit at 256 bytes\n");
                return STM32_ERR_UNKNOWN;
            }

            /* must be 32bit aligned */
            if (address & 0x3) {
                sig("WRITE address must be 4 byte aligned.",2);
                fprintf(stderr, "Error: WRITE address must be 4 byte aligned\n");
                return STM32_ERR_UNKNOWN;
            }

            if (info.cmd->wm == STM32_CMD_ERR) {
                sig("WRITE command not implemented in bootloader.",2);
                fprintf(stderr, "Error: WRITE command not implemented in bootloader.\n");
                return STM32_ERR_NO_CMD;
            }

            /* send the address and checksum */
            if (stm32_send_command(info.cmd->wm) != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            buf[0] = address >> 24;
            buf[1] = (address >> 16) & 0xFF;
            buf[2] = (address >> 8) & 0xFF;
            buf[3] = address & 0xFF;
            buf[4] = buf[0] ^ buf[1] ^ buf[2] ^ buf[3];

            {
                ScopedLocker lock(_lock);
                if(sendData(buf, 5) != STM32_ERR_OK){
                    fprintf(stderr, "Failed to send command\n");
                    return STM32_ERR_UNKNOWN;
                }
            }

            if (stm32_get_ack() != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            aligned_len = (len + 3) & ~3;
            cs = aligned_len - 1;
            buf[0] = aligned_len - 1;
            for (i = 0; i < len; i++) {
                cs ^= data[i];
                buf[i + 1] = data[i];
            }
            /* padding data */
            for (i = len; i < aligned_len; i++) {
                cs ^= 0xFF;
                buf[i + 1] = 0xFF;
            }
            buf[aligned_len + 1] = cs;
            {
                ScopedLocker lock(_lock);
                if(sendData( buf, aligned_len + 2) != STM32_ERR_OK){
                    fprintf(stderr, "Failed to send command\n");
                    return STM32_ERR_UNKNOWN;
                }

            }

            s_err = stm32_get_ack_timeout( STM32_BLKWRITE_TIMEOUT*1000);
            if (s_err != STM32_ERR_OK) {
                if (m_flags & PORT_STRETCH_W
                    && info.cmd->wm != STM32_CMD_WM_NS)
                    stm32_warn_stretching("write");
                return STM32_ERR_UNKNOWN;
            }
            return STM32_ERR_OK;

    }
    stm32_err_t STM32BootLoader::stm32_wunprot_memory(const stm32_info& info,uint32_t timeout){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        stm32_err_t s_err;

            if (info.cmd->uw == STM32_CMD_ERR) {
                fprintf(stderr, "Error: WRITE UNPROTECT command not implemented in bootloader.\n");
                sig("WRITE UNPROTECT command not implemented in bootloader.",2);

                return STM32_ERR_NO_CMD;
            }

            if (stm32_send_command(info.cmd->uw) != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            s_err = stm32_get_ack_timeout(STM32_WUNPROT_TIMEOUT*1000);
            if (s_err == STM32_ERR_TIMEOUT) {
                fprintf(stderr, "Error: Failed to WRITE UNPROTECT\n");
                sig("Failed to WRITE UNPROTECT.",2);

                return STM32_ERR_UNKNOWN;
            }
            if (s_err != STM32_ERR_OK) {
                if (m_flags & PORT_STRETCH_W
                    && info.cmd->uw != STM32_CMD_UW_NS)
                    stm32_warn_stretching("WRITE UNPROTECT");
                return STM32_ERR_UNKNOWN;
            }
            return STM32_ERR_OK;

    }
    stm32_err_t STM32BootLoader::stm32_wprot_memory(const stm32_info& info,uint32_t timeout){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }
        stm32_err_t s_err;

            if (info.cmd->wp == STM32_CMD_ERR) {
                fprintf(stderr, "Error: WRITE PROTECT command not implemented in bootloader.\n");
                sig("WRITE PROTECT command not implemented in bootloader.",2);
                return STM32_ERR_NO_CMD;
            }

            if (stm32_send_command(info.cmd->wp) != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            s_err = stm32_get_ack_timeout(STM32_WPROT_TIMEOUT*1000);
            if (s_err == STM32_ERR_TIMEOUT) {
                fprintf(stderr, "Error: Failed to WRITE PROTECT\n");
                sig("Failed to WRITE PROTECT.",2);

                return STM32_ERR_UNKNOWN;
            }
            if (s_err != STM32_ERR_OK) {
                if (m_flags & PORT_STRETCH_W
                    && info.cmd->wp != STM32_CMD_WP_NS)
                    stm32_warn_stretching("WRITE PROTECT");
                return STM32_ERR_UNKNOWN;
            }
            return STM32_ERR_OK;

    }
    stm32_err_t STM32BootLoader::stm32_runprot_memory(const stm32_info& info,uint32_t timeout){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        stm32_err_t s_err;

            if (info.cmd->ur == STM32_CMD_ERR) {
                fprintf(stderr, "Error: READOUT UNPROTECT command not implemented in bootloader.\n");
                sig("READOUT UNPROTECT command not implemented in bootloader.",2);

                return STM32_ERR_NO_CMD;
            }

            if (stm32_send_command(info.cmd->ur) != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            s_err = stm32_get_ack_timeout(STM32_MASSERASE_TIMEOUT*1000);
            if (s_err == STM32_ERR_TIMEOUT) {
                sig("Failed to READOUT UNPROTECT.",2);

                fprintf(stderr, "Error: Failed to READOUT UNPROTECT\n");
                return STM32_ERR_UNKNOWN;
            }
            if (s_err != STM32_ERR_OK) {
                if (m_flags & PORT_STRETCH_W
                    && info.cmd->ur != STM32_CMD_UR_NS)
                    stm32_warn_stretching("READOUT UNPROTECT");
                return STM32_ERR_UNKNOWN;
            }
            return STM32_ERR_OK;

    }
    stm32_err_t STM32BootLoader::stm32_readprot_memory(const stm32_info& info,uint32_t timeout ){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        stm32_err_t s_err;

            if (info.cmd->rp == STM32_CMD_ERR) {
                fprintf(stderr, "Error: READOUT PROTECT command not implemented in bootloader.\n");
                sig("READOUT PROTECT command not implemented in bootloader.",2);
                return STM32_ERR_NO_CMD;
            }

            if (stm32_send_command(info.cmd->rp) != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            s_err = stm32_get_ack_timeout(STM32_RPROT_TIMEOUT*1000);
            if (s_err == STM32_ERR_TIMEOUT) {
                fprintf(stderr, "Error: Failed to READOUT PROTECT\n");
                sig("Failed to READOUT PROTECT.",2);

                return STM32_ERR_UNKNOWN;
            }
            if (s_err != STM32_ERR_OK) {
                if (m_flags & PORT_STRETCH_W
                    && info.cmd->rp != STM32_CMD_RP_NS)
                    stm32_warn_stretching("READOUT PROTECT");
                return STM32_ERR_UNKNOWN;
            }
            return STM32_ERR_OK;

    }
    stm32_err_t STM32BootLoader::stm32_mass_erase(const stm32_info& info,uint32_t timeout){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        stm32_err_t s_err;
            uint8_t buf[3];

            if (stm32_send_command(info.cmd->er) != STM32_ERR_OK) {
                fprintf(stderr, "Can't initiate chip mass erase!\n");
                sig("Can't initiate chip mass erase.",2);
                return STM32_ERR_UNKNOWN;
            }

            /* regular erase (0x43) */
            if (info.cmd->er == STM32_CMD_ER) {
                s_err = stm32_send_command_timeout(0xFF, STM32_MASSERASE_TIMEOUT*1000);
                if (s_err != STM32_ERR_OK) {
                    if (m_flags & PORT_STRETCH_W)
                        stm32_warn_stretching("mass erase");
                    return STM32_ERR_UNKNOWN;
                }
                return STM32_ERR_OK;
            }

            /* extended erase */
            buf[0] = 0xFF;	/* 0xFFFF the magic number for mass erase */
            buf[1] = 0xFF;
            buf[2] = 0x00;  /* checksum */
            {
                ScopedLocker lock(_lock);
                if(sendData( buf, 3) != STM32_ERR_OK){
                    fprintf(stderr, "Failed to send command\n");
                    return STM32_ERR_UNKNOWN;
                }

            }
            s_err = stm32_get_ack_timeout(STM32_MASSERASE_TIMEOUT*1000);
            if (s_err != STM32_ERR_OK) {
                fprintf(stderr, "Mass erase failed. Try specifying the number of pages to be erased.\n");
                sig("Mass erase failed. Try specifying the number of pages to be erased.",2);
            if (m_flags & PORT_STRETCH_W
                && info.cmd->er != STM32_CMD_EE_NS)
                stm32_warn_stretching("mass erase");
                return STM32_ERR_UNKNOWN;
            }
            return STM32_ERR_OK;

    }
    stm32_err_t STM32BootLoader::stm32_pages_erase(const stm32_info& info, uint32_t spage, uint32_t pages,uint32_t timeout ){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        stm32_err_t s_err;
        uint32_t pg_num;
        uint8_t pg_byte;
        uint8_t cs = 0;
        uint8_t *buf;
        int i = 0;

        /* The erase command reported by the bootloader is either 0x43, 0x44 or 0x45 */
        /* 0x44 is Extended Erase, a 2 byte based protocol and needs to be handled differently. */
        /* 0x45 is clock no-stretching version of Extended Erase for I2C port. */
        if (stm32_send_command(info.cmd->er) != STM32_ERR_OK) {
            fprintf(stderr, "Can't initiate chip mass erase!\n");
            sig("Can't initiate chip mass erase.",2);

            return STM32_ERR_UNKNOWN;
        }

        /* regular erase (0x43) */
        if (info.cmd->er == STM32_CMD_ER) {
            buf = (uint8_t*)malloc(1 + pages + 1);
            if (!buf)
                return STM32_ERR_UNKNOWN;

            buf[i++] = pages - 1;
            cs ^= (pages-1);
            for (pg_num = spage; pg_num < (pages + spage); pg_num++) {
                buf[i++] = pg_num;
                cs ^= pg_num;
            }
            buf[i++] = cs;
            {
                ScopedLocker lock(_lock);
                if(sendData(buf, i) != STM32_ERR_OK){
                    free(buf);
                    fprintf(stderr, "Failed to send command\n");
                    return STM32_ERR_UNKNOWN;
                }
            }
            free(buf);

            s_err = stm32_get_ack_timeout(pages * STM32_PAGEERASE_TIMEOUT*1000);
            if (s_err != STM32_ERR_OK) {
                if (m_flags & PORT_STRETCH_W)
                    stm32_warn_stretching("erase");
                return STM32_ERR_UNKNOWN;
            }
            return STM32_ERR_OK;
        }

        /* extended erase */
        buf = (uint8_t*)malloc(2 + 2 * pages + 1);
        if (!buf)
            return STM32_ERR_UNKNOWN;

        /* Number of pages to be erased - 1, two bytes, MSB first */
        pg_byte = (pages - 1) >> 8;
        buf[i++] = pg_byte;
        cs ^= pg_byte;
        pg_byte = (pages - 1) & 0xFF;
        buf[i++] = pg_byte;
        cs ^= pg_byte;

        for (pg_num = spage; pg_num < spage + pages; pg_num++) {
            pg_byte = pg_num >> 8;
            cs ^= pg_byte;
            buf[i++] = pg_byte;
            pg_byte = pg_num & 0xFF;
            cs ^= pg_byte;
            buf[i++] = pg_byte;
        }
        buf[i++] = cs;
        {
            ScopedLocker lock(_lock);
            if(sendData(buf, i) != STM32_ERR_OK){
                free(buf);
                fprintf(stderr, "Failed to send command\n");
                return STM32_ERR_UNKNOWN;
            }
        }
        free(buf);


        s_err = stm32_get_ack_timeout(pages * STM32_PAGEERASE_TIMEOUT*1000);
        if (s_err != STM32_ERR_OK) {
            fprintf(stderr, "Page-by-page erase failed. Check the maximum pages your device supports.\n");
            sig("Page-by-page erase failed. Check the maximum pages your device supports.",2);

            if (m_flags & PORT_STRETCH_W
                && info.cmd->er != STM32_CMD_EE_NS)
                stm32_warn_stretching("erase");
            return STM32_ERR_UNKNOWN;
        }

        return STM32_ERR_OK;

    }
    stm32_err_t STM32BootLoader::stm32_erase_memory(const stm32_info& info, uint32_t spage, uint32_t pages,uint32_t timeout ){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        uint32_t n;
            stm32_err_t s_err;

            if (!pages || spage > STM32_MAX_PAGES ||
                ((pages != STM32_MASS_ERASE) && ((spage + pages) > STM32_MAX_PAGES)))
                return STM32_ERR_OK;

            if (info.cmd->er == STM32_CMD_ERR) {
                fprintf(stderr, "Error: ERASE command not implemented in bootloader.\n");
                sig("ERASE command not implemented in bootloader.",2);

                return STM32_ERR_UNKNOWN;
            }

            if (pages == STM32_MASS_ERASE) {
                /*
                 * Not all chips support mass erase.
                 * Mass erase can be obtained executing a "readout protect"
                 * followed by "readout un-protect". This method is not
                 * suggested because can hang the target if a debug SWD/JTAG
                 * is connected. When the target enters in "readout
                 * protection" mode it will consider the debug connection as
                 * a tentative of intrusion and will hang.
                 * Erasing the flash page-by-page is the safer way to go.
                 */
                if (!(info.dev->flags & F_NO_ME))
                    return stm32_mass_erase(info);

                pages = flash_addr_to_page_ceil(info, info.dev->fl_end);
            }

            /*
             * Some device, like STM32L152, cannot erase more than 512 pages in
             * one command. Split the call.
             */
            while (pages) {
                n = (pages <= 512) ? pages : 512;
                s_err = stm32_pages_erase(info, spage, n,timeout);
                if (s_err != STM32_ERR_OK)
                    return s_err;
                spage += n;
                pages -= n;
            }
            return STM32_ERR_OK;

    }
    stm32_err_t STM32BootLoader::stm32_run_raw_code(const stm32_info& info,uint32_t target_address,const uint8_t *code, uint32_t code_size,uint32_t timeout ){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        uint32_t stack_le = le_u32(0x20002000);
            uint32_t code_address_le = le_u32(target_address + 8 + 1); // thumb mode address (!)
            uint32_t length = code_size + 8;
            uint8_t *mem, *pos;
            uint32_t address, w;

            /* Must be 32-bit aligned */
            if (target_address & 0x3) {
                fprintf(stderr, "Error: code address must be 4 byte aligned\n");
                sig("code address must be 4 byte aligned.",2);
                return STM32_ERR_UNKNOWN;
            }

            mem = (uint8_t*)malloc(length);
            if (!mem)
                return STM32_ERR_UNKNOWN;

            memcpy(mem, &stack_le, sizeof(uint32_t));
            memcpy(mem + 4, &code_address_le, sizeof(uint32_t));
            memcpy(mem + 8, code, code_size);

            pos = mem;
            address = target_address;
            while (length > 0) {
                w = length > 256 ? 256 : length;
                if (stm32_write_memory(info,address, pos, w) != STM32_ERR_OK) {
                    free(mem);
                    return STM32_ERR_UNKNOWN;
                }

                address += w;
                pos += w;
                length -= w;
            }

            free(mem);
            return stm32_go(info, target_address, timeout);

    }
    stm32_err_t STM32BootLoader::stm32_go(const stm32_info& info,uint32_t address,uint32_t timeout ){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }

        uint8_t buf[5];

        if (info.cmd->go == STM32_CMD_ERR) {
            fprintf(stderr, "Error: GO command not implemented in bootloader.\n");
            sig(" GO command not implemented in bootloader.",2);

            return STM32_ERR_NO_CMD;
        }


        if (stm32_send_command(info.cmd->go) != STM32_ERR_OK)
            return STM32_ERR_UNKNOWN;


        buf[0] = address >> 24;
        buf[1] = (address >> 16) & 0xFF;
        buf[2] = (address >> 8) & 0xFF;
        buf[3] = address & 0xFF;
        buf[4] = buf[0] ^ buf[1] ^ buf[2] ^ buf[3];

        {
            ScopedLocker lock(_lock);
            if(sendData( buf, 5) != STM32_ERR_OK){
                fprintf(stderr, "Failed to send command\n");
                return STM32_ERR_UNKNOWN;
            }

        }


        if (stm32_get_ack() != STM32_ERR_OK)
            return STM32_ERR_UNKNOWN;
        return STM32_ERR_OK;

    }
    stm32_err_t STM32BootLoader::stm32_reset_device(const stm32_info& info,uint32_t timeout ){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }
        uint32_t target_address = info.dev->ram_start;

        if (info.dev->flags & F_OBLL) {
            /* set the OBL_LAUNCH bit to reset device (see RM0360, 2.5) */
            return stm32_run_raw_code(info,target_address, stm_obl_launch_code, stm_obl_launch_code_length,timeout);

        } else {
            return stm32_run_raw_code(info,target_address, stm_reset_code, stm_reset_code_length,timeout);

        }

    }
    stm32_err_t STM32BootLoader::stm32_crc_memory( const stm32_info& info,uint32_t address,uint32_t length, uint32_t *crc,uint32_t timeout ){
        if (!isConnected) {
            return STM32_ERR_UNKNOWN;
        }
            uint8_t buf[5];

            if (address & 0x3 || length & 0x3) {
                fprintf(stderr, "Start and end addresses must be 4 byte aligned\n");
                sig("Start and end addresses must be 4 byte aligned.",2);

                return STM32_ERR_UNKNOWN;
            }

            if (info.cmd->crc == STM32_CMD_ERR) {
                fprintf(stderr, "Error: CRC command not implemented in bootloader.\n");
                sig("CRC command not implemented in bootloader.",2);

                return STM32_ERR_NO_CMD;
            }

            if (stm32_send_command(info.cmd->crc) != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            buf[0] = address >> 24;
            buf[1] = (address >> 16) & 0xFF;
            buf[2] = (address >> 8) & 0xFF;
            buf[3] = address & 0xFF;
            buf[4] = buf[0] ^ buf[1] ^ buf[2] ^ buf[3];
            {
                ScopedLocker lock(_lock);
                if(sendData(buf, 5) != STM32_ERR_OK){
                    fprintf(stderr, "Failed to send command\n");
                    return STM32_ERR_UNKNOWN;
                }
            }

            if (stm32_get_ack() != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            buf[0] = length >> 24;
            buf[1] = (length >> 16) & 0xFF;
            buf[2] = (length >> 8) & 0xFF;
            buf[3] = length & 0xFF;
            buf[4] = buf[0] ^ buf[1] ^ buf[2] ^ buf[3];
            {
                ScopedLocker lock(_lock);
                if(sendData(buf, 5) != STM32_ERR_OK){
                    fprintf(stderr, "Failed to send command\n");
                    return STM32_ERR_UNKNOWN;
                }

            }

            if (stm32_get_ack() != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            if (stm32_get_ack() != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            if (getData(buf, 5) != STM32_ERR_OK)
                return STM32_ERR_UNKNOWN;

            if (buf[4] != (buf[0] ^ buf[1] ^ buf[2] ^ buf[3]))
                return STM32_ERR_UNKNOWN;

            *crc = (buf[0] << 24) | (buf[1] << 16) | (buf[2] << 8) | buf[3];
            return STM32_ERR_OK;

    }
    uint32_t STM32BootLoader::stm32_sw_crc(uint32_t crc, uint8_t *buf, unsigned int len){
            int i;
            uint32_t data;
            if (len & 0x3) {
                fprintf(stderr, "Buffer length must be multiple of 4 bytes\n");
                return 0;
            }

            while (len) {
                data = *buf++;
                data |= *buf++ << 8;
                data |= *buf++ << 16;
                data |= *buf++ << 24;
                len -= 4;

                crc ^= data;

                for (i = 0; i < 32; i++)
                    if (crc & CRC_MSBMASK)
                        crc = (crc << 1) ^ CRCPOLY_BE;
                    else
                        crc = (crc << 1);
            }
           return crc;
    }
    stm32_err_t STM32BootLoader::stm32_crc_wrapper(const stm32_info& info,uint32_t address,uint32_t length, uint32_t *crc,uint32_t timeout ){
        uint8_t buf[256];
            uint32_t start, total_len, len, current_crc;

            if (address & 0x3 || length & 0x3) {
                fprintf(stderr, "Start and end addresses must be 4 byte aligned\n");
                sig("Start and end addresses must be 4 byte aligned.",2);
                return STM32_ERR_UNKNOWN;
            }

            if (info.cmd->crc != STM32_CMD_ERR)
                return stm32_crc_memory(info, address, length, crc);

            start = address;
            total_len = length;
            current_crc = CRC_INIT_VALUE;
            while (length) {
                len = length > 256 ? 256 : length;
                if (stm32_read_memory(info, address, buf, len) != STM32_ERR_OK) {
                    fprintf(stderr,
                        "Failed to read memory at address 0x%08x, target write-protected?\n",
                        address);
                    sig("Failed to read memory at address 0x%08x, target write-protected.",2);
                    return STM32_ERR_UNKNOWN;
                }
                current_crc = stm32_sw_crc(current_crc, buf, len);
                length -= len;
                address += len;

                fprintf(stderr,
                    "\rCRC address 0x%08x (%.2f%%) ",
                    address,
                    (100.0f / (float)total_len) * (float)(address - start)
                );
                fflush(stderr);
            }
            fprintf(stderr, "Done.\n");
            *crc = current_crc;
            return STM32_ERR_OK;

    }










}
