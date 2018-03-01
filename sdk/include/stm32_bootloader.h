#pragma once

#include <stdlib.h>
#include <atomic>
#include <functional>
#include "locker.h"
#include "serial.h"
#include "thread.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>

#if !defined(__cplusplus)
#ifndef __cplusplus
#error "The STM32 BOOTLOADER SDK requires a C++ compiler to be built"
#endif
#endif

#if defined(_WIN32)
#pragma pack(1)
#endif


//stm32 bootloader
#define STM32_MAX_RX_FRAME	256	/* cmd read memory */
#define STM32_MAX_TX_FRAME	(1 + 256 + 1)	/* cmd write memory */

#define STM32_MAX_PAGES		0x0000ffff
#define STM32_MASS_ERASE	0x00100000 /* > 2 x max_pages */

#define STM32_ACK	0x79
#define STM32_NACK	0x1F
#define STM32_BUSY	0x76

#define STM32_CMD_INIT	0x7F
#define STM32_CMD_GET	0x00	/* get the version and command supported */
#define STM32_CMD_GVR	0x01	/* get version and read protection status */
#define STM32_CMD_GID	0x02	/* get ID */
#define STM32_CMD_RM	0x11	/* read memory */
#define STM32_CMD_GO	0x21	/* go */
#define STM32_CMD_WM	0x31	/* write memory */
#define STM32_CMD_WM_NS	0x32	/* no-stretch write memory */
#define STM32_CMD_ER	0x43	/* erase */
#define STM32_CMD_EE	0x44	/* extended erase */
#define STM32_CMD_EE_NS	0x45	/* extended erase no-stretch */
#define STM32_CMD_WP	0x63	/* write protect */
#define STM32_CMD_WP_NS	0x64	/* write protect no-stretch */
#define STM32_CMD_UW	0x73	/* write unprotect */
#define STM32_CMD_UW_NS	0x74	/* write unprotect no-stretch */
#define STM32_CMD_RP	0x82	/* readout protect */
#define STM32_CMD_RP_NS	0x83	/* readout protect no-stretch */
#define STM32_CMD_UR	0x92	/* readout unprotect */
#define STM32_CMD_UR_NS	0x93	/* readout unprotect no-stretch */
#define STM32_CMD_CRC	0xA1	/* compute CRC */
#define STM32_CMD_ERR	0xFF	/* not a valid command */

#define STM32_RESYNC_TIMEOUT	35	/* seconds */
#define STM32_MASSERASE_TIMEOUT	35	/* seconds */
#define STM32_PAGEERASE_TIMEOUT	5	/* seconds */
#define STM32_BLKWRITE_TIMEOUT	1	/* seconds */
#define STM32_WUNPROT_TIMEOUT	1	/* seconds */
#define STM32_WPROT_TIMEOUT	1	/* seconds */
#define STM32_RPROT_TIMEOUT	1	/* seconds */

#define STM32_CMD_GET_LENGTH	17	/* bytes in the reply */


/* flags */
#define PORT_BYTE	(1 << 0)	/* byte (not frame) oriented */
#define PORT_GVR_ETX	(1 << 1)	/* cmd GVR returns protection status */
#define PORT_CMD_INIT	(1 << 2)	/* use INIT cmd to autodetect speed */
#define PORT_RETRY	(1 << 3)	/* allowed read() retry after timeout */
#define PORT_STRETCH_W	(1 << 4)	/* warning for no-stretching commands */

/*
 * CRC computed by STM32 is similar to the standard crc32_be()
 * implemented, for example, in Linux kernel in ./lib/crc32.c
 * But STM32 computes it on units of 32 bits word and swaps the
 * bytes of the word before the computation.
 * Due to byte swap, I cannot use any CRC available in existing
 * libraries, so here is a simple not optimized implementation.
 */
#define CRCPOLY_BE	0x04c11db7
#define CRC_MSBMASK	0x80000000
#define CRC_INIT_VALUE	0xFFFFFFFF


/* find newer command by higher code */
#define newer(prev, a) (((prev) == STM32_CMD_ERR) ? (a) : (((prev) > (a)) ? (prev) : (a)))


typedef struct stm32_dev	stm32_dev_t;

typedef enum {
    F_NO_ME = 1 << 0,	/* Mass-Erase not supported */
    F_OBLL  = 1 << 1,	/* OBL_LAUNCH required */
} flags_t;

struct stm32_dev {
    uint16_t	id;
    const char	*name;
    uint32_t	ram_start, ram_end;
    uint32_t	fl_start, fl_end;
    uint16_t	fl_pps; // pages per sector
    uint32_t	*fl_ps;  // page size
    uint32_t	opt_start, opt_end;
    uint32_t	mem_start, mem_end;
    uint32_t	flags;
};


#define SZ_128	0x00000080
#define SZ_256	0x00000100
#define SZ_1K	0x00000400
#define SZ_2K	0x00000800
#define SZ_16K	0x00004000
#define SZ_32K	0x00008000
#define SZ_64K	0x00010000
#define SZ_128K	0x00020000
#define SZ_256K	0x00040000

/*
 * Page-size for page-by-page flash erase.
 * Arrays are zero terminated; last non-zero value is automatically repeated
 */

/* fixed size pages */
static uint32_t p_128[] = { SZ_128, 0 };
static uint32_t p_256[] = { SZ_256, 0 };
static uint32_t p_1k[]  = { SZ_1K,  0 };
static uint32_t p_2k[]  = { SZ_2K,  0 };
/* F2 and F4 page size */
static uint32_t f2f4[]  = { SZ_16K, SZ_16K, SZ_16K, SZ_16K, SZ_64K, SZ_128K, 0 };
/* F4 dual bank page size */
static uint32_t f4db[]  = {
    SZ_16K, SZ_16K, SZ_16K, SZ_16K, SZ_64K, SZ_128K, SZ_128K, SZ_128K,
    SZ_16K, SZ_16K, SZ_16K, SZ_16K, SZ_64K, SZ_128K, 0
};
/* F7 page size */
static uint32_t f7[]    = { SZ_32K, SZ_32K, SZ_32K, SZ_32K, SZ_128K, SZ_256K, 0 };

/*
 * Device table, corresponds to the "Bootloader device-dependant parameters"
 * table in ST document AN2606.
 * Note that the option bytes upper range is inclusive!
 */
const static stm32_dev_t devices[] = {
    /* ID   "name"                              SRAM-address-range      FLASH-address-range    PPS  PSize   Option-byte-addr-range  System-mem-addr-range   Flags */
    /* F0 */
    {0x440, "STM32F030x8/F05xxx"              , 0x20000800, 0x20002000, 0x08000000, 0x08010000,  4, p_1k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFEC00, 0x1FFFF800, 0},
    {0x442, "STM32F030xC/F09xxx"              , 0x20001800, 0x20008000, 0x08000000, 0x08040000,  2, p_2k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFD800, 0x1FFFF800, F_OBLL},
    {0x444, "STM32F03xx4/6"                   , 0x20000800, 0x20001000, 0x08000000, 0x08008000,  4, p_1k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFEC00, 0x1FFFF800, 0},
    {0x445, "STM32F04xxx/F070x6"              , 0x20001800, 0x20001800, 0x08000000, 0x08008000,  4, p_1k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFC400, 0x1FFFF800, 0},
    {0x448, "STM32F070xB/F071xx/F72xx"        , 0x20001800, 0x20004000, 0x08000000, 0x08020000,  2, p_2k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFC800, 0x1FFFF800, 0},
    /* F1 */
    {0x412, "STM32F10xxx Low-density"         , 0x20000200, 0x20002800, 0x08000000, 0x08008000,  4, p_1k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFF000, 0x1FFFF800, 0},
    {0x410, "STM32F10xxx Medium-density"      , 0x20000200, 0x20005000, 0x08000000, 0x08020000,  4, p_1k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFF000, 0x1FFFF800, 0},
    {0x414, "STM32F10xxx High-density"        , 0x20000200, 0x20010000, 0x08000000, 0x08080000,  2, p_2k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFF000, 0x1FFFF800, 0},
    {0x420, "STM32F10xxx Medium-density VL"   , 0x20000200, 0x20002000, 0x08000000, 0x08020000,  4, p_1k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFF000, 0x1FFFF800, 0},
    {0x428, "STM32F10xxx High-density VL"     , 0x20000200, 0x20008000, 0x08000000, 0x08080000,  2, p_2k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFF000, 0x1FFFF800, 0},
    {0x418, "STM32F105xx/F107xx"              , 0x20001000, 0x20010000, 0x08000000, 0x08040000,  2, p_2k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFB000, 0x1FFFF800, 0},
    {0x430, "STM32F10xxx XL-density"          , 0x20000800, 0x20018000, 0x08000000, 0x08100000,  2, p_2k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFE000, 0x1FFFF800, 0},
    /* F2 */
    {0x411, "STM32F2xxxx"                     , 0x20002000, 0x20020000, 0x08000000, 0x08100000,  1, f2f4  , 0x1FFFC000, 0x1FFFC00F, 0x1FFF0000, 0x1FFF7800, 0},
    /* F3 */
    {0x432, "STM32F373xx/F378xx"              , 0x20001400, 0x20008000, 0x08000000, 0x08040000,  2, p_2k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFD800, 0x1FFFF800, 0},
    {0x422, "STM32F302xB(C)/F303xB(C)/F358xx" , 0x20001400, 0x2000A000, 0x08000000, 0x08040000,  2, p_2k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFD800, 0x1FFFF800, 0},
    {0x439, "STM32F301xx/F302x4(6/8)/F318xx"  , 0x20001800, 0x20004000, 0x08000000, 0x08010000,  2, p_2k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFD800, 0x1FFFF800, 0},
    {0x438, "STM32F303x4(6/8)/F334xx/F328xx"  , 0x20001800, 0x20003000, 0x08000000, 0x08010000,  2, p_2k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFD800, 0x1FFFF800, 0},
    {0x446, "STM32F302xD(E)/F303xD(E)/F398xx" , 0x20001800, 0x20010000, 0x08000000, 0x08080000,  2, p_2k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFD800, 0x1FFFF800, 0},
    /* F4 */
    {0x413, "STM32F40xxx/41xxx"               , 0x20003000, 0x20020000, 0x08000000, 0x08100000,  1, f2f4  , 0x1FFFC000, 0x1FFFC00F, 0x1FFF0000, 0x1FFF7800, 0},
    {0x419, "STM32F42xxx/43xxx"               , 0x20003000, 0x20030000, 0x08000000, 0x08200000,  1, f4db  , 0x1FFEC000, 0x1FFFC00F, 0x1FFF0000, 0x1FFF7800, 0},
    {0x423, "STM32F401xB(C)"                  , 0x20003000, 0x20010000, 0x08000000, 0x08040000,  1, f2f4  , 0x1FFFC000, 0x1FFFC00F, 0x1FFF0000, 0x1FFF7800, 0},
    {0x433, "STM32F401xD(E)"                  , 0x20003000, 0x20018000, 0x08000000, 0x08080000,  1, f2f4  , 0x1FFFC000, 0x1FFFC00F, 0x1FFF0000, 0x1FFF7800, 0},
    {0x458, "STM32F410xx"                     , 0x20003000, 0x20008000, 0x08000000, 0x08020000,  1, f2f4  , 0x1FFFC000, 0x1FFFC00F, 0x1FFF0000, 0x1FFF7800, 0},
    {0x431, "STM32F411xx"                     , 0x20003000, 0x20020000, 0x08000000, 0x08080000,  1, f2f4  , 0x1FFFC000, 0x1FFFC00F, 0x1FFF0000, 0x1FFF7800, 0},
    {0x421, "STM32F446xx"                     , 0x20003000, 0x20020000, 0x08000000, 0x08080000,  1, f2f4  , 0x1FFFC000, 0x1FFFC00F, 0x1FFF0000, 0x1FFF7800, 0},
    {0x434, "STM32F469xx"                     , 0x20003000, 0x20060000, 0x08000000, 0x08200000,  1, f4db  , 0x1FFEC000, 0x1FFFC00F, 0x1FFF0000, 0x1FFF7800, 0},
    /* F7 */
    {0x449, "STM32F74xxx/75xxx"               , 0x20004000, 0x20050000, 0x08000000, 0x08100000,  1, f7    , 0x1FFF0000, 0x1FFF001F, 0x1FF00000, 0x1FF0EDC0, 0},
    /* L0 */
    {0x425, "STM32L031xx/041xx"               , 0x20001000, 0x20002000, 0x08000000, 0x08008000, 32, p_128 , 0x1FF80000, 0x1FF8001F, 0x1FF00000, 0x1FF01000, 0},
    {0x417, "STM32L05xxx/06xxx"               , 0x20001000, 0x20002000, 0x08000000, 0x08010000, 32, p_128 , 0x1FF80000, 0x1FF8001F, 0x1FF00000, 0x1FF01000, F_NO_ME},
    {0x447, "STM32L07xxx/08xxx"               , 0x20002000, 0x20005000, 0x08000000, 0x08030000, 32, p_128 , 0x1FF80000, 0x1FF8001F, 0x1FF00000, 0x1FF02000, 0},
    /* L1 */
    {0x416, "STM32L1xxx6(8/B)"                , 0x20000800, 0x20004000, 0x08000000, 0x08020000, 16, p_256 , 0x1FF80000, 0x1FF8001F, 0x1FF00000, 0x1FF01000, F_NO_ME},
    {0x429, "STM32L1xxx6(8/B)A"               , 0x20001000, 0x20008000, 0x08000000, 0x08020000, 16, p_256 , 0x1FF80000, 0x1FF8001F, 0x1FF00000, 0x1FF01000, F_NO_ME},
    {0x427, "STM32L1xxxC"                     , 0x20001000, 0x20008000, 0x08000000, 0x08040000, 16, p_256 , 0x1FF80000, 0x1FF8001F, 0x1FF00000, 0x1FF02000, F_NO_ME},
    {0x436, "STM32L1xxxD"                     , 0x20001000, 0x2000C000, 0x08000000, 0x08060000, 16, p_256 , 0x1FF80000, 0x1FF8009F, 0x1FF00000, 0x1FF02000, 0},
    {0x437, "STM32L1xxxE"                     , 0x20001000, 0x20014000, 0x08000000, 0x08080000, 16, p_256 , 0x1FF80000, 0x1FF8009F, 0x1FF00000, 0x1FF02000, F_NO_ME},
    /* L4 */
    {0x415, "STM32L476xx/486xx"               , 0x20003100, 0x20018000, 0x08000000, 0x08100000,  1, p_2k  , 0x1FFF7800, 0x1FFFF80F, 0x1FFF0000, 0x1FFF7000, 0},
    /* These are not (yet) in AN2606: */
    {0x641, "Medium_Density PL"               , 0x20000200, 0x20005000, 0x08000000, 0x08020000,  4, p_1k  , 0x1FFFF800, 0x1FFFF80F, 0x1FFFF000, 0x1FFFF800, 0},
    {0x9a8, "STM32W-128K"                     , 0x20000200, 0x20002000, 0x08000000, 0x08020000,  4, p_1k  , 0x08040800, 0x0804080F, 0x08040000, 0x08040800, 0},
    {0x9b0, "STM32W-256K"                     , 0x20000200, 0x20004000, 0x08000000, 0x08040000,  4, p_2k  , 0x08040800, 0x0804080F, 0x08040000, 0x08040800, 0},
    {0x0}
};


/* Reset code for ARMv7-M (Cortex-M3) and ARMv6-M (Cortex-M0)
 * see ARMv7-M or ARMv6-M Architecture Reference Manual (table B3-8)
 * or "The definitive guide to the ARM Cortex-M3", section 14.4.
 */
static const uint8_t stm_reset_code[] = {
    0x01, 0x49,		// ldr     r1, [pc, #4] ; (<AIRCR_OFFSET>)
    0x02, 0x4A,		// ldr     r2, [pc, #8] ; (<AIRCR_RESET_VALUE>)
    0x0A, 0x60,		// str     r2, [r1, #0]
    0xfe, 0xe7,		// endless: b endless
    0x0c, 0xed, 0x00, 0xe0,	// .word 0xe000ed0c <AIRCR_OFFSET> = NVIC AIRCR register address
    0x04, 0x00, 0xfa, 0x05	// .word 0x05fa0004 <AIRCR_RESET_VALUE> = VECTKEY | SYSRESETREQ
};

static const uint32_t stm_reset_code_length = sizeof(stm_reset_code);

/* RM0360, Empty check
 * On STM32F070x6 and STM32F030xC devices only, internal empty check flag is
 * implemented to allow easy programming of the virgin devices by the boot loader. This flag is
 * used when BOOT0 pin is defining Main Flash memory as the target boot space. When the
 * flag is set, the device is considered as empty and System memory (boot loader) is selected
 * instead of the Main Flash as a boot space to allow user to program the Flash memory.
 * This flag is updated only during Option bytes loading: it is set when the content of the
 * address 0x08000 0000 is read as 0xFFFF FFFF, otherwise it is cleared. It means a power
 * on or setting of OBL_LAUNCH bit in FLASH_CR register is needed to clear this flag after
 * programming of a virgin device to execute user code after System reset.
 */
static const uint8_t stm_obl_launch_code[] = {
    0x01, 0x49,		// ldr     r1, [pc, #4] ; (<FLASH_CR>)
    0x02, 0x4A,		// ldr     r2, [pc, #8] ; (<OBL_LAUNCH>)
    0x0A, 0x60,		// str     r2, [r1, #0]
    0xfe, 0xe7,		// endless: b endless
    0x10, 0x20, 0x02, 0x40, // address: FLASH_CR = 40022010
    0x00, 0x20, 0x00, 0x00  // value: OBL_LAUNCH = 00002000
};

static const uint32_t stm_obl_launch_code_length = sizeof(stm_obl_launch_code);


/* detect CPU endian */
static char cpu_le() {
    const uint32_t cpu_le_test = 0x12345678;
    return ((const unsigned char*)&cpu_le_test)[0] == 0x78;
}

static uint32_t be_u32(const uint32_t v) {
    if (cpu_le())
        return	((v & 0xFF000000) >> 24) |
            ((v & 0x00FF0000) >>  8) |
            ((v & 0x0000FF00) <<  8) |
            ((v & 0x000000FF) << 24);
    return v;
}

static uint32_t le_u32(const uint32_t v) {
        if (!cpu_le())
                return  ((v & 0xFF000000) >> 24) |
                        ((v & 0x00FF0000) >>  8) |
                        ((v & 0x0000FF00) <<  8) |
                        ((v & 0x000000FF) << 24);
        return v;
}



static void stm32_warn_stretching(const char *f)
{
    fprintf(stderr, "Attention !!!\n");
    fprintf(stderr, "\tThis %s error could be caused by your I2C\n", f);
    fprintf(stderr, "\tcontroller not accepting \"clock stretching\"\n");
    fprintf(stderr, "\tas required by bootloader.\n");
    fprintf(stderr, "\tCheck \"I2C.txt\" in stm32flash source code.\n");
}


struct stm32_cmd {
    uint8_t get;
    uint8_t gvr;
    uint8_t gid;
    uint8_t rm;
    uint8_t go;
    uint8_t wm;
    uint8_t er; /* this may be extended erase */
    uint8_t wp;
    uint8_t uw;
    uint8_t rp;
    uint8_t ur;
    uint8_t	crc;
}__attribute__((packed));

typedef enum {
    STM32_ERR_OK = 0,
    STM32_ERR_TIMEOUT,
    STM32_ERR_UNKNOWN,	/* Generic error */
    STM32_ERR_NACK,
    STM32_ERR_NO_CMD,	/* Command not available in bootloader */
} stm32_err_t;


enum parser_err {
    PARSER_ERR_OK,
    PARSER_ERR_SYSTEM,
    PARSER_ERR_INVALID_FILE,
    PARSER_ERR_WRONLY,
    PARSER_ERR_RDONLY
};
typedef enum   parser_err parser_err_t;


typedef struct {
    int		fd;
    char		write;
    struct stat	stat;
} binary_t;

typedef struct {
    size_t		data_len, offset;
    uint8_t		*data;
    uint32_t	base;
} hex_t;


struct stm32_info
{
    uint8_t			bl_version;
    uint8_t			version;
    uint8_t			option1;
    uint8_t         option2;
    uint16_t		pid;
    stm32_cmd       *cmd;
    const stm32_dev_t *dev;
}__attribute__((packed));


static int is_addr_in_ram(const stm32_info& info,uint32_t addr)
{
    return addr >= info.dev->ram_start && addr < info.dev->ram_end;
}

static int is_addr_in_flash(const stm32_info& info,uint32_t addr)
{
    return addr >= info.dev->fl_start && addr < info.dev->fl_end;
}

/* returns the page that contains address "addr" */
static int flash_addr_to_page_floor(const stm32_info& info,uint32_t addr)
{
    int page;
    uint32_t *psize;

    if (!is_addr_in_flash(info,addr))
        return 0;

    page = 0;
    addr -= info.dev->fl_start;
    psize = info.dev->fl_ps;

    while (addr >= psize[0]) {
        addr -= psize[0];
        page++;
        if (psize[1])
            psize++;
    }

    return page;
}

/* returns the first page whose start addr is >= "addr" */
static int flash_addr_to_page_ceil(const stm32_info& info,uint32_t addr)
{
    int page;
    uint32_t *psize;

    if (!(addr >= info.dev->fl_start && addr <= info.dev->fl_end))
        return 0;

    page = 0;
    addr -= info.dev->fl_start;
    psize = info.dev->fl_ps;

    while (addr >= psize[0]) {
        addr -= psize[0];
        page++;
        if (psize[1])
            psize++;
    }

    return addr ? page + 1 : page;
}

/* returns the lower address of flash page "page" */
static uint32_t flash_page_to_addr(const stm32_info& info,int page)
{
    int i;
    uint32_t addr, *psize;

    addr = info.dev->fl_start;
    psize = info.dev->fl_ps;

    for (i = 0; i < page; i++) {
        addr += psize[0];
        if (psize[1])
            psize++;
    }

    return addr;
}


static binary_t* binary_init() {
    return (binary_t*)calloc(sizeof(binary_t), 1);
}


static hex_t* hex_init() {
    return (hex_t*)calloc(sizeof(hex_t), 1);
}
//O_RDONLY 以只读方式打开文件
//O_WRONLY 以只写方式打开文件
//O_RDWR 以可读写方式打开文件. 上述三种旗标是互斥的, 也就是不可同时使用, 但可与下列的旗标利用OR(|)运算符组合.
//O_CREAT 若欲打开的文件不存在则自动建立该文件.
//O_EXCL 如果O_CREAT 也被设置, 此指令会去检查文件是否存在. 文件若不存在则建立该文件, 否则将导致打开文件错误. 此外, 若O_CREAT 与O_EXCL 同时设置, 并且欲打开的文件为符号连接, 则会打开文件失败.
//O_NOCTTY 如果欲打开的文件为终端机设备时, 则不会将该终端机当成进程控制终端机.
//O_TRUNC 若文件存在并且以可写的方式打开时, 此旗标会令文件长度清为0, 而原来存于该文件的资料也会消失.
//O_APPEND 当读写文件时会从文件尾开始移动, 也就是所写入的数据会以附加的方式加入到文件后面.
//O_NONBLOCK 以不可阻断的方式打开文件, 也就是无论有无数据读取或等待, 都会立即返回进程之中.
//O_NDELAY 同O_NONBLOCK.
//O_SYNC 以同步的方式打开文件.
//O_NOFOLLOW 如果参数pathname 所指的文件为一符号连接, 则会令打开文件失败.
//O_DIRECTORY 如果参数pathname 所指的文件并非为一目录, 则会令打开文件失败。注：此为Linux2. 2 以后特有的旗

//S_IRWXU00700 权限, 代表该文件所有者具有可读、可写及可执行的权限.
//S_IRUSR 或S_IREAD, 00400 权限, 代表该文件所有者具有可读取的权限.
//S_IWUSR 或S_IWRITE, 00200 权限, 代表该文件所有者具有可写入的权限.
//S_IXUSR 或S_IEXEC, 00100 权限, 代表该文件所有者具有可执行的权限.
//S_IRWXG 00070 权限, 代表该文件用户组具有可读、可写及可执行的权限.
//S_IRGRP 00040 权限, 代表该文件用户组具有可读的权限.
//S_IWGRP 00020 权限, 代表该文件用户组具有可写入的权限.
//S_IXGRP 00010 权限, 代表该文件用户组具有可执行的权限.
//S_IRWXO 00007 权限, 代表其他用户具有可读、可写及可执行的权限.
//S_IROTH 00004 权限, 代表其他用户具有可读的权限
//S_IWOTH 00002 权限, 代表其他用户具有可写入的权限.
//S_IXOTH 00001 权限, 代表其他用户具有可执行的权限.

static parser_err_t binary_open(binary_t *storage, const char *filename, const char write) {
    if (write) {
        if (filename[0] == '-')
            storage->fd = 1;
        else
            storage->fd = open(
                filename,
#ifndef __WIN32__
                O_WRONLY | O_CREAT | O_TRUNC ,
#else
                O_WRONLY | O_CREAT | O_TRUNC |O_BINARY | S_IREAD | S_IWRITE,
#endif
#ifndef __WIN32__
                S_IRUSR  | S_IWUSR | S_IRGRP | S_IROTH
#else
                S_IRUSR | IWUSR | S_IWGRP | S_IWOTH
#endif
            );
        storage->stat.st_size = 0;
    } else {
        if (filename[0] == '-') {
            storage->fd = 0;
        } else {
            if (stat(filename, &storage->stat) != 0)
                return PARSER_ERR_INVALID_FILE;
            storage->fd = open(filename,
#ifndef __WIN32__
                O_RDONLY
#else
                O_RDONLY | O_BINARY
#endif
            );
        }
    }

    storage->write = write;
    return storage->fd == -1 ? PARSER_ERR_SYSTEM : PARSER_ERR_OK;
}



static parser_err_t hex_open(hex_t *storage, const char *filename, const char write) {
    if (write) {
        return PARSER_ERR_RDONLY;
    } else {
        char mark;
        int i, fd;
        uint8_t checksum;
        unsigned int c;
        uint32_t base = 0;
        unsigned int last_address = 0x0;

        fd = open(filename, O_RDONLY);
        if (fd < 0)
            return PARSER_ERR_SYSTEM;

        /* read in the file */

        while(read(fd, &mark, 1) != 0) {
            if (mark == '\n' || mark == '\r') continue;
            if (mark != ':')
                return PARSER_ERR_INVALID_FILE;

            char buffer[9];
            unsigned int reclen, address, type;
            uint8_t *record = NULL;

            /* get the reclen, address, and type */
            buffer[8] = 0;
            if (read(fd, &buffer, 8) != 8) return PARSER_ERR_INVALID_FILE;
            if (sscanf(buffer, "%2x%4x%2x", &reclen, &address, &type) != 3) {
                close(fd);
                return PARSER_ERR_INVALID_FILE;
            }

            /* setup the checksum */
            checksum =
                reclen +
                ((address & 0xFF00) >> 8) +
                ((address & 0x00FF) >> 0) +
                type;

            switch(type) {
                /* data record */
                case 0:
                    c = address - last_address;
                    storage->data = (uint8_t*)realloc(storage->data, storage->data_len + c + reclen);

                    /* if there is a gap, set it to 0xff and increment the length */
                    if (c > 0) {
                        memset(&storage->data[storage->data_len], 0xff, c);
                        storage->data_len += c;
                    }

                    last_address = address + reclen;
                    record = &storage->data[storage->data_len];
                    storage->data_len += reclen;
                    break;

                /* extended segment address record */
                case 2:
                    base = 0;
                    break;

                /* extended linear address record */
                case 4:
                    base = 0;
                    break;
            }

            buffer[2] = 0;
            for(i = 0; i < reclen; ++i) {
                if (read(fd, &buffer, 2) != 2 || sscanf(buffer, "%2x", &c) != 1) {
                    close(fd);
                    return PARSER_ERR_INVALID_FILE;
                }

                /* add the byte to the checksum */
                checksum += c;

                switch(type) {
                    case 0:
                        if (record != NULL) {
                            record[i] = c;
                        } else {
                            return PARSER_ERR_INVALID_FILE;
                        }
                        break;

                    case 2:
                    case 4:
                        base = (base << 8) | c;
                        break;
                }
            }

            /* read, scan, and verify the checksum */
            if (
                read(fd, &buffer, 2 ) != 2 ||
                sscanf(buffer, "%2x", &c) != 1 ||
                (uint8_t)(checksum + c) != 0x00
            ) {
                close(fd);
                return PARSER_ERR_INVALID_FILE;
            }

            switch(type) {
                /* EOF */
                case 1:
                    close(fd);
                    return PARSER_ERR_OK;

                /* address record */
                case 4:	base = base << 12;
                case 2: base = base << 4;
                    /* Reset last_address since our base changed */
                    last_address = 0;

                    /* Only assign the program's base address once, and only
                     * do so if we haven't seen any data records yet.
                     * If there are any data records before address records,
                     * the program's base address must be zero.
                     */
                    if (storage->base == 0 && storage->data_len == 0) {
                        storage->base = base;
                        break;
                    }

                    /* we cant cope with files out of order */
                    if (base < storage->base) {
                        close(fd);
                        return PARSER_ERR_INVALID_FILE;
                    }

                    /* if there is a gap, enlarge and fill with 0xff */
                    unsigned int len = base - storage->base;
                    if (len > storage->data_len) {
                        storage->data = (uint8_t*)realloc(storage->data, len);
                        memset(&storage->data[storage->data_len], 0xff, len - storage->data_len);
                        storage->data_len = len;
                    }
                    break;
            }
        }

        close(fd);
        return PARSER_ERR_OK;
    }
}


static parser_err_t binary_close(binary_t *storage) {
    if (storage->fd) close(storage->fd);
    free(storage);
    return PARSER_ERR_OK;
}

static parser_err_t hex_close(hex_t *storage) {
    if (storage) free(storage->data);
    free(storage);
    return PARSER_ERR_OK;
}

static unsigned int hex_size(hex_t *storage) {
    return storage->data_len;
}

static unsigned int binary_size(binary_t *storage) {
    return storage->stat.st_size;
}

static parser_err_t binary_read(binary_t *storage, uint8_t *data, unsigned int *len) {
    unsigned int left = *len;
    if (storage->write) return PARSER_ERR_WRONLY;

    ssize_t r;
    while(left > 0) {
        r = read(storage->fd, data, left);
        /* If there is no data to read at all, return OK, but with zero read */
        if (r == 0 && left == *len) {
            *len = 0;
            return PARSER_ERR_OK;
        }
        if (r <= 0) return PARSER_ERR_SYSTEM;
        left -= r;
        data += r;
    }

    *len = *len - left;
    return PARSER_ERR_OK;
}


static parser_err_t hex_read(hex_t *storage, uint8_t *data, unsigned int *len) {
    unsigned int left = storage->data_len - storage->offset;
    unsigned int get  = left > *len ? *len : left;

    memcpy(data, &storage->data[storage->offset], get);
    storage->offset += get;

    *len = get;
    return PARSER_ERR_OK;
}



static parser_err_t binary_write(binary_t *storage, uint8_t *data, unsigned int len) {
    if (!storage->write) return PARSER_ERR_RDONLY;

    ssize_t r;
    while(len > 0) {
        r = write(storage->fd, data, len);
        if (r < 1) return PARSER_ERR_SYSTEM;
        storage->stat.st_size += r;

        len  -= r;
        data += r;
    }

    return PARSER_ERR_OK;
}


static parser_err_t hex_write(hex_t *storage, uint8_t *data, unsigned int len) {
    return PARSER_ERR_RDONLY;
}


static inline const char* parser_errstr(parser_err_t err) {
    switch(err) {
        case PARSER_ERR_OK          : return "OK";
        case PARSER_ERR_SYSTEM      : return "System Error";
        case PARSER_ERR_INVALID_FILE: return "Invalid File";
        case PARSER_ERR_WRONLY      : return "Parser can only write";
        case PARSER_ERR_RDONLY      : return "Parser can only read";
        default:
            return "Unknown Error";
    }
}

#include "simplesignal.hpp"
using namespace std;
using namespace serial;


namespace stm32{

	class STM32BootLoader
	{
	public:

        lsignal::signal<void(std::string,int)> sig;


		static STM32BootLoader* singleton(){
			return _impl;
		}
		static void initDriver(){
			_impl = new STM32BootLoader;
		}
		static void done(){	
			if(_impl){
				delete _impl;	
				_impl = NULL;
			}
		}

            stm32_err_t connect(const char * port_path, uint32_t baudrate,serial::bytesize_t bytesize = serial::eightbits, parity_t parity = serial::parity_none, serial::stopbits_t stopbits = serial::stopbits_one,
                                serial::flowcontrol_t flowcontrol = serial::flowcontrol_none);
            void disconnect();
        	static std::string getSDKVersion();

        	//stm32 bootloader
        	stm32_err_t stm32_send_init_seq(uint32_t timeout = DEFAULT_TIMEOUT);

        	stm32_err_t stm32_send_command(const uint8_t cmd);
        	stm32_err_t stm32_send_command_timeout(const uint8_t cmd, uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_send_command_adj(const uint8_t cmd,uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_get_version(stm32_info& info,uint32_t current_speed,uint32_t timeout = DEFAULT_TIMEOUT);

        	stm32_err_t stm32_get_ack_timeout(uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_get_ack();

        	stm32_err_t stm32_init(stm32_info& info, const char init, uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_guess_len_cmd(uint8_t cmd,uint8_t *data, unsigned int len,uint32_t timeout = DEFAULT_TIMEOUT);

        	stm32_err_t stm32_resync(uint32_t timeout = DEFAULT_TIMEOUT);

        	stm32_err_t stm32_read_memory(const stm32_info& info,uint32_t address,uint8_t *data, unsigned int len,uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_write_memory(const stm32_info& info,uint32_t address,const uint8_t *data, unsigned int len,uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_wunprot_memory(const stm32_info& info,uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_wprot_memory(const stm32_info& info,uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_runprot_memory(const stm32_info& info,uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_readprot_memory(const stm32_info& info,uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_mass_erase(const stm32_info& info, uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_pages_erase(const stm32_info& info, uint32_t spage, uint32_t pages,uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_erase_memory(const stm32_info& info,uint32_t spage, uint32_t pages,uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_run_raw_code(const stm32_info& info,uint32_t target_address,const uint8_t *code, uint32_t code_size,uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_go(const stm32_info& info,uint32_t address,uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_reset_device(const stm32_info& info,uint32_t timeout = DEFAULT_TIMEOUT);
        	stm32_err_t stm32_crc_memory(const stm32_info& info, uint32_t address,uint32_t length, uint32_t *crc,uint32_t timeout = DEFAULT_TIMEOUT);
        	static uint32_t stm32_sw_crc(uint32_t crc, uint8_t *buf, unsigned int len);
        	stm32_err_t stm32_crc_wrapper(const stm32_info& info,uint32_t address,uint32_t length, uint32_t *crc,uint32_t timeout = DEFAULT_TIMEOUT);

	protected:
		STM32BootLoader();
		virtual ~STM32BootLoader();
		stm32_err_t waitForData(size_t data_count,uint32_t timeout = -1, size_t * returned_size = NULL);
		stm32_err_t getData(uint8_t * data, size_t size);
		stm32_err_t sendData(const uint8_t * data, size_t size);


	public:
        	std::atomic<bool>     isConnected;

		enum {
			DEFAULT_TIMEOUT = 2000, 
		};
		Locker         _lock;
        Locker         serial_lock;

	private:
		static STM32BootLoader* _impl;
		serial::Serial *_serial;
		uint32_t _baudrate;
        serial::bytesize_t _bytesize;
        serial::parity_t	 _parity;
        serial::stopbits_t   _stopbits;
        serial::flowcontrol_t _flowcontrol;
        unsigned m_flags;

	};
}
