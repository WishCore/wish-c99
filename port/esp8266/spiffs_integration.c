

#include <stdint.h>
#include "wish_fs.h"

/* spi_flash_* functions of Espressif SDK assume these odd definitions */
typedef uint32_t uint32;
typedef uint16_t uint16;


#include "spi_flash.h"
#include "spiffs.h"
#include "spiffs_integration.h"

/* The SPI HAL layer functions */
int32_t my_spi_read(uint32_t addr, uint32_t size, uint8_t *dst);
int32_t my_spi_write(uint32_t addr, uint32_t size, uint8_t *src);
int32_t my_spi_erase(uint32_t addr, uint32_t size);


#define LOG_PAGE_SIZE       256

static u8_t spiffs_work_buf[LOG_PAGE_SIZE*2];
static u8_t spiffs_fds[32*4];
static u8_t spiffs_cache_buf[(LOG_PAGE_SIZE+32)*4];

#define SPIFFS_HAL_DEBUG os_printf_plus


static spiffs fs;

void my_spiffs_mount() {
    spiffs_config cfg = { 0 };
#if 0
    /* NB: SPIFFS_SIGNLETON is defined, configuration is static! */
    //cfg.phys_size = 2*1024*1024; // use all spi flash
    cfg.phys_size = 8*SPI_FLASH_SEC_SIZE; // use just some spi flash
    cfg.phys_addr = 0x1da000; // start spiffs at start of spi flash
    cfg.phys_erase_block = SPI_FLASH_SEC_SIZE; // according to datasheet
    cfg.log_block_size = SPI_FLASH_SEC_SIZE; // let us not complicate things
    cfg.log_page_size = LOG_PAGE_SIZE; // as we said
#endif

    cfg.hal_read_f = my_spi_read;
    cfg.hal_write_f = my_spi_write;
    cfg.hal_erase_f = my_spi_erase;

    int res = SPIFFS_mount(&fs, &cfg, spiffs_work_buf, spiffs_fds, sizeof(spiffs_fds), spiffs_cache_buf, sizeof(spiffs_cache_buf), 0);
    SPIFFS_HAL_DEBUG("mount res: %d\n", res);
}


wish_file_t my_fs_open(const char *pathname) {
    spiffs_file fd = 0;
    fd = SPIFFS_open(&fs, pathname, SPIFFS_CREAT |  SPIFFS_RDWR, 0);
    if (fd < 0) {
        SPIFFS_HAL_DEBUG("Could not open file: %d\n\r", SPIFFS_errno(&fs));
    }
    return fd;
}

int32_t my_fs_read(wish_file_t fd, void* buf, size_t count) {
    int32_t ret = SPIFFS_read(&fs, fd, buf, count);
    if (ret < 0) {
        if (ret == SPIFFS_ERR_END_OF_OBJECT) {
            //SPIFFS_HAL_DEBUG("EOF encountered?\n\r");
            ret = 0;
        }
        else {
            SPIFFS_HAL_DEBUG("read errno %d\n\r", SPIFFS_errno(&fs));
        }
    }
    return ret;
}

int32_t my_fs_write(wish_file_t fd, const void *buf, size_t count) {
    int32_t ret = SPIFFS_write(&fs, fd, (void *)buf, count); 
    if (ret < 0) {
        SPIFFS_HAL_DEBUG("write errno %d\n", SPIFFS_errno(&fs));
    }
    return ret; 
}

wish_offset_t my_fs_lseek(wish_file_t fd, wish_offset_t offset, int whence) {
    int32_t ret = SPIFFS_lseek(&fs, fd, offset, whence);
    if (ret < 0) {
        SPIFFS_HAL_DEBUG("seek errno %d\n", SPIFFS_errno(&fs));
    }
    return ret;
}

int32_t my_fs_close(wish_file_t fd) {
    int32_t ret = SPIFFS_close(&fs, fd);
    return ret;
}

int32_t my_fs_rename(const char *oldpath, const char *newpath) {
    return SPIFFS_rename(&fs, oldpath, newpath);
}


int32_t my_fs_remove(const char *path) {
    return SPIFFS_remove(&fs, path);
}


int32_t my_spi_read(uint32_t addr, uint32_t size, uint8_t *dst) {
    uint32_t result = SPIFFS_OK;
    /* The address that is the next alingned one after addr */
    uint32_t alignedBegin = (addr + 3) & (~3);
    /* The address that is the next alingned one after addr + size */
    uint32_t alignedEnd = (addr + size) & (~3);
    if (alignedEnd < alignedBegin) {
        alignedEnd = alignedBegin;
    }

    /* Read the odd bytes that are immediately before the next aligned
     * address after start addr */
    if (addr < alignedBegin) {
        uint32_t nb = alignedBegin - addr;
        uint32_t tmp;
        if (spi_flash_read(alignedBegin - 4, &tmp, 4) != SPI_FLASH_RESULT_OK) {
            SPIFFS_HAL_DEBUG("Flash operation fail line %d\n\r", __LINE__);
            return SPIFFS_ERR_INTERNAL;
        }
        memcpy(dst, &tmp + 4 - nb, nb);
    }

    /* Read the bytes which are between the correctly aligned start and
     * end addresses */
    if (alignedEnd != alignedBegin) {
        if (spi_flash_read(alignedBegin, (uint32_t*) (dst + alignedBegin - addr),
                alignedEnd - alignedBegin) != SPI_FLASH_RESULT_OK) {
            SPIFFS_HAL_DEBUG("Flash operation fail line %d\n\r", __LINE__);
            return SPIFFS_ERR_INTERNAL;
        }
    }

    /* Read the odd bytes tat are immediately after the aligned address
     * before 'addr + size' */
    if (addr + size > alignedEnd) {
        uint32_t nb = addr + size - alignedEnd;
        uint32_t tmp;
        if (spi_flash_read(alignedEnd, &tmp, 4) != SPI_FLASH_RESULT_OK) {
            SPIFFS_HAL_DEBUG("Flash operation fail line %d\n\r", __LINE__);
            return SPIFFS_ERR_INTERNAL;
        }

        memcpy(dst + size - nb, &tmp, nb);
    }

    return result;
}

/* Don't set this smaller than 256 as it will corrupt things? */
static const int UNALIGNED_WRITE_BUFFER_SIZE = 256;

int32_t my_spi_write(uint32_t addr, uint32_t size, uint8_t *src) {

    uint32_t alignedBegin = (addr + 3) & (~3);
    uint32_t alignedEnd = (addr + size) & (~3);
    if (alignedEnd < alignedBegin) {
        alignedEnd = alignedBegin;
    }

    if (addr < alignedBegin) {
        uint32_t ofs = alignedBegin - addr;
        uint32_t nb = (size < ofs) ? size : ofs;
        uint8_t tmp[4] __attribute__((aligned(4))) = {0xff, 0xff, 0xff, 0xff};
        memcpy(tmp + 4 - ofs, src, nb);
        if (spi_flash_write(alignedBegin - 4, (uint32_t*) tmp, 4) != SPI_FLASH_RESULT_OK) {
            SPIFFS_HAL_DEBUG("Flash operation fail line %d\n\r", __LINE__);
            return SPIFFS_ERR_INTERNAL;
        }
    }

    if (alignedEnd != alignedBegin) {
        uint32_t* srcLeftover = (uint32_t*) (src + alignedBegin - addr);
        uint32_t srcAlign = ((uint32_t) srcLeftover) & 3;
        if (!srcAlign) {
            if (spi_flash_write(alignedBegin, (uint32_t*) srcLeftover,
                    alignedEnd - alignedBegin) != SPI_FLASH_RESULT_OK) {
                SPIFFS_HAL_DEBUG("Flash operation fail line %d\n\r", __LINE__);
                return SPIFFS_ERR_INTERNAL;
            }
        }
        else {
            uint8_t buf[UNALIGNED_WRITE_BUFFER_SIZE];
            uint32_t sizeLeft = 0;
            for (sizeLeft = alignedEnd - alignedBegin; sizeLeft; ) {
                size_t willCopy;
                if (sizeLeft < sizeof(buf)) {
                    willCopy = sizeLeft;
                }
                else {
                    willCopy = sizeof(buf);
                }
                memcpy(buf, srcLeftover, willCopy);

                if (spi_flash_write(alignedBegin, (uint32_t*) buf, willCopy) != SPI_FLASH_RESULT_OK) {
                    SPIFFS_HAL_DEBUG("Flash operation fail line %d\n\r", 
                        __LINE__);
                    return SPIFFS_ERR_INTERNAL;
                }

                sizeLeft -= willCopy;
                srcLeftover += willCopy;
                alignedBegin += willCopy;
            }
        }
    }

    if (addr + size > alignedEnd) {
        uint32_t nb = addr + size - alignedEnd;
        uint32_t tmp = 0xffffffff;
        memcpy(&tmp, src + size - nb, nb);

        if (spi_flash_write(alignedEnd, &tmp, 4) != SPI_FLASH_RESULT_OK) {
            SPIFFS_HAL_DEBUG("Flash operation fail line %d\n\r", __LINE__);
            return SPIFFS_ERR_INTERNAL;
        }
    }

    return SPIFFS_OK;
}

int32_t my_spi_erase(uint32_t addr, uint32_t size) {
    if ((size & (SPI_FLASH_SEC_SIZE - 1)) != 0 ||
        (addr & (SPI_FLASH_SEC_SIZE - 1)) != 0) {
        SPIFFS_HAL_DEBUG("Flash operation fail line %d\n\r", __LINE__);
    }
    const uint32_t sector = addr / SPI_FLASH_SEC_SIZE;
    const uint32_t sectorCount = size / SPI_FLASH_SEC_SIZE;
    uint32_t i = 0;
    for (i = 0; i < sectorCount; ++i) {
        if (spi_flash_erase_sector(sector + i) != SPI_FLASH_RESULT_OK) {
            SPIFFS_HAL_DEBUG("Flash operation fail line %d\n\r", __LINE__);
            return SPIFFS_ERR_INTERNAL;
        }
    }
    return SPIFFS_OK;
}

#if 0
/* SPIFFS port testing */

#define TEST_STR "Morjens 123...Morjens 123...Morjens 123...Morjens 123...Morjens 123...Morjens 123...Morjens 123...Morjens 123...Morjens 123...Morjens 123..."
/* Have a '/' in front of the filename, just because mkspiffs likes to
 * add one when creating filesystems */
#define TEST_FILENAME "/my_file"

void test_spiffs(void) {
    uint8_t buf[strlen(TEST_STR)] __attribute__((aligned(4)));
    spiffs_file fd __attribute__((aligned(4))) = { 0 };
    int ret = 0;
#if 1   /* Set to zero to disable writing of the file first */
    memcpy(buf, TEST_STR, strlen(TEST_STR));

    // Surely, I've mounted spiffs before entering here

    fd = SPIFFS_open(&fs, TEST_FILENAME, SPIFFS_CREAT | SPIFFS_TRUNC | SPIFFS_RDWR, 0);
    if (fd < 0) {
        SPIFFS_HAL_DEBUG("Bad fd (1) %d\n\r", SPIFFS_errno(&fs));
    }
    ret = SPIFFS_write(&fs, fd, buf, strlen(TEST_STR)); 
    if (ret < 0) {
        SPIFFS_HAL_DEBUG("write errno %d\n", SPIFFS_errno(&fs));
    }
    SPIFFS_HAL_DEBUG("write ret %d\n", ret);

    SPIFFS_close(&fs, fd); 
#endif
    fd = SPIFFS_open(&fs, TEST_FILENAME, SPIFFS_RDWR, 0);
    if (fd < 0) {
        SPIFFS_HAL_DEBUG("Bad fd (1)\n\r");
    }

    memset(buf, 0, strlen(TEST_STR));
    ret = SPIFFS_lseek(&fs, fd, strlen(TEST_STR) - 10 , SPIFFS_SEEK_SET);
    //ret = SPIFFS_lseek(&fs, fd, 10 , SPIFFS_SEEK_SET);
    if (ret < 0) {
        SPIFFS_HAL_DEBUG("seek errno %d\n", SPIFFS_errno(&fs));
    }
    SPIFFS_HAL_DEBUG("seek ret %d\n", ret);
 
    ret = SPIFFS_read(&fs, fd, buf, strlen(TEST_STR));
    if (ret < 0) {
        SPIFFS_HAL_DEBUG("read errno %d\n", SPIFFS_errno(&fs));
    }
    SPIFFS_HAL_DEBUG("read ret %d\n", ret);
    SPIFFS_close(&fs, fd);

    SPIFFS_HAL_DEBUG("--> %s <--\n", buf);
}
#endif


