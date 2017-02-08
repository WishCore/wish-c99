/*
 * Wish file system abstraction layer
 *
 * This layer provides "normal" functions for reading and writing
 * sequential files on a file system or similar storage. Wish expects
 * a "posix-like" behaviour, so if you are working with bare flash
 * devices, you might need a filesystem on top (such as spiffs), or you
 * need to provide some extra functionality.
 *
 * The reference to an opened file is abstracted behind the wish_file_t
 * type. On systems with Posix-like functionality this should be
 * compatible with the concept of a file descripter, but on some other
 * systems where open files are described as pointers (such as a void*) 
 * it would perhaps be wise to create a simple "lookup table", and
 * use the index to the table instead as "pseudo-filedescriptor".
 *
 */
#include "wish_fs.h"
#include "wish_debug.h"


/* Variables for function pointers pointing to the actual functions
 * implementing the file system I/O. Each pointer has a setter function
 * of its own. */
static wish_file_t (*fs_open_fn)(const char *pathname);
static int32_t (*fs_read_fn)(wish_file_t fd, void* buf, size_t count);
static int32_t (*fs_write_fn)(wish_file_t fd, const void* buf, size_t count);
static wish_offset_t (*fs_lseek_fn)(wish_file_t fd, wish_offset_t offset, int whence);
static wish_offset_t (*fs_close_fn)(wish_file_t fd);
static int32_t (*fs_rename_fn)(const char *oldpath, const char *newpath);
static int32_t (*fs_remove_fn)(const char *path);

/* Implementations of the file system abstraction functions - they are
 * really just simple "call-throughs" for the function pointers which
 * points to actual system-dependent implementations of the functions */

wish_file_t wish_fs_open(const char *pathname) {
    if (fs_open_fn == NULL) {
        WISHDEBUG(LOG_CRITICAL, "wish_fs not initialised properly");
        return WISH_FS_FAIL;    
    }
    return fs_open_fn(pathname);
}

int32_t wish_fs_read(wish_file_t fd, void* buf, size_t count) {
    if (fs_read_fn == NULL) {
        WISHDEBUG(LOG_CRITICAL, "wish_fs not initialised properly");
        return WISH_FS_FAIL;        
    }
    return fs_read_fn(fd, buf, count);
}

int32_t wish_fs_write(wish_file_t fd, const void *buf, size_t count) {
    if (fs_write_fn == NULL) {
        WISHDEBUG(LOG_CRITICAL, "wish_fs not initialised properly");
        return WISH_FS_FAIL;
    }
    return fs_write_fn(fd, buf, count);
}

wish_offset_t wish_fs_lseek(wish_file_t fd, wish_offset_t offset, int whence) {
    if (fs_lseek_fn == NULL) {
        WISHDEBUG(LOG_CRITICAL, "wish_fs not initialised properly");
        return WISH_FS_FAIL;
    }
    return fs_lseek_fn(fd, offset, whence);
}

int32_t wish_fs_close(wish_file_t fd) {
    if (fs_close_fn == NULL) {
        WISHDEBUG(LOG_CRITICAL, "wish_fs not initialised properly");
        return WISH_FS_FAIL;
    }
    return fs_close_fn(fd);
}


int32_t wish_fs_rename(const char *old_path, const char *new_path) {
    if (fs_rename_fn == NULL) {
        WISHDEBUG(LOG_CRITICAL, "wish_fs not initialised properly");
        return WISH_FS_FAIL;
    }
    return fs_rename_fn(old_path, new_path);
}

int32_t wish_fs_remove(const char *path) {
    if (fs_remove_fn == NULL) {
        WISHDEBUG(LOG_CRITICAL, "wish_fs not initialised properly");
        return WISH_FS_FAIL;
    }
    return fs_remove_fn(path);
}



/* Dependency injection setter functions for the platform-dependent file
 * system functions */
void wish_fs_set_open(wish_file_t (*fn)(const char *path)) {
    fs_open_fn = fn;
}

void wish_fs_set_read(int32_t (*fn)(wish_file_t fd, void* buf, size_t count)) {
    fs_read_fn = fn;
}

void wish_fs_set_write(int32_t (*fn)(wish_file_t fd, const void* buf, size_t count)) {
    fs_write_fn = fn;
}

void wish_fs_set_lseek(int32_t (*fn)(wish_file_t fd, wish_offset_t offset, int whence)) {
    fs_lseek_fn = fn;
}

void wish_fs_set_close(int32_t (*fn)(wish_file_t fd)) {
    fs_close_fn = fn;

}

void wish_fs_set_rename(int32_t (*fn)(const char *oldpath, 
        const char *newpath)) {
    fs_rename_fn = fn;
}

void wish_fs_set_remove(int32_t (*fn)(const char *path)) {
    fs_remove_fn = fn;
}
