#ifndef WISH_FS_H
#define WISH_FS_H



#include <stdint.h>
#include <stddef.h>

#define WISH_FS_SEEK_SET    0       /* Seek from beginning of file.  */
#define WISH_FS_SEEK_CUR    1       /* Seek from current position.  */
#define WISH_FS_SEEK_END    2       /* Seek from end of file.  */

#define WISH_FS_FAIL -1

/* File handle: Note that this must be a signed type */
typedef int wish_file_t;
typedef uint16_t wish_mode_t;
typedef int32_t wish_offset_t;

wish_file_t wish_fs_open(const char *pathname);
int32_t wish_fs_read(wish_file_t fd, void* buf, size_t count);
int32_t wish_fs_write(wish_file_t fd, const void *buf, size_t count);
int32_t wish_fs_lseek(wish_file_t fd, wish_offset_t offset, int whence);
int32_t wish_fs_close(wish_file_t fd);
int32_t wish_fs_rename(const char *old_path, const char *new_path);
int32_t wish_fs_remove(const char* path);

/* Dependency injection */
void wish_fs_set_open(wish_file_t (*fn)(const char *path));
void wish_fs_set_read(int32_t (*fn)(wish_file_t fd, void* buf, size_t count));
void wish_fs_set_write(int32_t (*fn)(wish_file_t fd, const void* buf, size_t count));
void wish_fs_set_lseek(int32_t (*fn)(wish_file_t fd, wish_offset_t offset, int whence));
void wish_fs_set_close(int32_t (*fn)(wish_file_t fd));
void wish_fs_set_rename(int32_t (*fn)(const char *oldpath, const char *newpath));
void wish_fs_set_remove(int32_t (*fn)(const char *path));


#endif //WISH_FS_H
