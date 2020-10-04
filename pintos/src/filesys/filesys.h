#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"

#include "devices/block.h"
#include "threads/synch.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

#define CACHE_SIZE 64           /* Number of entries in the buffer cache */

typedef struct cache_entry {
    block_sector_t sector;
    //char buffer[BLOCK_SECTOR_SIZE];
    char* buffer;
    bool empty;
    bool dirty;
    bool ref;

    struct lock entry_lock;
} cache_entry_t;

/* Block device that contains the file system. */
struct block *fs_device;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
struct file *filesys_open (const char *name);
bool filesys_remove (const char *name);

void cache_read(block_sector_t sector, void* buffer);
void cache_write(block_sector_t sector, const void* data);
cache_entry_t* find_cache_entry(block_sector_t sector, bool read);

cache_entry_t* find_entry_cache_eviction(block_sector_t sector, bool read);
cache_entry_t* find_matching_entry(block_sector_t sector);
cache_entry_t* find_empty_entry(void);

#endif /* filesys/filesys.h */
