#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

#include "threads/synch.h"
#include "threads/malloc.h"
#include "devices/block.h"


/* Partition that contains the file system. */
struct block *fs_device;

cache_entry_t *cache[CACHE_SIZE];
struct lock cache_lock;
int clock_hand;

static void do_format (void);

void cache_read(block_sector_t sector, void* buffer);
void cache_write(block_sector_t sector, const void* data);
cache_entry_t* find_cache_entry(block_sector_t sector, bool read);
cache_entry_t* find_entry_cache_eviction(block_sector_t sector, bool read);
cache_entry_t* find_matching_entry(block_sector_t sector);
cache_entry_t* find_empty_entry(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
  /* Intitialize each entry in the buffer cache */
  /* We initialize each entry using malloc since we don't want these large structs stored in kernel stack */
  for(int i = 0; i < CACHE_SIZE; i += 1) {
    cache_entry_t* entry = malloc(sizeof(cache_entry_t));
    cache[i] = entry;
    entry->dirty = 0;
    entry->ref = 0;
    entry->sector = -1;
    entry->empty = 1;
    entry->buffer = malloc(sizeof(char) * BLOCK_SECTOR_SIZE);
    memset(entry->buffer, 0, BLOCK_SECTOR_SIZE);
    lock_init(&entry->entry_lock);

  }
  
  clock_hand = 0;
  lock_init(&cache_lock);
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();

  
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void)
{
  for(int i = 0; i < CACHE_SIZE; i += 1) {
    cache_entry_t* entry = cache[i];
    if(entry->dirty) {
      block_write(fs_device, entry->sector, entry->buffer);
    }
  }
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size)
{
  block_sector_t inode_sector = 0;
  struct dir *dir = dir_open_root ();
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size)
                  && dir_add (dir, name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *
filesys_open (const char *name)
{
  struct dir *dir = dir_open_root ();
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, name, &inode);
  dir_close (dir);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name)
{
  struct dir *dir = dir_open_root ();
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir);

  return success;
}

/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}


/* Check the sector is in our cache, and read the contents of the cache into our buffer */
/* Otherwise, read the contents from disk into the cache and then into the buffer */
void cache_read(block_sector_t sector, void* buffer) {
  cache_entry_t* entry = find_cache_entry(sector, true);
  memcpy(buffer, entry->buffer, BLOCK_SECTOR_SIZE);
  entry->ref = 1;
  lock_release(&entry->entry_lock);
}

/* Write DATA into our cache. Set the dirty bit to 1 so we can flush to disk during eviction */
void cache_write(block_sector_t sector, const void* buffer) {
  // find cache entry
  
  cache_entry_t* entry = find_cache_entry(sector, true);
  memcpy(entry->buffer, buffer, BLOCK_SECTOR_SIZE);
  entry->ref = 1;
  entry->dirty = 1;
  lock_release(&entry->entry_lock);
}

/* returns matching cache entry if found, NULL otherwise. This is not thread safe. Make sure to acquire cache lock before calling */
cache_entry_t* find_matching_entry(block_sector_t sector) {
  for (int i = 0; i < CACHE_SIZE; i += 1) {
    cache_entry_t* entry = cache[i];
    if(entry->sector == sector) {
      return entry;
    }
  }
  return NULL;
}

/* returns empty entry if found, NULL otherwise. Not thread safe */
cache_entry_t* find_empty_entry() {
  for(int i = 0; i < CACHE_SIZE; i += 1) {
    cache_entry_t* entry = cache[i];
    if(entry->empty) {
      return entry;
    }
  }
  return NULL;
}


/* find a buffer cache entry by evicting an old entry */
cache_entry_t* find_entry_cache_eviction(block_sector_t sector, bool read) {
  lock_acquire(&cache_lock);

  /* loop through cache to make sure matching sector doesn't exist */
  cache_entry_t* matching_entry = find_matching_entry(sector);
  if (matching_entry != NULL) {
    lock_release(&cache_lock);

    lock_acquire(&matching_entry->entry_lock);
    return matching_entry;
  }

  /* we keep looping until we find an empty buffer cache entry */
  while(true) {
    //current clock hand position
    clock_hand = clock_hand % CACHE_SIZE;
    cache_entry_t* entry = cache[clock_hand];
    /* acquire lock associated with cache[clock_hand] entry*/
    bool success = lock_try_acquire(&entry->entry_lock);

    if(!success) {
      clock_hand += 1;
      continue;
    }

    if(entry->ref) {
      entry->ref = 0;
    } else {
      /* if entry is dirty, we must flush it */
      if(entry->dirty) {
        block_write(fs_device, entry->sector, entry->buffer);
      }
      /* zero fill the current buffer cache entry */
      memset(entry->buffer, 0, BLOCK_SECTOR_SIZE);
      entry->empty = 0;
      entry->dirty = 0;
      entry->sector = sector;
      /* once we found an empty sector we must free the entry lock and the cache lock */
      lock_release(&cache_lock);

      if(read) {
        block_read(fs_device, sector, entry->buffer);
      }

      return entry;
    }
    lock_release(&entry->entry_lock);
    clock_hand++;
  }
}

/* Finds the cache entry corresponding to sector, or an empty entry if it doesn't exist */
cache_entry_t* find_cache_entry(block_sector_t sector, bool read) {
  lock_acquire(&cache_lock);
  cache_entry_t* found_entry = NULL;
  /* First look for the cache entry corresponding to sector */
  found_entry = find_matching_entry(sector);
  /* If no matching sector in cache, find an empty cache buffer */
  if(found_entry == NULL) {
    found_entry = find_empty_entry();
  }
  lock_release(&cache_lock);


  /* double look up to make sure things did not change */
  if(found_entry != NULL) {

    lock_acquire(&found_entry->entry_lock);
    if(found_entry->sector == sector) {
      return found_entry;
    }
    if(found_entry->empty) {
      found_entry->empty = 0;
      found_entry->sector = sector;
      memset(found_entry->buffer, 0, BLOCK_SECTOR_SIZE);

      /* If this is a read operation, we read from disk into the cache entry */
      if(read) {
        block_read(fs_device, sector, found_entry->buffer);
      }
      return found_entry;
    }

    /* This means the found entry was modified to either not be empty or have a different sector, so retry */
    lock_release(&found_entry->entry_lock);
    return find_cache_entry(sector, read);
  }


  /*if no empty cache entry, evict an old entry*/
  return find_entry_cache_eviction(sector, read);

}
