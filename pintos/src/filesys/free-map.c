#include "filesys/free-map.h"
#include <bitmap.h>
#include <debug.h>
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"

#include "threads/synch.h"
#include "threads/malloc.h"

static struct file *free_map_file;   /* Free map file. */
static struct bitmap *free_map;      /* Free map, one bit per sector. */

struct lock free_map_lock;

/* Initializes the free map. */
void
free_map_init (void)
{
  free_map = bitmap_create (block_size (fs_device));
  if (free_map == NULL)
    PANIC ("bitmap creation failed--file system device is too large");
  bitmap_mark (free_map, FREE_MAP_SECTOR);
  bitmap_mark (free_map, ROOT_DIR_SECTOR);
  
  lock_init(&free_map_lock);
}

static bool allocate_one(int* num_allocated, block_sector_t* sectors_allocated, block_sector_t* sector) {

  lock_acquire(&free_map_lock);
  bool success = free_map_allocate(1, sector);
  if(!success) {
    /* If we fail to allocate, rollback our allocations */
    for(int i = 0; i < *num_allocated; i += 1) {
      bitmap_set(free_map, sectors_allocated[i], false);
    }

    free(sectors_allocated);
    free(num_allocated);
    lock_release(&free_map_lock);
    
    return false;
  }

  lock_release(&free_map_lock);
  sectors_allocated[*num_allocated] = *sector;
  *num_allocated += 1;

  static char zeroes[BLOCK_SECTOR_SIZE];
  cache_write(*sector, zeroes);
  
  return true;
}

/* Allocates CNT blocks, starting at START block in INODE. This function will allocate the indirect and doubly indirect pointers if needed */
/* Start represents the number of sectors the inode currently has and is used to index into the pointers */
bool free_map_allocate_nonconsec(int start, size_t cnt, struct inode_disk* inode_data) {

  /* Keep track of the current sectors that were allocated for rollback */
  block_sector_t* sectors_allocated = malloc(sizeof(block_sector_t) * (cnt + POINTERS_PER_SECTOR));
  int* num_allocated = malloc(sizeof(int));
  *num_allocated = 0;

  lock_acquire(&free_map_lock);
  size_t free_sectors = bitmap_count(free_map, 0, bitmap_size(free_map), false);
  if(free_sectors < cnt) {
    return false;
  }
  lock_release(&free_map_lock);

  int curr_index = start;

  while(cnt > 0) {
    block_sector_t* sector = malloc(sizeof(block_sector_t));
    bool success = allocate_one(num_allocated, sectors_allocated, sector);

    if(!success) {
      return false;
    }
    
    if(curr_index < NUM_DIRECT) {
      inode_data->direct_pointers[curr_index] = *sector;
    } else if(curr_index < NUM_DIRECT + POINTERS_PER_SECTOR) {
      /* If we currently do not have an indirect pointer allocated, allocate it, and another block for data */
      if(inode_data->indirect_pointer == -1) {
        inode_data->indirect_pointer = *sector;
        bool success = allocate_one(num_allocated, sectors_allocated, sector);

        if(!success) {
          return false;
        }
      }
      block_sector_t* indirect_data_blocks = malloc(sizeof(block_sector_t) * POINTERS_PER_SECTOR);
      cache_read(inode_data->indirect_pointer, indirect_data_blocks);

      int indirect_index = curr_index - NUM_DIRECT;
      indirect_data_blocks[indirect_index] = *sector;
      cache_write(inode_data->indirect_pointer, indirect_data_blocks);

    } else {
      /* Insert assignment for doubly indirect pointers */

      if(inode_data->doub_indirect_pointer == -1) {
        inode_data->doub_indirect_pointer = *sector;
        bool success = allocate_one(num_allocated, sectors_allocated, sector);

        if(!success) {
          return false;
        }

      }
      int doub_block = curr_index - NUM_DIRECT - POINTERS_PER_SECTOR;
      int doub_index = doub_block / POINTERS_PER_SECTOR;
      block_sector_t* doub_indirect_blocks = malloc(sizeof(block_sector_t) * POINTERS_PER_SECTOR);
      cache_read(inode_data->doub_indirect_pointer, doub_indirect_blocks);

      /* If this is the first block in this part of the doubly indirect sector, allocate a new indirect pointer */
      if(doub_block % POINTERS_PER_SECTOR == 0) {
        doub_indirect_blocks[doub_index] = *sector;
        cache_write(inode_data->doub_indirect_pointer, doub_indirect_blocks);

        bool success = allocate_one(num_allocated, sectors_allocated, sector);

        if(!success) {
          return false;
        }
      }
      /* Read in the indirect pointer, and assign the newly allocated data block */
      block_sector_t* indirect_data_blocks = malloc(sizeof(block_sector_t) * POINTERS_PER_SECTOR);
      cache_read(doub_indirect_blocks[doub_index], indirect_data_blocks);
      int indirect_index = (curr_index - NUM_DIRECT - POINTERS_PER_SECTOR) % POINTERS_PER_SECTOR;

      indirect_data_blocks[indirect_index] = *sector;
      cache_write(doub_indirect_blocks[doub_index], indirect_data_blocks);

    }
    cnt -= 1;
    curr_index += 1;

  }

  free(sectors_allocated);
  free(num_allocated);


  return true;
}

/* Allocates CNT consecutive sectors from the free map and stores
   the first into *SECTORP.
   Returns true if successful, false if not enough consecutive
   sectors were available or if the free_map file could not be
   written. */
bool
free_map_allocate (size_t cnt, block_sector_t *sectorp)
{
  block_sector_t sector = bitmap_scan_and_flip (free_map, 0, cnt, false);
  if (sector != BITMAP_ERROR
      && free_map_file != NULL
      && !bitmap_write (free_map, free_map_file))
    {
      bitmap_set_multiple (free_map, sector, cnt, false);
      sector = BITMAP_ERROR;
    }
  if (sector != BITMAP_ERROR)
    *sectorp = sector;
  return sector != BITMAP_ERROR;
}

/* Makes CNT sectors starting at SECTOR available for use. */
void
free_map_release (block_sector_t sector, size_t cnt)
{
  ASSERT (bitmap_all (free_map, sector, cnt));
  bitmap_set_multiple (free_map, sector, cnt, false);
  bitmap_write (free_map, free_map_file);
}

/* Opens the free map file and reads it from disk. */
void
free_map_open (void)
{
  free_map_file = file_open (inode_open (FREE_MAP_SECTOR));
  if (free_map_file == NULL)
    PANIC ("can't open free map");
  if (!bitmap_read (free_map, free_map_file))
    PANIC ("can't read free map");
}

/* Writes the free map to disk and closes the free map file. */
void
free_map_close (void)
{
  file_close (free_map_file);
}

/* Creates a new free map file on disk and writes the free map to
   it. */
void
free_map_create (void)
{
  /* Create inode. */
  if (!inode_create (FREE_MAP_SECTOR, bitmap_file_size (free_map)))
    PANIC ("free map creation failed");

  /* Write bitmap to file. */
  free_map_file = file_open (inode_open (FREE_MAP_SECTOR));
  if (free_map_file == NULL)
    PANIC ("can't open free map");
  if (!bitmap_write (free_map, free_map_file))
    PANIC ("can't write free map");
}
