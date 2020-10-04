#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44



/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}




/* This is the improved form of byte_to_sector, which takes into account direct, indirect,
   and doubly indirect pointers. It first checks direct, then indirect, then doubly indirect.
   The old function assumes a contiguous, fixed set of sectors to find blocks, which cannot be used with file growth.
   At each level:
      direct: NUM_DIRECT number of pointers, or block_sector_t (think of it as an array of indices, who each refer to a datablock in disk)
      indirect: represented by a block on disk at sector INDIRECT_POINTERS. Each block on disk contains 512 bytes,
                so each block on disk can contain 512 / 4 = 128 pointers. Think of this as an array of indices stored in disk
                at sector INDIRECT_POINTERS
      doubly indirect: starts with a block located at sector DOUB_INDIRECT_POINTERS, who contains 128 sector indexes, each referring to
                a block on disk who each contain 128 sector indexes that each refer to a data block.
                In total, there are 128 * 128 data blocks held by one doubly indirect pointer
                To calculate, where the block at pos is, we need to first index into the first block by dividing by 128. 
                then index into the next using mod 128. Work this out with an example of a block at 500.
      pos is guaranteed to be within length if we go through our pointers, otherwise we just return -1. 
      We are not expanding the inode in this function.
*/
static
block_sector_t byte_to_sector_expanded(struct inode_disk *inode_data, off_t pos) {
  ASSERT (inode_data != NULL);
  if (pos < inode_data->length) {
    int block_location = pos / BLOCK_SECTOR_SIZE;
    if(block_location < NUM_DIRECT) {
      /* If the block we are looking for is within our direct pointers */
      return inode_data->direct_pointers[block_location];
    } else if(block_location < NUM_DIRECT + POINTERS_PER_SECTOR) {
      /* If the block we are looking for is in our indirect pointers */
      /* First, we need to read the sector corresponding to our indirect pointer.
         This will result in 512 bytes being read, or 128 sector indexes
         Of these 128 sector indexes, we find which block by taking our block_location 
         and subtracting the number of direct pointers */

      block_sector_t* buffer = malloc(sizeof(block_sector_t) * POINTERS_PER_SECTOR);
      cache_read(inode_data->indirect_pointer, buffer);
      block_location = block_location - NUM_DIRECT;
      return buffer[block_location];
    } else {
      /* This means the data block is located in our doubly indirect block */
      /* We assume we have allocated enough blocks since our pos is less than our data length */
      block_location = block_location - NUM_DIRECT - POINTERS_PER_SECTOR;

    
      block_sector_t* indirect_pointers = malloc(sizeof(block_sector_t) * POINTERS_PER_SECTOR);
      cache_read(inode_data->doub_indirect_pointer, indirect_pointers);

      /* Finds the index sector to the indirect pointer */
      int indirect_sector_index = block_location / POINTERS_PER_SECTOR;
      block_sector_t indirect_sector = indirect_pointers[indirect_sector_index];

      /* Reads in the sector corresponding to indirect sector */
      block_sector_t* data_blocks = malloc(sizeof(block_sector_t) * POINTERS_PER_SECTOR);
      cache_read(indirect_sector, data_blocks);

      /* Index into the indirect sector, which is an array of sector indexes to data blocks */
      int index_to_data = block_location % POINTERS_PER_SECTOR;

      return data_blocks[index_to_data];
    }
  } else {
    return -1;
  }
}
/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */

/*
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  if (pos < inode->data.length) {
    return inode->data.start + pos / BLOCK_SECTOR_SIZE;
  } else {
    return -1;
  }
}
*/

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;
struct lock open_lock;

/* Initializes the inode module. */
void
inode_init (void)
{
  lock_init(&open_lock);
  list_init (&open_inodes);
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create (block_sector_t sector, off_t length)
{
  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);

      memset(disk_inode->direct_pointers, -1, NUM_DIRECT * sizeof(block_sector_t));
      disk_inode->indirect_pointer = -1;
      disk_inode->doub_indirect_pointer = -1;
      
      //disk_inode->length = length;
      disk_inode->length = 0;
      disk_inode->magic = INODE_MAGIC;


      /* Allocate nonconsecutive data blocks to populate pointers */
      success = free_map_allocate_nonconsec(0, sectors, disk_inode);

      if(success) {
        disk_inode->length = length;
        cache_write(sector, disk_inode);

        /* Once we've allocated the necessary blocks, write into them with zeros */
        size_t curr_secs = 0;
        while(curr_secs < sectors) {
          static char zeros[BLOCK_SECTOR_SIZE];
          block_sector_t curr = byte_to_sector_expanded(disk_inode, curr_secs * BLOCK_SECTOR_SIZE);
          cache_write(curr, zeros);

          curr_secs += 1;
        }

      }

      /*
      if (free_map_allocate (sectors, &disk_inode->start))
        {
          block_write (fs_device, sector, disk_inode);
          if (sectors > 0)
            {
              static char zeros[BLOCK_SECTOR_SIZE];
              size_t i;

              for (i = 0; i < sectors; i++)
                block_write (fs_device, disk_inode->start + i, zeros);
            }
          success = true;
        }
      */
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  lock_acquire(&open_lock);
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          lock_release(&open_lock);
          return inode;
        }
    }
    
  lock_release(&open_lock);

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  lock_acquire(&open_lock);
  list_push_front (&open_inodes, &inode->elem);
  lock_release(&open_lock);

  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;

  inode->num_writers = 0;
  lock_init(&inode->metadata_lock);
  lock_init(&inode->resize_lock);
  cond_init(&inode->deny_write_cond);

  cache_read(inode->sector, &inode->data);
  //block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      lock_acquire(&open_lock);
      list_remove (&inode->elem);
      lock_release(&open_lock);

      /* Deallocate blocks if removed. */
      if (inode->removed)
        {
          free_map_release (inode->sector, 1);

          int curr_block = 0;
          int num_blocks = bytes_to_sectors(inode->data.length);

          while(curr_block < num_blocks) {
            if(curr_block < NUM_DIRECT) {
              free_map_release(inode->data.direct_pointers[curr_block], 1);
            } else if(curr_block < NUM_DIRECT + POINTERS_PER_SECTOR) {
              int indirect_block_num = curr_block - NUM_DIRECT;
              block_sector_t* data_blocks = malloc(sizeof(block_sector_t) * POINTERS_PER_SECTOR);
              cache_read(inode->data.indirect_pointer, data_blocks);
              free_map_release(data_blocks[indirect_block_num], 1);

              if(indirect_block_num == POINTERS_PER_SECTOR - 1 || curr_block == num_blocks - 1) {
                free_map_release(inode->data.indirect_pointer, 1);
              }
            } else {
              int doub_block_num = curr_block - NUM_DIRECT - POINTERS_PER_SECTOR;
              block_sector_t* indirect_pointers = malloc(sizeof(block_sector_t) * POINTERS_PER_SECTOR);
              cache_read(inode->data.doub_indirect_pointer, indirect_pointers);

              /* Finds the index sector to the indirect pointer */
              int indirect_sector_index = doub_block_num / POINTERS_PER_SECTOR;
              block_sector_t indirect_sector = indirect_pointers[indirect_sector_index];

              /* Reads in the sector corresponding to indirect sector */
              block_sector_t* data_blocks = malloc(sizeof(block_sector_t) * POINTERS_PER_SECTOR);
              cache_read(indirect_sector, data_blocks);

              /* Index into the indirect sector, which is an array of sector indexes to data blocks */
              int index_to_data = doub_block_num % POINTERS_PER_SECTOR;
              
              free_map_release(data_blocks[index_to_data], 1);

              if(index_to_data == POINTERS_PER_SECTOR - 1 || curr_block == num_blocks - 1) {
                free_map_release(indirect_sector, 1);
              }

              if(curr_block == num_blocks - 1) {
                free_map_release(inode->data.doub_indirect_pointer, 1);
              }
            }

            curr_block += 1;
          }
          //free_map_release (inode->data.start,
          //                  bytes_to_sectors (inode->data.length));
        }

      free (inode);
    }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector_expanded(&inode->data, offset);
      //block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          //block_read (fs_device, sector_idx, buffer + bytes_read);
          cache_read(sector_idx, buffer + bytes_read);
        }
      else
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          //block_read (fs_device, sector_idx, bounce);
          cache_read(sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  lock_acquire(&inode->metadata_lock);
  if (inode->deny_write_cnt) {
    lock_release(&inode->metadata_lock);
    return 0;
  }
  
  

  size_t new_blocks_size = bytes_to_sectors(offset + size);
  size_t old_blocks_size = bytes_to_sectors(inode->data.length);

  lock_release(&inode->metadata_lock);

  int block_diff = new_blocks_size - old_blocks_size;

  /* For expanding file size */
  if(block_diff > 0) {

    lock_acquire(&inode->resize_lock);
    bool success = free_map_allocate_nonconsec(old_blocks_size, block_diff, &inode->data);
    lock_release(&inode->resize_lock);

    if(!success) {
      return 0;
    }

  }

  if(offset + size > inode->data.length) {
    lock_acquire(&inode->metadata_lock);
    inode->data.length = offset + size;
    lock_release(&inode->metadata_lock);
  }

  lock_acquire(&inode->metadata_lock);
  inode->num_writers += 1;
  lock_release(&inode->metadata_lock);

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */

      block_sector_t sector_idx = byte_to_sector_expanded(&inode->data, offset);
      //block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          //block_write (fs_device, sector_idx, buffer + bytes_written);
          cache_write(sector_idx, buffer + bytes_written);
        }
      else
        {
          /* We need a bounce buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            //block_read (fs_device, sector_idx, bounce);
            cache_read(sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          //block_write (fs_device, sector_idx, bounce);
          cache_write(sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  lock_acquire(&inode->metadata_lock);
  inode->num_writers -= 1;
  cond_signal(&inode->deny_write_cond, &inode->metadata_lock);
  lock_release(&inode->metadata_lock);

  
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode)
{
  lock_acquire(&inode->metadata_lock);
  while(inode->num_writers > 0) {
    cond_wait(&inode->deny_write_cond, &inode->metadata_lock);
  }
  inode->deny_write_cnt++;
  lock_release(&inode->metadata_lock);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode)
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

struct inode_disk get_inode_data(struct inode* inode) {
  return inode->data;
}
