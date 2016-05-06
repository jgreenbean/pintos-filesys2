#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "userprog/syscall.h"
#include "threads/synch.h"
#include <stdio.h>

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44
/* Maximum number of sectors per block. */
#define SECTORS_PER_BLOCK 128

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    block_sector_t indirect_block;      /* 2nd level indirection block. */
    uint32_t unused[125];               /* Not used. */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  if(size)
    return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
  else
    return 1;
}

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct lock inode_lock;             /* Create/Remove lock for this inode */
    struct lock rw_lock;                /* Read/Write lock for this inode*/
    struct inode_disk data;             /* Inode content. */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);

  if(pos - inode_length(inode) <= BLOCK_SECTOR_SIZE) {
    // get index block
    block_sector_t num_sectors = pos / BLOCK_SECTOR_SIZE;
    block_sector_t index_block = num_sectors / SECTORS_PER_BLOCK;
    // get data block
    block_sector_t data_block = num_sectors - (index_block * SECTORS_PER_BLOCK);
    block_sector_t* data = malloc(sizeof(block_sector_t) * SECTORS_PER_BLOCK);
    block_sector_t* index_block_sectors = malloc(sizeof(block_sector_t) * SECTORS_PER_BLOCK);
    if(data == NULL || index_block_sectors == NULL)
      exit(-1);

    block_read(fs_device, inode->data.indirect_block, index_block_sectors);
    block_read(fs_device, index_block_sectors[index_block], data);
    data_block = data[data_block];

    free(data);
    free(index_block_sectors);
    return data_block;
  }
  else
    return -1;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
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
  if(disk_inode != NULL) {
    static char zeros[BLOCK_SECTOR_SIZE];
    size_t sectors = bytes_to_sectors(length); // number of sectors for data
    size_t index_blocks = DIV_ROUND_UP(sectors, SECTORS_PER_BLOCK); // number of index blocks needed
    block_sector_t* index_block_sectors = malloc(BLOCK_SECTOR_SIZE);
    if(index_block_sectors == NULL)
      return success;

    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;

    size_t i, j;
    size_t limit;

    for(i = 0; i < index_blocks; i++) {
      if(sectors >= SECTORS_PER_BLOCK)
        limit = SECTORS_PER_BLOCK;
      else
        limit = sectors % SECTORS_PER_BLOCK;

      block_sector_t* data = malloc(BLOCK_SECTOR_SIZE);
      if(data == NULL)
        return success & 0;
      for(j = 0; j < limit; j++) {
        if(free_map_allocate(1, &data[j])) { // allocate map for actual data
          block_write(fs_device, data[j], zeros); // write to data block 
        }
      }
      if(free_map_allocate(1, &index_block_sectors[i])) { // allocate map for IB
        block_write(fs_device, index_block_sectors[i], data); // write to index block
      }
      free(data);
      sectors -= SECTORS_PER_BLOCK;
    }

    if(free_map_allocate(1, &disk_inode->indirect_block)) { // allocate map for indirect block
      block_write(fs_device, disk_inode->indirect_block, index_block_sectors); // write to indirect block
      block_write(fs_device, sector, disk_inode); // write inode to disk
      success = true; 
    }

    free(disk_inode);
    free(index_block_sectors);
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
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->inode_lock);
  lock_init(&inode->rw_lock);
  block_read (fs_device, inode->sector, &inode->data); 

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

/* Closes INODE and writes it to disk. (Does it?  Check code.)
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
      list_remove (&inode->elem);

      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);

          size_t sectors = bytes_to_sectors(inode->data.length);
          size_t index_blocks = DIV_ROUND_UP(sectors, SECTORS_PER_BLOCK);
          size_t i, j, limit;

          block_sector_t* data = malloc(BLOCK_SECTOR_SIZE);
          block_sector_t* index_block_sectors = malloc(BLOCK_SECTOR_SIZE);
          if(data == NULL || index_block_sectors == NULL)
            exit(-1);

          block_read(fs_device, inode->data.indirect_block, index_block_sectors);
          for(i = 0; i < index_blocks; i++) {
            block_read(fs_device, index_block_sectors[i], data);

            if(sectors >= SECTORS_PER_BLOCK)
              limit = SECTORS_PER_BLOCK;
            else
              limit = sectors % SECTORS_PER_BLOCK;
            sectors -= SECTORS_PER_BLOCK;
            for(j = 0; j < limit; j++) {
              free_map_release(data[j], 1);
            }
            free_map_release(index_block_sectors[i], 1);
          }
          free_map_release(inode->data.indirect_block, 1);

          free(data);
          free(index_block_sectors);
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
  lock_acquire(&inode->rw_lock);
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;
  if(offset + size > inode_length(inode)) {
    lock_release(&inode->rw_lock);
    return bytes_read;      
  }
  
  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length(inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0){
        break;
      }
      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
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
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);
  lock_release(&inode->rw_lock);
  return bytes_read;
}

bool inode_grow_file(struct inode* inode, block_sector_t new_sector) {
  // get last data block
  lock_acquire(&inode->rw_lock);
  block_sector_t last_sector = inode_length(inode) / BLOCK_SECTOR_SIZE; // last block sector
  block_sector_t index_block = last_sector / SECTORS_PER_BLOCK; // last index block sector
  block_sector_t data_block = last_sector - (index_block * SECTORS_PER_BLOCK); // last data block within last index block
  block_sector_t* index_block_sectors; // indirect block

  if(data_block == 0) {
    block_sector_t new_block_sector;

    // check conditions and allocate for new index block
    if(index_block == 0 || !free_map_allocate(1, &new_block_sector)) {
      lock_release(&inode->rw_lock);
      return false;
    }

    // add to indirect/index block
    block_sector_t* new_data = malloc(BLOCK_SECTOR_SIZE); // new block within new index block
    index_block_sectors = malloc(BLOCK_SECTOR_SIZE);
    if(new_data == NULL || index_block_sectors == NULL) {
      lock_release(&inode->rw_lock);
      return false;
    }

    block_read(fs_device, inode->data.indirect_block, index_block_sectors);
    // update new index block
    new_data[0] = new_sector;
    block_write(fs_device, new_block_sector, new_data);
    // update indirect block
    index_block_sectors[index_block] = new_block_sector;
    block_write(fs_device, inode->data.indirect_block, index_block_sectors);
    free(new_data);
    free(index_block_sectors);
  }
  else {
    block_sector_t* data = malloc(BLOCK_SECTOR_SIZE);
    index_block_sectors = malloc(BLOCK_SECTOR_SIZE);
    if(data == NULL || index_block_sectors == NULL) {
      lock_release(&inode->rw_lock);
      return false;
    }
    block_read(fs_device, inode->data.indirect_block, index_block_sectors);
    block_read(fs_device, index_block_sectors[index_block], data);
    data[data_block] = new_sector;
    block_write(fs_device, index_block_sectors[index_block], data);
    block_write(fs_device, inode->data.indirect_block, index_block_sectors);
    free(data);
    free(index_block_sectors);
  }
  lock_release(&inode->rw_lock);
  return true;
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
  bool grew_file = false;
  int rem_gap = 0;
  int gap = 0;

  if(inode->deny_write_cnt)
    return 0;

  if(offset > inode_length(inode)) {
    block_sector_t zero_sector;
    uint8_t* gap_buffer;

    int sec_file_size = inode_length(inode) % BLOCK_SECTOR_SIZE;
    rem_gap = offset - inode_length(inode) < BLOCK_SECTOR_SIZE - sec_file_size ? 
      offset - inode_length(inode) : BLOCK_SECTOR_SIZE - sec_file_size;

    // add zeros
    if(rem_gap + sec_file_size >= BLOCK_SECTOR_SIZE) {
      gap = offset - (rem_gap + inode_length(inode));
    }
    if(rem_gap > 0) {
      uint8_t* eof_buffer = malloc(BLOCK_SECTOR_SIZE);
      gap_buffer = malloc(BLOCK_SECTOR_SIZE);
      if(eof_buffer == NULL || gap_buffer == NULL)
        return bytes_written;
      memset(gap_buffer, 0, sec_file_size + rem_gap);
      block_sector_t last_block = byte_to_sector(inode, inode_length(inode));
      block_read(fs_device, last_block, eof_buffer);
      memcpy(gap_buffer, eof_buffer, sec_file_size);
      block_write(fs_device, last_block, gap_buffer);
      free(eof_buffer);
      free(gap_buffer);
      inode->data.length += rem_gap;
    }

    // initialize zero buffer
    gap_buffer = malloc(BLOCK_SECTOR_SIZE);
    if(gap_buffer == NULL)
      return bytes_written;
    memset(gap_buffer, 0, BLOCK_SECTOR_SIZE);

    while(gap / BLOCK_SECTOR_SIZE > 0) {
      if(!free_map_allocate(1, &zero_sector))
        break;
      if(!inode_grow_file(inode, zero_sector))
        break;

      block_write(fs_device, zero_sector, gap_buffer);
      inode->data.length += BLOCK_SECTOR_SIZE;
      gap -= BLOCK_SECTOR_SIZE;
    }
    free(gap_buffer);
  }

  while(size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx;
      if(offset >= inode_length(inode) && inode_length(inode) % BLOCK_SECTOR_SIZE == 0 && offset) { // if needed sectors > file sectors
        grew_file = true;
        
        // allocate free map and get sector for new data block
        if(!free_map_allocate(1, &sector_idx))
          break;
        if(!inode_grow_file(inode, sector_idx))
          break;
      }
      else { // sector can be found from offset
        sector_idx = byte_to_sector(inode, offset);
      }

      int sector_ofs = offset % BLOCK_SECTOR_SIZE;
      /* Bytes left in sector. */
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs; // offset in terms of sector

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < sector_left ? size : sector_left;
      if (chunk_size <= 0) // size <= 0 invalid
        break;

      block_sector_t chunk_sectors = DIV_ROUND_UP(chunk_size, BLOCK_SECTOR_SIZE); // size in bytes to sectors needed
      block_sector_t num_sectors = DIV_ROUND_UP(inode_length(inode), BLOCK_SECTOR_SIZE); // length in bytes to sectors
      if(num_sectors + chunk_sectors > SECTORS_PER_BLOCK * SECTORS_PER_BLOCK) // check if exceeds 8 MB
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
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
          if ((sector_ofs > 0 || chunk_size < sector_left) && !grew_file) { // If offset is in the middle of the sector
            block_read (fs_device, sector_idx, bounce);
          }
          else // if chunk size = sector left != 512 bytes, offset can't be 0
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      int growth_size = (chunk_size + offset) - inode->data.length;
      size_t actual_growth = growth_size > 0 ? growth_size : 0; 
      inode->data.length += actual_growth;
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);
  block_write(fs_device, inode->sector, &inode->data);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
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

/* Return the 'removed' value of a given inode*/
bool
inode_get_removed (const struct inode *inode)
{
  ASSERT(inode != NULL);
  return inode->removed;
}
