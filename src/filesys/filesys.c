#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/palloc.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

static struct dir* get_dir(const char* file, char* file_name) {
  char *dir_cpy, *cur_cpy, *token, *save_ptr;
  struct inode* child_inode;
  struct dir* parent_dir = NULL;

  dir_cpy = palloc_get_page(PAL_ZERO);
  cur_cpy = palloc_get_page(PAL_ZERO);
  if(dir_cpy == NULL || cur_cpy == NULL) {
    goto done;
  }
  parent_dir = dir_open_root();
  if(parent_dir == NULL) 
    goto done;
  strlcpy(dir_cpy, file, strlen(file) + 1);
  if(dir_cpy[0] == '/') {  // absolute path
    token = strtok_r(dir_cpy, "/", &save_ptr);
    // printf("file: ");
    while(token != NULL) {
      // printf("/%s", token);
      strlcpy(file_name, token, strlen(token) + 1);
      if(!dir_lookup(parent_dir, token, &child_inode)) { // parent_dir is parent, token is new dir
        if((token = strtok_r(NULL, "/", &save_ptr)) == NULL) {
          break;
        }
        else {
          dir_close(parent_dir);
          parent_dir = NULL;
          goto done;
        }
      }
      token = strtok_r(NULL, "/", &save_ptr);
      if(token == NULL)
        goto done;
      dir_close(parent_dir);
      parent_dir = dir_open(child_inode);  // open next directory
      if(parent_dir == NULL) {
        goto done;
      }
    }
    // printf("\n");
  }
  else {  // relative path
    strlcpy(cur_cpy, thread_current()->cur_dir, strlen(thread_current()->cur_dir) + 1);
    // first get to directory of process
    // printf("parent_dir: %p\n", parent_dir);

    for(token = strtok_r(cur_cpy, "/", &save_ptr); token != NULL; 
      token = strtok_r(NULL, "/", &save_ptr)) {
      dir_lookup(parent_dir, token, &child_inode); // parent_dir is parent, token is new dir
      dir_close(parent_dir);
      parent_dir = dir_open(child_inode);  // open next directory
      if(parent_dir == NULL) {
        goto done;
      }
    }
    // then make new directory
    token = strtok_r(dir_cpy, "/", &save_ptr);
    while(token != NULL) {
      strlcpy(file_name, token, strlen(token) + 1);
      if(!dir_lookup(parent_dir, token, &child_inode)) { // parent_dir is parent, token is new dir
        if((token = strtok_r(NULL, "/", &save_ptr)) == NULL) {
          break;
        }
        else {
          dir_close(parent_dir);
          parent_dir = NULL;
          goto done;
        }
      }
      // save prev token
      token = strtok_r(NULL, "/", &save_ptr);
      if(token == NULL)
        goto done;
      dir_close(parent_dir);
      parent_dir = dir_open(child_inode);  // open next directory
      if(parent_dir == NULL) {
        goto done;
      }
    }
  }
  done:
    palloc_free_page(cur_cpy);
    palloc_free_page(dir_cpy);

  return parent_dir;
}

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
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
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size) 
{
  // look for directory in here instead of syscall 
  block_sector_t inode_sector = 0;
  char* file_name = palloc_get_page(PAL_ZERO);
  if(file_name == NULL)
    return false;
  struct dir *dir = get_dir(name, file_name);
  // printf("file name: %s, cur_dir: %s\n", file_name, thread_current()->cur_dir);
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size)
                  && dir_add (dir, file_name, inode_sector, false));

  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);
  // printf("file name: %s, success: %d\n", file_name, success);

  palloc_free_page(file_name);
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
  char* file_name = palloc_get_page(PAL_ZERO);
  if(file_name == NULL)
    return NULL;
  struct dir *dir = get_dir(name, file_name);
  struct inode *inode = NULL;

  if (dir != NULL) {
    dir_lookup (dir, file_name, &inode);
    if (dir_isdir(dir, file_name)) {
      palloc_free_page(file_name);
      dir_close (dir);
      return NULL;
    }
  }
  dir_close (dir);
  palloc_free_page(file_name);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name) 
{
  char* file_name = palloc_get_page(PAL_ZERO);
  if(file_name == NULL)
    return NULL;
  struct dir *dir = get_dir(name, file_name);
  bool success = dir != NULL && dir_remove (dir, file_name);
  dir_close (dir); 
  palloc_free_page(file_name);
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
