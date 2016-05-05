#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "pagedir.h"
#include "devices/shutdown.h"
#include "threads/synch.h"
#include "kernel/console.h"
#include "threads/palloc.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "lib/string.h"
#include "userprog/process.h"
#include "devices/input.h"
#include "threads/pte.h"
#include "filesys/inode.h"
#include "filesys/free-map.h"
#include "filesys/directory.h"
#include "threads/malloc.h"

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
    block_sector_t indirect_block;      /* 2nd level indirection block. */
    uint32_t unused[125];               /* Not used. */
  };

/* In-memory inode. */
struct inode 
  {
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* A directory. */
struct dir 
  {
    struct inode *inode;                /* Backing store. */
    off_t pos;                          /* Current position. */
  };

static void syscall_handler (struct intr_frame *);

void halt (void) NO_RETURN;
pid_t exec (const char *file);
int wait (pid_t);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
int read (int fd, void *buffer, unsigned length);
int write (int fd, const void *buffer, unsigned length);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
bool mkdir(const char *dir);
bool chdir(const char *dir);
bool isdir(int fd);
bool readdir (int fd, char *name);
int inumber (int fd);
void valid_pointer(const void *pointer);
bool is_valid(const void *pointer);

// Lock variable
static struct lock file_lock;
static struct lock exit_lock;

void syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_lock);
  lock_init(&exit_lock);
}

static struct dir* get_dir(const char* file, char* file_name) {
  char *dir_cpy, *token, *save_ptr;
  struct inode* child_inode;
  struct dir* parent_dir = NULL;

  dir_cpy = palloc_get_page(PAL_ZERO);
  // cur_cpy = palloc_get_page(PAL_ZERO);
  if(dir_cpy == NULL) {
    goto done;
  }

  strlcpy(dir_cpy, file, strlen(file) + 1);
  if(dir_cpy[0] == '/') {  // absolute path
    parent_dir = dir_open_root();
    if(parent_dir == NULL) 
      goto done;
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
  else {  // relative path
    // strlcpy(cur_cpy, thread_current()->cur_dir, strlen(thread_current()->cur_dir) + 1);
    // // first get to directory of process
    // for(token = strtok_r(cur_cpy, "/", &save_ptr); token != NULL; 
    //   token = strtok_r(NULL, "/", &save_ptr)) {
    //   dir_lookup(parent_dir, token, &child_inode); // parent_dir is parent, token is new dir
    //   dir_close(parent_dir);
    //   parent_dir = dir_open(child_inode);  // open next directory
    //   if(parent_dir == NULL) {
    //     goto done;
    //   }
    // }

    parent_dir = dir_reopen(thread_current()->cur_dir);

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
    // palloc_free_page(cur_cpy);
    palloc_free_page(dir_cpy);

  return parent_dir;
}



/* Returns the address of the page table entry for virtual
   address VADDR in page directory PD.
   If PD does not have a page table for VADDR, behavior depends
   on CREATE.  If CREATE is true, then a new page table is
   created and a pointer into it is returned.  Otherwise, a null
   pointer is returned. */
uint32_t* lookup_page (uint32_t *pd, const void *vaddr, bool create)
{
  uint32_t *pt, *pde;

  ASSERT (pd != NULL);

  /* Shouldn't create new kernel virtual mappings. */
  ASSERT (!create || is_user_vaddr (vaddr));

  /* Check for a page table for VADDR.
     If one is missing, create one if requested. */
  pde = pd + pd_no (vaddr);
  if (*pde == 0) 
    {
      if (create)
        {
          pt = palloc_get_page (PAL_ZERO);
          if (pt == NULL) 
            return NULL; 
      
          *pde = pde_create (pt);
        }
      else
        return NULL;
    }

  /* Return the page table entry. */
  pt = pde_get_pt (*pde);
  return &pt[pt_no (vaddr)];
}

static void
syscall_handler (struct intr_frame *f) 
{
  /*Jasmine Drove Here*/
  int status;
  const char *file;
  pid_t pid;
  unsigned initial_size;
  int fd;
  void *read_buffer;
  unsigned size;
  const char *write_buffer;
  unsigned position;
  int syscall;
  const char* dir;
  char* name;

  valid_pointer(f->esp);
  syscall = *(int *)(f->esp);

  switch(syscall) {
  	case(SYS_HALT):
  		halt();
  		break;
  	case(SYS_EXIT):
  		/*Read from stack once*/
      valid_pointer(f->esp + 4);
  		status = *(int *)(f->esp + 4);
  		exit(status);
  		break;
  	case(SYS_EXEC):
  		/*Read from stack to get file pointer, check if valid*/
      valid_pointer(f->esp + 4);
  		file = *(char **)(f->esp + 4);
  		f->eax = exec(file);
  		break;
  	case(SYS_WAIT):
  		/*Read from stack once*/
      valid_pointer(f->esp + 4);
  		pid = *(int *)(f->esp + 4);
  		f->eax = wait(pid);
  		break;
  	case(SYS_CREATE):
  		/*Read from stack twice, check if file is valid*/
      valid_pointer(f->esp + 4);
  		file = *(char **)(f->esp + 4);
      valid_pointer(f->esp + 8);
  		initial_size = *(unsigned *)(f->esp + 8);
  		f->eax = create(file, initial_size);
  		break;
  	case(SYS_REMOVE):
  		/*Read from stack once, check if file is valid*/
      valid_pointer(f->esp + 4);
  		file = *(char **)(f->esp + 4);
  		f->eax = remove(file);
  		break;
      /*Rebecca Drove Here*/
  	case(SYS_OPEN):
  		/*Read from stack once, check if file is valid*/
      valid_pointer(f->esp + 4);
      file = *(char **)(f->esp + 4);;
  		f->eax = open(file);
  		break;
  	case(SYS_FILESIZE):
  		/*Read from stack once*/
      valid_pointer(f->esp + 4);
  		fd = *(int *)(f->esp + 4);
  		f->eax = filesize(fd);
  		break;
  	case(SYS_READ):
  		/*Read from stack 3 times, check if buffer is valid*/
      valid_pointer(f->esp + 4);
  		fd = *(int *)(f->esp + 4);
      valid_pointer(f->esp + 8);
  		read_buffer = *(char**)(f->esp + 8);
      valid_pointer(f->esp + 12);
  		size = *(unsigned *)(f->esp + 12);
  		f->eax = read(fd, read_buffer, size);
  		break;
  	case(SYS_WRITE):
  		/*Read from stack 3 times, check if buffer is valid*/
      valid_pointer(f->esp + 4);
  		fd = *(int *)(f->esp + 4);
      valid_pointer(f->esp + 8);
  		write_buffer = *(char**)(f->esp + 8);
      valid_pointer(f->esp + 12);
  		size = *(unsigned *)(f->esp + 12);
  		f->eax = write(fd, write_buffer, size);
  		break;
  	case(SYS_SEEK):
  		/*Read from stack twice*/
      valid_pointer(f->esp + 4);
  		fd = *(int *)(f->esp + 4);
      valid_pointer(f->esp + 8);
  		position = *(unsigned *)(f->esp + 8);
  		seek(fd, position);
  		break;
  	case(SYS_TELL):
  		/*Read from stack once*/
      valid_pointer(f->esp + 4);
  		fd = *(int *)(f->esp + 4);
  		f->eax = tell(fd);
  		break;
  	case(SYS_CLOSE):
  		/*Read from stack once*/
      valid_pointer(f->esp + 4);
  		fd = *(int *)(f->esp + 4);
  		close(fd);
  		break;
    case(SYS_MKDIR):
      valid_pointer(f->esp + 4);
      dir = *(char **)(f->esp + 4);
      f->eax = mkdir(dir);
      break;
    case(SYS_CHDIR):
      valid_pointer(f->esp + 4);
      dir = *(char **)(f->esp + 4);
      f->eax = chdir(dir);
      break;
    case(SYS_ISDIR):
      valid_pointer(f->esp + 4);
      fd = *(int*)(f->esp + 4);
      f->eax = isdir(fd);
      break;
    case(SYS_READDIR):
      valid_pointer(f->esp + 4);
      fd = *(int*)(f->esp + 4);
      valid_pointer(f->esp + 8);
      name = *(char**)(f->esp + 8);
      f->eax = readdir(fd, name);
      break;
    case(SYS_INUMBER):
      valid_pointer(f->esp + 4);
      fd = *(int*)(f->esp + 4);
      f->eax = inumber(fd);
      break;
  	default:
  		printf ("system call! %d \n", syscall);
  		thread_exit ();
  }
}


/*This Function checks if the given pointer
is valid. That is, check if the pointer is NULL, 
a not a user address, and if the address in virtual 
memory is unmapped.*/
bool is_valid(const void *pointer) {
  /*Charles Drove Here*/
  struct thread *cur_thread = thread_current();
  if(pointer == NULL || is_kernel_vaddr(pointer) ||
    lookup_page(cur_thread->pagedir, pointer, false) == NULL){
    return 0;
  }
  return 1;
}

void valid_pointer(const void *pointer) {
  /*Charles Drove Here*/
  if (!is_valid(pointer)) {
    exit(-1);
  }
}

void halt () {
  /*Charles Drove Here*/
	shutdown_power_off();
}

void exit (int status) {
  /*Jorge Drove Here*/
  struct zombie* z;
  struct list_elem* e;
  struct list_elem* next;
  struct zombie* reaped;
  struct thread* c;
  struct open_file *of;

  // if parent process hasn't already exited
  lock_acquire(&exit_lock);
  if(thread_current()->parent_process != NULL) {
    z = palloc_get_page(PAL_ZERO); // allocate
    z->exit_status = status;
    z->tid = thread_current()->tid;
    // add to parent's zombie list
    list_push_back(&thread_current()->parent_process->zombies, &z->z_elem);
    // remove from parent's children list 
    list_remove(&thread_current()->child_elem);
  }

  // set all children's parent to null
  for (e = list_begin (&thread_current()->children); 
    e != list_end (&thread_current()->children);
    e = list_next (e)) 
  {
    c = list_entry(e, struct thread, child_elem);
    c->parent_process = NULL;
  }
  lock_release(&exit_lock);

  /*Rebecca Drove Here*/
  // deallocate all its zombie children
  if(!list_empty(&thread_current()->zombies)) {
    e = list_begin (&thread_current()->zombies);
    while(e != list_end (&thread_current()->zombies)) {
      reaped = list_entry(e, struct zombie, z_elem);
      e = list_next(e);
      palloc_free_page(reaped);
    }
  } 

  printf("%s: exit(%d)\n", thread_current()->file_name, status);  

  sema_up(&thread_current()->process_sema);

  if(file_lock.holder == thread_current()) {
    lock_release(&file_lock);
  }

    // Closing and removing all open files
  if(!list_empty(&thread_current()->open_files)) {
    e = list_begin (&thread_current()->open_files);
    while(e != list_end (&thread_current()->open_files)) {
      of = list_entry(e, struct open_file, file_elem);
      next = list_next(e);
      close(of->fd);
      e = next;
    }
  } 

  // close the current process' file (executable)
  if(thread_current()->exec_file != NULL) {
    lock_acquire(&file_lock);
    file_close(thread_current()->exec_file);
    lock_release(&file_lock);
  }

  thread_exit();
}

pid_t exec (const char *file) {
  /*Jasmine Drove here*/
  valid_pointer(file);  
  process_execute(file);
  if(thread_current()->success) {
    return thread_current()->child_pid;
  }
  return PID_ERROR;
}

int wait (pid_t pid) {
  /*Jasmine Drove here*/
	return process_wait((tid_t) pid);
}

bool create (const char *file, unsigned initial_size){
  /*Rebecca Drove here*/
  lock_acquire(&file_lock);
  if (!is_valid(file)) {
    lock_release(&file_lock);
    exit(-1);
  }
  bool success = filesys_create(file, initial_size);
  lock_release(&file_lock);
  return success;
}

bool remove (const char *file){
  /*Jasmine Drove here*/
  lock_acquire(&file_lock);
  if (!is_valid(file)) {
    lock_release(&file_lock);
    exit(-1);
  } 
  printf("remove FILE: %s ", file);
  bool success = filesys_remove(file);          
  lock_release(&file_lock);
	return success;
}

int open (const char *file){
  /*Charles Drove Here*/
  struct file* f;
  struct open_file* of;
  struct dir* dir = NULL;
  struct inode* dir_inode;
  char* dir_name;
  // if (dir_name == NULL) {
  //   exit(-1);
  // }

  lock_acquire(&file_lock);
  // printf("file: %s\n", file);
  if (!is_valid(file)) {
    lock_release(&file_lock);
    exit(-1);
  }

  // of = palloc_get_page(PAL_ZERO);
  // if (of == NULL) {
  //   palloc_free_page(dir_name);
  //   lock_release(&file_lock);
  //   exit(-1);
  // }
  // of->fd = thread_current()->fd_cnt;

  f = filesys_open(file);

  if(f == NULL) {
    if(!strcmp(file, "/"))
      dir = dir_open_root();
    else {
      dir_name = palloc_get_page(PAL_ZERO);
      if(dir_name == NULL) {
        lock_release(&file_lock);
        return -1;
      }
      dir = get_dir(file, dir_name);
      if (dir == NULL) {
        //palloc_free_page(of);
        palloc_free_page(dir_name);
        lock_release(&file_lock);
        return -1;
      }
      dir_lookup(dir, dir_name, &dir_inode);
      dir_close(dir);
      dir = dir_open(dir_inode);
      if(dir == NULL) {
        //palloc_free_page(of);
        palloc_free_page(dir_name);
        lock_release(&file_lock);
        return -1;
      }
      palloc_free_page(dir_name);
    }
  //   of->d = dir;
  //   of->f = NULL;
  // } else {
  //   of->f = f;
  //   of->d = NULL;
  }

  of = palloc_get_page(PAL_ZERO);
  if (of == NULL) {
    // palloc_free_page(dir_name);
    lock_release(&file_lock);
    exit(-1);
  }
  of->f = f;
  of->d = dir;
  of->fd = thread_current()->fd_cnt;

  // printf("file: %s, fd: %d\n", file, thread_current()->fd_cnt);

  thread_current()->fd_cnt++;
  list_push_back(&thread_current()->open_files, &of->file_elem);
  // palloc_free_page(dir_name);
  lock_release(&file_lock);
	return of->fd;
}

int filesize (int fd){
  /*Jasmine Drove Here*/
  struct list_elem *e;
  struct open_file *of;
  int size = -1;

  if(fd < 2) {
    exit(-1);
  }

  lock_acquire(&file_lock);

  for (e = list_begin (&thread_current()->open_files); 
   e != list_end (&thread_current()->open_files);
   e = list_next (e)) 
  {
    of = list_entry(e, struct open_file, file_elem);
    if(fd == of->fd) {
      size = file_length(of->f);
      break;
    }
  }
  lock_release(&file_lock);
  return size;
}

int read (int fd, void *buffer, unsigned size){
  /*Charles Drove here*/
  int num_bytes = -1;
  struct list_elem* e;
  struct open_file* of;

  lock_acquire(&file_lock);
  if(!is_valid(buffer) || fd == 1) {
    lock_release(&file_lock);
    exit(-1);
  }
  if(!fd) {
    // read from keyboard
    num_bytes = input_getc();
    lock_release(&file_lock);
    return num_bytes;
  }
  else {
    for (e = list_begin (&thread_current()->open_files);
     e != list_end (&thread_current()->open_files);
     e = list_next (e))
    {
      of = list_entry(e, struct open_file, file_elem);       
      if(of->fd == fd) {
        num_bytes = file_read(of->f, buffer, size);
        break;
      }     
    }
  }
  lock_release(&file_lock);
  return num_bytes;
}

int write (int fd, const void *buffer, unsigned size) {
  /*Jorge Drove here*/
  // may have to break up buffer if too long
  int num_bytes = 0;
  struct list_elem *e;
  struct open_file *of;

  if(!fd) {
    exit(-1);
  }

  lock_acquire(&file_lock);
  if (!is_valid(buffer)) {
    lock_release(&file_lock);
    exit(-1);
  } 
  if(fd == 1) {
    while(size > 128) {
      size -= 128;
      if(strlen((char*) buffer) <= 128)
        break;
      putbuf(buffer, 128);
      buffer += 128;
    }
    putbuf(buffer, (int) size);
    num_bytes = written_chars();
  }
  /*Chalres Drove Here*/
  else {
    for (e = list_begin (&thread_current()->open_files); 
    e != list_end (&thread_current()->open_files);
    e = list_next (e)) 
    {
      of = list_entry(e, struct open_file, file_elem);
      if(of->fd == fd) {
        if(of->f == NULL) {
          lock_release(&file_lock);
          exit(-1);
        }
        if(!(of->f->deny_write)) {
          num_bytes = file_write(of->f, buffer, size); 
        }
        break;
      }
    }
  }
  lock_release(&file_lock);
	return num_bytes;
}

void seek (int fd, unsigned position){
  /*Jorge Drove here*/
  struct open_file *of;
  struct list_elem *e;

  if(fd < 2) {
    exit(-1);
  }

  lock_acquire(&file_lock);

  for(e = list_begin (&thread_current()->open_files); 
  e != list_end (&thread_current()->open_files);
  e = list_next (e)) 
  {
    of = list_entry(e, struct open_file, file_elem);
    if(of->fd == fd) {
      file_seek(of->f, position);
      break;
    }
  }
  lock_release(&file_lock);
}

unsigned tell (int fd){
  /*Charlesw Drove here*/
	off_t next_byte = 0; 
  struct list_elem* e;
  struct open_file* of; 

  if(fd < 2) { 
    exit(-1); 
  } 
  
  lock_acquire(&file_lock); 

  for (e = list_begin (&thread_current()->open_files); 
    e != list_end (&thread_current()->open_files); 
    e = list_next (e)) 
    { 
      of = list_entry(e, struct open_file, file_elem); 
      if(of->fd == fd) { 
        next_byte = file_tell(of->f); 
        break; 
      } 
    } 
  lock_release(&file_lock); 
  return next_byte;
}

void close (int fd) {
  /*Rebecca Drove here*/
  // special cases
  if (fd == 0 || fd == 1) {
    exit(-1);
  }

  lock_acquire(&file_lock);

  struct open_file *of;
  struct list_elem *e;
  bool found;

  found = false;
  for (e = list_begin (&thread_current()->open_files);
  e != list_end (&thread_current()->open_files);
  e = list_next (e))
  {
    of = list_entry(e, struct open_file, file_elem);
    if (of->fd == fd) {
      found = true;
      if(of->d == NULL) {
        if(of->f != NULL) {
          file_close(of->f);
          break;
        }
        else {
          lock_release(&file_lock);
          exit(-1);
        }
      }
      else {
        dir_close(of->d);
        break;
      }
    }
  }

  if (!found) {
    lock_release(&file_lock);
    exit(-1);
  }
  list_remove(e);
  palloc_free_page(of);
  lock_release(&file_lock);
}

bool mkdir(const char *dir) {
  char *dir_cpy, *token, *save_ptr, *child_tok;
  block_sector_t dir_sector;
  struct inode* child_inode;
  struct inode* new_inode;
  struct dir* parent_dir;
  struct dir* new_dir;
  bool success = true;

  valid_pointer(dir);
  if(!strcmp(dir, ""))
    return false;

  // printf("mkdir file: %s\n", dir);

  dir_cpy = palloc_get_page(PAL_ZERO);
  child_tok = palloc_get_page(PAL_ZERO);
  // cur_cpy = palloc_get_page(PAL_ZERO);
  if(dir_cpy == NULL || child_tok == NULL) {
    success = false;
    goto done;
  }
  strlcpy(dir_cpy, dir, strlen(dir) + 1);
  if(dir_cpy[0] == '/') {  // absolute path
    parent_dir = dir_open_root();
    if(parent_dir == NULL)
      goto done;
    token = strtok_r(dir_cpy, "/", &save_ptr);
    while(token != NULL) {
      strlcpy(child_tok, token, strlen(token) + 1);
      if(!dir_lookup(parent_dir, token, &child_inode)) { // parent_dir is parent, token is new dir
        if((token = strtok_r(NULL, "/", &save_ptr)) == NULL) {

          break;
        }
        else {
          dir_close(parent_dir);
          success = false;
          goto done;
        }
      }
      // save prev token
      token = strtok_r(NULL, "/", &save_ptr);
      if(token == NULL && dir_lookup(parent_dir, child_tok, &new_inode)) {
        success = false;
        dir_close(parent_dir);
        goto done;
      }
      dir_close(parent_dir);
      parent_dir = dir_open(child_inode);  // open next directory
      if(parent_dir == NULL) {
        success = false;
        goto done;
      }
    }
  }
  else {  // relative path
    // strlcpy(cur_cpy, thread_current()->cur_dir, strlen(thread_current()->cur_dir) + 1);
    // // first get to directory of process
    // for(token = strtok_r(cur_cpy, "/", &save_ptr); token != NULL; 
    //   token = strtok_r(NULL, "/", &save_ptr)) {
    //   dir_lookup(parent_dir, token, &child_inode); // parent_dir is parent, token is new dir
    //   dir_close(parent_dir);
    //   parent_dir = dir_open(child_inode);  // open next directory
    //   if(parent_dir == NULL) {
    //     success = false;
    //     goto done;
    //   }
    // }

    parent_dir = dir_reopen(thread_current()->cur_dir);

    // then make new directory
    token = strtok_r(dir_cpy, "/", &save_ptr);
    while(token != NULL) {
      strlcpy(child_tok, token, strlen(token) + 1);
      if(!dir_lookup(parent_dir, token, &child_inode)) { // parent_dir is parent, token is new dir
        // strlcpy(child_tok, token, strlen(token) + 1);
        if((token = strtok_r(NULL, "/", &save_ptr)) == NULL) {
          break;
        }
        else {
          dir_close(parent_dir);
          success = false;
          goto done;
        }
      }
      // save prev token
      token = strtok_r(NULL, "/", &save_ptr);
      if(token == NULL && dir_lookup(parent_dir, child_tok, &new_inode)) {
        dir_close(parent_dir);
        success = false;
        goto done;
      }
      dir_close(parent_dir);
      parent_dir = dir_open(child_inode);  // open next directory
      if(parent_dir == NULL) {
        ASSERT(0);
        success = false;
        goto done;
      }
    }
  }

  if(!free_map_allocate(1, &dir_sector))  // allocate new sector 
    goto done;

  dir_create(dir_sector, 2);  // create new directory
  dir_add(parent_dir, child_tok, dir_sector, true);  // add new directory to parent
  dir_lookup(parent_dir, child_tok, &new_inode);  // get new directory's inode
  new_dir = dir_open(new_inode);  // open new directory

  if (new_dir == NULL)
    ASSERT(0);

  dir_add(new_dir, ".", new_dir->inode->sector, true); // .
  dir_add(new_dir, "..", parent_dir->inode->sector, true); // ..

  // if(!strcmp(child_tok, "dir33"))
    printf("name: %s, inode: %p\n", child_tok, new_inode);

  dir_close(new_dir);
  dir_close(parent_dir);

  done:
//    palloc_free_page(cur_cpy);
    palloc_free_page(dir_cpy);
    palloc_free_page(child_tok);

  return success;
}

/*
Changes the current working directory of the process to dir, which may be 
relative or absolute. Returns true if successful, false on failure. 
*/
bool chdir(const char *dir) {
  char *dir_cpy, *token, *save_ptr;
  struct inode* child_inode;
  struct dir* parent_dir;
  bool success = true;
  // int cur_dir_len = 0;

  valid_pointer(dir);

  printf("new dir: %s\n", dir);

  dir_cpy = palloc_get_page(PAL_ZERO);
  if(dir_cpy == NULL) {
    success = false;
    goto done;
  }
  // absolute path
  if(dir[0] == '/') {  // absolute path
    parent_dir = dir_open_root();
    if(parent_dir == NULL) {
      ASSERT(0);
      goto done;
    }
    strlcpy(dir_cpy, dir, PGSIZE);
    for(token = strtok_r(dir_cpy, "/", &save_ptr); token != NULL; 
    token = strtok_r(NULL, "/", &save_ptr)) {
      if(!dir_lookup(parent_dir, token, &child_inode)) { // given absolute path is invalid
        success = false;
        dir_close(parent_dir);
        goto done;
      } 
      dir_close(parent_dir);
      parent_dir = dir_open(child_inode);  // open next directory
      if(parent_dir == NULL) {
        ASSERT(0);
        success = false;
        goto done;
      }
    }
  }
  else {
    // strlcpy(dir_cpy, thread_current()->cur_dir, strlen(thread_current()->cur_dir) + 1);
    // for(token = strtok_r(dir_cpy, "/", &save_ptr); token != NULL; 
    // token = strtok_r(NULL, "/", &save_ptr)) {
    //   dir_lookup(parent_dir, token, &child_inode); // parent_dir is parent, token is new dir
    //   dir_close(parent_dir);
    //   parent_dir = dir_open(child_inode);  // open next directory
    //   if(parent_dir == NULL) {
    //     success = false;
    //     goto done;
    //   }
    // }
    // palloc_free_page(dir_cpy);

    parent_dir = dir_reopen(thread_current()->cur_dir);

    strlcpy(dir_cpy, dir, PGSIZE);
    for(token = strtok_r(dir_cpy, "/", &save_ptr); token != NULL; 
    token = strtok_r(NULL, "/", &save_ptr)) {
      if(!dir_lookup(parent_dir, token, &child_inode)) { // given absolute path is invalid
        success = false;
        dir_close(parent_dir);
        goto done;
      } 
      dir_close(parent_dir);
      parent_dir = dir_open(child_inode);  // open next directory
      ASSERT(child_inode != NULL);
      if(parent_dir == NULL) {
        printf("\ninode open cnt: %d. inode: %p\n", child_inode->open_cnt, child_inode);
        success = false;
        goto done;
      }
    }

    // printf("child inode: %d\n", child_inode->sector);
    // cur_dir_len = strlen(thread_current()->cur_dir);
    // if(strcmp(thread_current()->cur_dir, "/")) {
    //   strlcpy(thread_current()->cur_dir + cur_dir_len, "/", 2);
    //   cur_dir_len++;
    // }
    // strlcpy(thread_current()->cur_dir + cur_dir_len, dir, strlen(dir) + 1);
    // printf("cur_dir: %s\n", thread_current()->cur_dir);
  }  

  dir_close(thread_current()->cur_dir);
  thread_current()->cur_dir = parent_dir;

  done:
    palloc_free_page(dir_cpy);
    // printf("\nSUCCESS: %d\n\n", success);
  return success;
}

bool isdir(int fd) {
  struct list_elem *e;
  struct open_file *of;
  bool found_fd = false;

  for (e = list_begin (&thread_current()->open_files); 
       e != list_end (&thread_current()->open_files); 
       e = list_next (e)) 
    { 
    of = list_entry(e, struct open_file, file_elem); 
    if(of->fd == fd) { 
      found_fd = true;
      if((of->f == NULL) && (of->d != NULL)) {
        return true;
      } 
      break;
    } 
  } 
  if(!found_fd)
    exit(-1);
  return false;
}


bool readdir (int fd, char *name) {
  struct list_elem *e;
  struct open_file *of;
  bool found_fd = false;
  bool success = false;

  for (e = list_begin (&thread_current()->open_files); 
       e != list_end (&thread_current()->open_files); 
       e = list_next (e)) 
    { 
    of = list_entry(e, struct open_file, file_elem); 
    if(of->fd == fd) { 
      found_fd = true;
      if(of->d == NULL) {
        exit(-1);
      } else {
        success = dir_readdir(of->d, name);
        break;        
      }
    } 
  } 
  if(!found_fd)
    exit(-1);
  return success;
}


int inumber (int fd) {
  struct list_elem *e;
  struct open_file *of;
  bool found_fd = false;
  int sector_num = 0;

  for (e = list_begin (&thread_current()->open_files); 
       e != list_end (&thread_current()->open_files); 
       e = list_next (e)) 
    { 
    of = list_entry(e, struct open_file, file_elem); 
    if(of->fd == fd) { 
      found_fd = true;
      if(of->d == NULL) {
        if(of->f != NULL) {
          sector_num = of->f->inode->sector;
          break;
        } else {
          printf("fails\n");
          exit(-1);
        }
      } else {
        sector_num = of->d->inode->sector;
        break;        
      }
    } 
  } 
  if(!found_fd)
    exit(-1);
  return sector_num;
}
