#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/malloc.h"

#include "filesys/filesys.h"
#include "lib/kernel/list.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "devices/input.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

#include "lib/user/syscall.h"


static void syscall_handler (struct intr_frame *);
file_map_node_t *find_file_mapping(struct list *file_lst, int fd);
bool is_valid_usrptr(void *inptr);

bool sys_create_handler(uint32_t *args);
bool sys_remove_handler(uint32_t *args);
int sys_open_handler(uint32_t *args);
int sys_file_size_handler(uint32_t *args);
int sys_read_handler(uint32_t *args);
int sys_write_handler(uint32_t *args);
void sys_seek_handler(uint32_t *args);
unsigned sys_tell_handler(uint32_t *args);
void sys_close_handler(uint32_t *args);
pid_t sys_exec_handler(uint32_t *args);
int sys_wait_handler(uint32_t *args);
void manual_exit(int exit_code);

wait_status_t* find_wait_status(pid_t tid);




// global lock for file system
//static struct lock fslock;


/* This function checks if the input pointer is valid */
bool is_valid_usrptr(void *inptr) {
  struct thread *current_thread = thread_current();
  int i;
  for (i=0; i<4; i++) {
    uint32_t *curptr = (uint32_t*) inptr;
    curptr = curptr + i;

    if (curptr == NULL || !is_user_vaddr(curptr)) {
      return false;
    }

    if (pagedir_get_page(current_thread->pagedir, curptr) == NULL) {
      return false;
    }
  }
  return true;
}



void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  //lock_init(&fslock);
}


// find file_map_node_t with the file descriptor fd
file_map_node_t *find_file_mapping(struct list *file_lst, int fd){
  struct list_elem* e;

  for(e = list_begin(file_lst); e != list_end(file_lst); e = list_next(e)) {
    file_map_node_t* file_node = list_entry(e, file_map_node_t, elem);
    if(file_node->file_descriptor == fd) {
      return file_node;
    }
  }

  return NULL;
}

bool sys_create_handler(uint32_t *args) {
  //lock_acquire(&fslock);

  char *file_name = (char *)args[1];
  unsigned initial_size = (unsigned)args[2];

  // check valid file_name
  if (!is_valid_usrptr(file_name)) {
    //lock_release(&fslock);
    manual_exit(-1);
  }

  // create file
  bool file_status = filesys_create(file_name, initial_size);
  //lock_release(&fslock);
  return file_status;
}

bool sys_remove_handler(uint32_t *args) {
  //lock_acquire(&fslock);

  char *file_name = (char *)args[1];
  
  // check valid file_name
  if (!is_valid_usrptr(file_name)) {
    //lock_release(&fslock);
    manual_exit(-1);
  }

  bool file_status = filesys_remove(file_name);
  //lock_release(&fslock);
  return file_status;
}


int sys_file_size_handler(uint32_t *args) {
  //lock_acquire(&fslock);

  // retrieve file with file descriptor
  int fd = (int)args[1];
  struct thread *current_thread = thread_current();
  lock_acquire(&current_thread->mapping_lock);
  file_map_node_t *file_node = find_file_mapping(&(current_thread->file_lst), fd);
  lock_release(&current_thread->mapping_lock);
  struct file *file_pointer = file_node->file_pointer;

  int length = file_length(file_pointer);
  
  //lock_release(&fslock);
  return length;
}


int sys_open_handler(uint32_t *args) {
  //lock_acquire(&fslock);

  char *file_name = (char *)args[1];

    // check valid file_name
  if (!is_valid_usrptr(file_name)) {
    //lock_release(&fslock);
    manual_exit(-1);
  }

  file_map_node_t *new_file_node = malloc(sizeof(file_map_node_t));


  // assign file descriptor
  struct thread *current_thread = thread_current();
  new_file_node->file_descriptor = current_thread->file_counter;
  current_thread->file_counter += 1;
  
  // open file pointer
  struct file *file_ = filesys_open(file_name);
  if (file_ == NULL) {
    //lock_release(&fslock);
    return -1;
  }
  new_file_node->file_pointer = file_;
  lock_acquire(&current_thread->mapping_lock);
  list_push_front(&(current_thread->file_lst), &(new_file_node->elem));
  lock_release(&current_thread->mapping_lock);

  //lock_release(&fslock);
  return new_file_node->file_descriptor;
}


void sys_close_handler(uint32_t *args) {
  //lock_acquire(&fslock);
  int fd = (int)args[1];
  struct thread *current_thread = thread_current();

  lock_acquire(&current_thread->mapping_lock);
  file_map_node_t *file_node = find_file_mapping(&(current_thread->file_lst), fd);
  lock_release(&current_thread->mapping_lock);

  if (file_node == NULL) {
    //lock_release(&fslock);
    return;
  }

  lock_acquire(&current_thread->mapping_lock);
  list_remove(&file_node->elem);
  lock_release(&current_thread->mapping_lock);

  free(file_node);
  //lock_release(&fslock);

}

int sys_read_handler(uint32_t *args) {
  //lock_acquire(&fslock);
  int fd = args[1];
  void* buf = (void *) args[2];
  unsigned size = args[3];
  struct thread *current_thread = thread_current();

  if(fd == 1) {
    //lock_release(&fslock);
    return 0;
  } else if (fd == 0) {
    int result = input_getc();
    //lock_release(&fslock);
    return result;
  } else {

    lock_acquire(&current_thread->mapping_lock);
    file_map_node_t *file = find_file_mapping(&(current_thread->file_lst), fd);
    lock_release(&current_thread->mapping_lock);

    if(file == NULL) {
      //lock_release(&fslock);
      return -1;
    }

    // check valid file_name
    if (!is_valid_usrptr(buf)) {
      //lock_release(&fslock);
      manual_exit(-1);
    }

    int bytes_read = (int) file_read(file->file_pointer, buf, size);
    //lock_release(&fslock);
    return bytes_read;
  }
  return -1; // should not reach here
}


int sys_write_handler(uint32_t *args) {
  //lock_acquire(&fslock);
  
  int fd = args[1];
  void *buf = (void *)args[2];
  unsigned size = args[3];
  struct thread *current_thread = thread_current();

  if (fd == 1) {
    putbuf((char*) buf, size);
    //lock_release(&fslock);
    return size;
  } 
  else 
  { 

    lock_acquire(&current_thread->mapping_lock);
    file_map_node_t *file = find_file_mapping(&(current_thread->file_lst), fd);
    lock_release(&current_thread->mapping_lock);

    if (file == NULL) {
      //lock_release(&fslock);
      return 0;
    }
    
    // check valid file_name
    if (!is_valid_usrptr(buf)) {
      //lock_release(&fslock);
      manual_exit(-1);
    }
    int bytes_written = (int)file_write(file->file_pointer, buf, size);
    //lock_release(&fslock);
    return bytes_written;
  }
}

void sys_seek_handler(uint32_t *args) {
  //lock_acquire(&fslock);
  int fd = args[1];
  off_t position = args[2];
  struct thread *current_thread = thread_current();
  if(fd == 1 || fd == 0 || fd == 2) {
    //lock_release(&fslock);
    printf("Cannot seek this file");
    return;
  }
  lock_acquire(&current_thread->mapping_lock);
  file_map_node_t* file = find_file_mapping(&(current_thread->file_lst), fd);
  lock_release(&current_thread->mapping_lock);

  if(file == NULL) {
    //lock_release(&fslock);
    printf("Cannot seek file");
    return;
  } else {
    file_seek(file->file_pointer, position);
  }

  //lock_release(&fslock);
}

unsigned sys_tell_handler(uint32_t *args) { 
  //lock_acquire(&fslock);
  int fd = args[1];
  struct thread *current_thread = thread_current();
  if (fd <= 2) {
    //lock_release(&fslock);
    printf("Cannot tell stdin, stdout, or stderr");
    return 0;
  } else {

    lock_acquire(&current_thread->mapping_lock);
    file_map_node_t* file = find_file_mapping(&(current_thread->file_lst), fd);
    lock_release(&current_thread->mapping_lock);
    if(file == NULL) {
      //lock_release(&fslock);
      printf("Cannot tell file");
      return 0;
    } 
    unsigned position = file_tell(file->file_pointer);
    //lock_release(&fslock);
    return position;
  }

}

pid_t sys_exec_handler(uint32_t *args) {
  char* cmd_line = (char*) args[1];
  if(!is_valid_usrptr(cmd_line)) {
    manual_exit(-1);
  }

  pid_t child_id = process_execute(cmd_line);

  return child_id;
}

int sys_wait_handler(uint32_t *args) {
  pid_t pid = args[1];
  int exit_code = process_wait(pid);

  return exit_code;
  
}


wait_status_t* find_wait_status(pid_t tid) {
  struct thread *current_thread = thread_current();
  struct list_elem *e;
  for(e = list_begin(&current_thread->wait_list); e != list_end(&current_thread->wait_list); e = list_next(e)) {
    wait_status_t *ws = list_entry(e, wait_status_t, elem);
    if (ws->tid == tid) {
      return ws;
    }
  }

  return NULL;
}


// manual exit thread with exit code
void manual_exit(int exit_code) {
  printf ("%s: exit(%d)\n", &thread_current ()->name, exit_code);
  thread_exit ();
}


static void
syscall_handler (struct intr_frame *f UNUSED)
{
  uint32_t* args = ((uint32_t*) f->esp);

  if (!is_valid_usrptr(args)) {
      manual_exit(-1);
  }

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */


  if (args[0] == SYS_EXIT){
      if (!is_valid_usrptr(args+4)) {
        // bad address of args[1]
        manual_exit(-1);
      }

      f->eax = args[1];

      struct thread *current_thread = thread_current();
      wait_status_t *ws = current_thread->wait_status;
      ws->exit_code = args[1];

      printf ("%s: exit(%d)\n", &thread_current ()->name, args[1]);
      thread_exit ();

  } else if (args[0] == SYS_OPEN) {
    int fd = sys_open_handler(args);
    f->eax = fd;
  } else if (args[0] == SYS_WRITE){
    int bytes_written = sys_write_handler(args);
    f->eax = bytes_written;
  } else if (args[0] == SYS_PRACTICE) {
    f->eax = args[1] + 1;
  } else if (args[0] == SYS_HALT) {
    shutdown_power_off();
  } else if (args[0] == SYS_SEEK) {
    sys_seek_handler(args);
  } else if(args[0] == SYS_TELL) {
    f->eax = sys_tell_handler(args);
  } else if (args[0] == SYS_CREATE) {
    f->eax = sys_create_handler(args);
  } else if (args[0] == SYS_REMOVE) {
    f->eax = sys_remove_handler(args);
  } else if (args[0] == SYS_CLOSE) {
    sys_close_handler(args);
  } else if (args[0] == SYS_READ) {
    f->eax =  sys_read_handler(args);
  } else if (args[0] == SYS_FILESIZE) {
    f->eax = sys_file_size_handler(args);
  } else if(args[0] == SYS_EXEC) {
    f->eax = sys_exec_handler(args);
  } else if(args[0] == SYS_WAIT) {
    f->eax = sys_wait_handler(args);
  }
}
