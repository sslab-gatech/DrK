#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <unistd.h>

#include <sys/mman.h>

#define __USE_GNU

#include "rdtsc.h"
#include "rtm.h"


// declare test function as mode_fn
typedef int (*mode_fn)(void *);

int test_calleax(void *addr)
{
    // call
    asm volatile("call *%0" : : "r"(addr) : "memory");
}

int test_callfunc(void *addr)
{
    // call as func
    ((int(*)())addr)();
}

int test_jmp(void *addr)
{
    // jmp
    asm volatile("jmp *%0" : : "r" (addr) : "memory");
}

int test_readmem(void *addr)
{
    // read access from ptr
    int a = *((int*)addr);
    return a;
}

int test_writemem(void *addr)
{
    // write access to ptr
    (*((int*)addr) = 0);
}

int test_ud2() {
    // trigger exception
    asm volatile("ud2");
}
int test_ill() {
    // illegal instruction
    asm volatile(".byte 0xc7; .byte 0xc8");
}

int test_movdqa(void* addr) {
    // break 32-byte alignment
    uint64_t addr_int = (uint64_t) addr;
    addr_int = (addr_int & 0xfffffffffffffff0) + 1;
    addr = (void*) addr_int;

    // access with movdqa (always trigger GP)
    asm volatile("movdqa (%0), %%xmm0" : : "r"(addr) : "memory");
}


// TSX RTM routine that measures one probe on the address
uint64_t _measure(void *addr, mode_fn fn)
{
  uint64_t beg = rdtsc_beg();

  if (_xbegin() == _XBEGIN_STARTED) {
    // try to probe the address with fn
    fn(addr);
    // will exit TSX RTM
    _xend(); // will not called
  } else {
    // TSX abort triggered!
    return rdtsc_end() - beg;
  }

  // should not reach here
  fprintf(stderr, "Not triggered\n");
}

// Iteratively probe the address with TSX RTM, and get the minimum timing
uint64_t measure(void *addr, int iter, mode_fn fn)
{
  uint64_t min = (uint64_t) -1;
  while (iter --) {
    uint64_t clk = _measure(addr, fn);
    if (clk < min) {
      min = clk;
    }
  }
  return  min;
}

// usage
void print_usage(char *prog)
{
  printf("[usage] %s [-a addr (in hex)] [-i times] [-m mode (readmem, jmp)]\n", prog);
  printf("For example: ./measure -a ffffffffc03e2000 -i 10000 -m jmp\n");
  printf("For example: ./measure -a ffffffffc03e2000 -i 1000 -m readmem\n");
}

// probing function selector
mode_fn get_mode_fn(char *mode)
{
  if (!strcmp(mode, "calleax"))
    return test_calleax;
  else if (!strcmp(mode, "callfunc"))
    return test_callfunc;
  else if (!strcmp(mode, "jmp"))
    return test_jmp;
  else if (!strcmp(mode, "readmem"))
    return test_readmem;
  else if (!strcmp(mode, "writemem"))
    return test_writemem;
  fprintf(stderr, "Unknown command: %s", optarg);
}

// map X/NX/U pages.
int global_variable = 0;
void* __attribute__((optimize("-O0"))) get_addr_for_type(char *arg)
{
  if(strcmp(arg, "x") == 0) {
    // map x
    void *mapped = mmap(NULL, 0x1000, 7, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    int *tmp = (int*)mapped;
    for(int i=0; i<0x400; ++i) {
      tmp[i] = 0x0b0f0b0f;
    }
    if(mapped == NULL) {
      fprintf(stderr, "Error on mapping x\n");
    }
    return mapped;
  }
  else if(strcmp(arg, "nx") == 0) {
    // map nx (non-writable)
    void *mapped = mmap(NULL, 0x1000, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    int *tmp = (int*)mapped;
    global_variable = tmp[0];
    if(mapped == NULL) {
      fprintf(stderr, "Error on mapping nx\n");
    }
    return mapped;
  }
  else if(strcmp(arg, "u") == 0) {
    // map u
    return (void*)(0xffffffffbffff000);
  }
}



int main(int argc, char **argv)
{
  char *mode = "test";
  void *addr = NULL;
  int iter = 10000;

  // get opts
  opterr = 0;
  char c;
  while ((c = getopt (argc, argv, "t:a:i:hm:")) != -1) {
    switch (c) {
    case 't':
      addr = get_addr_for_type(optarg);
      break;
    case 'a':
      addr = (void *)strtoull(optarg, NULL, 16);
      break;
    case 'i':
      iter = atoi(optarg);
      break;
    case 'm':
      mode = strdup(optarg);
      break;
    case 'h':
      print_usage(argv[0]);
      exit(0);
    default:
      print_usage(argv[0]);
      exit(1);
    }
  }

  if(strcmp(mode, "test") == 0) {
      // measure all for X/NX/U and M/U
      uint64_t x_jmp_clk = measure(get_addr_for_type("x"), iter, get_mode_fn("jmp"));
      uint64_t nx_jmp_clk = measure(get_addr_for_type("nx"), iter, get_mode_fn("jmp"));
      uint64_t m_write_clk = measure(get_addr_for_type("nx"), iter, get_mode_fn("writemem"));
      uint64_t u_write_clk = measure(get_addr_for_type("u"), iter, get_mode_fn("writemem"));
      uint64_t u_jmp_clk = measure(get_addr_for_type("u"), iter, get_mode_fn("jmp"));
      printf("{\n");
      printf(" 'x_jmp_clk':%" PRIu64 ",\n", x_jmp_clk);
      printf(" 'nx_jmp_clk':%" PRIu64 ",\n", nx_jmp_clk);
      printf(" 'u_jmp_clk':%" PRIu64 ",\n", u_jmp_clk);
      printf(" 'm_write_clk':%" PRIu64 ",\n", m_write_clk);
      printf(" 'u_write_clk':%" PRIu64 ",\n", u_write_clk);
      printf(" 'iter': %d,\n", iter);
      printf("}\n");
      exit(0);
  }

  // measure an address
  uint64_t clk = measure(addr, iter, get_mode_fn(mode));

  printf("{\n");
  printf(" 'addr': %p,\n", addr);
  printf(" 'iter': %d,\n", iter);
  printf(" 'time': %" PRIu64 ",\n", clk);
  printf(" 'mode': '%s',\n", mode);
  printf("}\n");

  return 0;
}
