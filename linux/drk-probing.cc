#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <csignal>

#include <map>
#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <sstream>

#include <inttypes.h>

#include <unistd.h>
#include <sys/time.h>

#include "rdtsc.h"
#include "rtm.h"

using namespace std;

// define probing functions
typedef int(*mode_fn)(void *);

int test_calleax(void *addr)
{
  asm volatile("call *%0" : : "r"(addr) : "memory");
  return 0;
}

int test_callfunc(void *addr)
{
  return ((int(*)())addr)();
}

int test_jmp(void *addr)
{
  asm volatile("jmp *%0" : : "r" (addr) : "memory");
  return 0;
}

int test_readmem(void *addr)
{
  volatile int a = *((int*)addr);
  return a;
}

int test_writemem(void *addr)
{
  (*((int*)addr) = 0);
  return 0;
}

// probing with with TSX RTM
uint64_t __attribute__((optimize("-O2"))) _measure(void *addr, mode_fn fn)
{
  while(1) {
    int result = 0;
    volatile uint64_t beg, end;
    beg = rdtsc_beg();
    if ( (result = _xbegin()) == _XBEGIN_STARTED) {
      // try probe here
      fn(addr);
      // should exit TSX RTM
      _xend(); // this is not called..
    }
    else {
      // TSX exception triggered!
      end = rdtsc_end();
      if(result != 0) {
        //fprintf(stderr, "WRONG! %d : %lld\n", result, (end - beg));
      } else {
        return end - beg;
      }
    }
  }

  // should not reach
  fprintf(stderr, "Not triggered\n");
  return (uint64_t)-1;
}

enum {
    PROBE_READ,
    PROBE_EXEC
};

uint64_t *iter_store;

// get minimum measurement from the probing
uint64_t __attribute__((optimize("-O2"))) measure(void *addr, int iter, mode_fn fn)
{
  uint64_t min = (uint64_t)-1;
  int initial_iter = iter;
  while (iter--) {
    uint64_t clk = _measure(addr, fn);
    if (clk < min) {
      min = clk;
    }
    iter_store[iter] = clk;
  }
  return min;
}

vector<string> result_vector;
vector<string> each_result_vector;
char buffer[256];

// change data into string output and insert into the vector
void insert_output(void* probe_addr, uint64_t r_min, uint64_t x_min) {
  sprintf(buffer, "%p %lld %lld\n", probe_addr, (long long)r_min, (long long)x_min);
  result_vector.push_back(string(buffer));
}

// probe memory region from base_addr to end_addr, by increment
void measure_range(void* base_addr, void* end_addr, uint64_t increment, int iter) {
  uint64_t probe_addr = (uint64_t)base_addr;
  uint64_t end_int = (uint64_t)end_addr;
  int g = 0;
  while (probe_addr < end_int) {
    g += 1;
    // Do usleep in 16 probes. This gives better accuracy.
    if(g<10 || g%16 == 0)
        usleep(0);
    uint64_t r_min = measure((void*)(probe_addr), iter, test_writemem);

    uint64_t x_min = measure((void*)(probe_addr), iter, test_jmp);
    // process output
    insert_output((void*)probe_addr, r_min, x_min);
    probe_addr += increment;
  }
}

// scan map region info. Scans from the base to the end by the increment.
typedef struct {
  uint64_t base_addr;
  uint64_t end_addr;
  uint64_t increment;
} addr_info;

// probe each addr info and write the result as a file
void run_each_experiment(int iter, vector<addr_info> *v_info, int exp_num, char *out_fn) {
  struct timeval tv_start, tv_end;
  gettimeofday(&tv_start, NULL);
  for (vector<addr_info>::iterator it = v_info->begin(); it != v_info->end(); ++it) {
    measure_range((void*)it->base_addr, (void*)it->end_addr, it->increment, iter);
  }
  gettimeofday(&tv_end, NULL);
  ostringstream oss;
  oss << out_fn << "_" << iter << "_" << exp_num;
  string output_fn = oss.str();
  cout << "Output file name: " << output_fn << endl;
  FILE *fp = fopen(output_fn.c_str(), "wb");
  if (fp == NULL) {
    printf("Error opening file\n");
  }
  unsigned long long usec = tv_end.tv_usec - tv_start.tv_usec;
  usec += (tv_end.tv_sec - tv_start.tv_sec) * 1000000;

  fprintf(fp, "Elapsed Time: %lld\n", usec);
  for (vector<string>::iterator it = result_vector.begin(); it != result_vector.end(); ++it) {
    fprintf(fp, "%s", it->c_str());
  }
  if(fp != NULL)
    fclose(fp);
}

// probe memory map region by addr_info.
void run_experiment(int iter, int repeat, vector<addr_info>* v_info, char* out_fn) {
  for (int i = 0; i < repeat; ++i) {
    result_vector.clear();
    each_result_vector.clear();
    result_vector.reserve(10000);
    each_result_vector.reserve(10000);
    run_each_experiment(iter, v_info, i, out_fn);
  }
}

void print_usage(char *prog)
{
  printf(
  "[usage] %s [-f input_file (scan)] [-o output_file] [-r repeat] [-i iterations]\n",
  prog);
}


int main(int argc, char **argv)
{
  // variables and default values.
  char *in_fn, *out_fn;
  int repeat;
  int iter = 10240;
  int test = 0;

  if(argc < 2) {
    print_usage(argv[0]);
    exit(1);
  }

  // get options.
  char c;
  while ((c = getopt (argc, argv, "t:i:f:r:o:h:")) != -1) {
    switch (c) {
    case 'f':
      in_fn = strdup(optarg);
      break;
    case 'o':
      out_fn = strdup(optarg);
      break;
    case 'i':
      iter = atoi(optarg);
      break;
    case 'r':
      repeat = atoi(optarg);
      break;
    case 't':
      test = atoi(optarg);
      break;
    case 'h':
      print_usage(argv[0]);
      exit(0);
    default:
      print_usage(argv[0]);
      exit(1);
    }
  }

  // allocate memory
  iter_store = new uint64_t[iter * 2];
  memset(iter_store, 0, sizeof(uint64_t) * iter);

  cout << "Running experiment for file " << in_fn << endl;
  cout << "Repeat experiment for " << repeat << " times.";
  cout << "Iteration: " << iter << endl;

  // read map info
  ifstream fin(in_fn);
  vector<addr_info> addr_to_test;

  char buf[256];

  // parse information file
  while(true) {
    fin.getline(buf, 256);
    string s(buf);
    if (s.length() == 0) {
      break;
    }
    addr_info i_addr;

    i_addr.base_addr = strtoull(s.c_str(), NULL, 16);

    fin.getline(buf, 256);
    string ss(buf);
    if (ss.length() == 0) {
      break;
    }
    i_addr.end_addr = strtoull(ss.c_str(), NULL, 16);
    fin.getline(buf, 256);
    string sss(buf);
    if (sss.length() == 0) {
      break;
    }
    i_addr.increment = strtoull(sss.c_str(), NULL, 16);
    cout << "BASE: " << i_addr.base_addr << " END: " << i_addr.end_addr << " INCR: " << i_addr.increment << endl;
    addr_to_test.push_back(i_addr);
  }

  // run probing with supplied information.
  run_experiment(iter, repeat, &addr_to_test, out_fn);
  return 0;
}

