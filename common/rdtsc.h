#pragma once

#include <stdint.h>

#define barrier() __asm__ __volatile__("": : :"memory")

static inline uint64_t __attribute__((__always_inline__))
rdtsc(void)
{
    uint32_t a, d;
    __asm __volatile("rdtsc" : "=a" (a), "=d" (d));
    return ((uint64_t) a) | (((uint64_t) d) << 32);
}

static inline uint64_t __attribute__((__always_inline__))
rdtsc_beg(void)
{
    // Don't let anything float into or out of the TSC region.
    // (The memory clobber on this is actually okay as long as GCC
    // knows that no one ever took the address of things it has in
    // registers.)
    barrier();
    // See the "Improved Benchmarking Method" in Intel's "How to
    // Benchmark Code Execution Times on Intel® IA-32 and IA-64
    // Instruction Set Architectures"
    uint64_t tsc;
#if defined(__x86_64__)
    // This generates tighter code than the __i386__ version
    //__asm __volatile("cpuid; rdtscp; shl $32, %%rdx; or %%rdx, %%rax"
    // use rdtscp rather than cpuid + rdtsc
    __asm __volatile("rdtscp; shl $32, %%rdx; or %%rdx, %%rax"
                     : "=a" (tsc)
                     : : "%rbx", "%rcx", "%rdx");
#elif defined(__i386__)
    uint32_t a, d;
    __asm __volatile("cpuid; rdtscp; mov %%eax, %0; mov %%edx, %1"
                     : "=r" (a), "=r" (d)
                     : : "%rax", "%rbx", "%rcx", "%rdx");
    tsc = ((uint64_t) a) | (((uint64_t) d) << 32);
#endif
    barrier();
    return tsc;
}

static inline uint64_t __attribute__((__always_inline__))
rdtsc_end(void)
{
    barrier();
    uint32_t a, d;
    //__asm __volatile("rdtscp; mov %%eax, %0; mov %%edx, %1; cpuid"
    // use rdtscp rather than cpuid + rdtsc
    __asm __volatile("rdtscp; mov %%eax, %0; mov %%edx, %1;"
                     : "=r" (a), "=r" (d)
                     : : "%rax", "%rbx", "%rcx", "%rdx");
    barrier();
    return ((uint64_t) a) | (((uint64_t) d) << 32);
}

uint64_t cpu_freq(void);
uint64_t rdtsc_overhead(double *stddev_out);
uint64_t cpu_freq_measured(void);
