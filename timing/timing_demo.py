#!/usr/bin/env python

import multiprocessing as mp
import os
from subprocess import Popen, PIPE
import sys

from colors import *

# get nproc for spawning loops to avoid speedstep noise
NPROC = mp.cpu_count()

# run command and get its output as dict
def run_command(cmd_args, evaluate=True):
    p = Popen(cmd_args,
                stdout=PIPE,
                stderr=PIPE)
    out, err = p.communicate()
    if(evaluate):
        return eval(out)
    else:
        return out

# print measurement result for an address with mode (read / exec)
def print_result(address, run_mode, additional_msg=None, do_print=True):

    # run measurement
    result = run_command(["./measure", "-i" , "20000", "-a", address, "-m", run_mode])

    addr = result['addr']
    mode = result['mode']
    cycle = result['time']

    string = (BLACK + "Access with " + \
        RED + "%s" + \
        BLACK + " on " + \
        BLUE + "0x%016x" + \
        BLACK + ": took " + \
        MAGENTA + "%d " + BLACK + "cycles")% (mode, addr, cycle)

    if do_print:
        if additional_msg != None:
            print(additional_msg + string)
        else:
            print(string)

# get kernel symbol
def get_syms(symbol):
    out = run_command(["./get_sym.sh", symbol], evaluate=False)
    addr = out.split(" ")[0]
    return (out, addr)

def measure_address(address, status_str, mode_str, priv_str, add_str):
    print(NORMAL)
    print("Measuring timing for %s address (%s access)" % (status_str, mode_str))
    print("type ';' with newline to move on to next measure")
    print(BOLD)
    print(BLACK + "Target address: " + BOLD + BLUE + address +
    GREEN + " <- " + RED + priv_str + BLACK)
    print("")

    raw_input()
    a = ""
    while a == "":
        if mode_str == 'read':
            mode = 'readmem'
        else:
            mode = 'jmp'
        # to reduce speedstep noise, run twice..
        print_result(address, mode, additional_msg=add_str, do_print=False)
        print_result(address, mode, additional_msg=add_str)
        a = raw_input()




if __name__ == '__main__':
    if not os.path.exists('loop'):
        print("Error: Please run 'make' on ../common " +
                "to build necessary files.")
        quit()

    # kill all loops if exists
    os.system("killall -9 loop 2>/dev/null")

    # run loops for avoiding the noise from speedstep
    # (creating nproc/2 loops to make the processor to work as full throttle)
    for i in xrange(int(NPROC/2)):
        os.system("taskset -c %d ./loop&" % i)


    ## Mapped and Unmapped testing
    U_str = (RED + "Unmapped\t")
    NX_str = (MAGENTA + "Non-executable\t")
    M_str = (BLUE + "Mapped\t")
    X_str = (BLUE + "Executable\t")


    # measure unmapped (read)
    measure_address("0xffffffff00000000", RED+"Unmapped"+NORMAL, "read", "unmapped", U_str)

    print("")
    print("Try to get a mapped (non-executable) address")
    out, mapped_address = get_syms("__kstrtab_commit_creds")
    print(BLUE + out + BLACK)

    # measure mapped (read)
    measure_address(mapped_address, BLUE+"Mapped"+NORMAL, "read", "mapped", M_str)

    print("\n\nCompare the result, UN-MAPPED vs MAPPED")
    print_result("0xffffffff00000000", "readmem", do_print=False)
    print_result("0xffffffff00000000", "readmem", additional_msg=(RED+"Unmapped\t"))
    print_result(mapped_address, "readmem", do_print=False)
    print_result(mapped_address, "readmem", additional_msg=(BLUE+"Mapped\t\t"))


    raw_input()



    # measure unmapped (exec)
    measure_address("0xffffffff00000000", RED+"Unmapped"+NORMAL, "exec", "unmapped", U_str)
    # measure mapped but non-executable (exec)
    measure_address(mapped_address, MAGENTA+"Mapped, but Non-executable"+NORMAL, "exec", "non-executable", NX_str)

    print("")
    print("Try to get a mapped, executable address")
    out, exec_address = get_syms(" commit_creds")
    print(BLUE + out + BLACK)

    # measure mapped and executable (exec)
    measure_address(exec_address, BLUE+"Mapped and Executable"+NORMAL, "exec", "executable", X_str)

    print("\n\nCompare the result, Unmapped/Non-executable/Executable")
    print_result("0xffffffff00000000", "jmp", do_print=False)
    print_result("0xffffffff00000000", "jmp", additional_msg=U_str)
    print_result(mapped_address, "jmp", do_print=False)
    print_result(mapped_address, "jmp", additional_msg=NX_str)
    print_result(exec_address, "jmp", do_print=False)
    print_result(exec_address, "jmp", additional_msg=X_str)

    # kill all loops if exists
    os.system("killall -9 loop 2>/dev/null")
