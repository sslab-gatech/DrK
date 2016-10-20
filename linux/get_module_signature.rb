#!/usr/bin/env ruby

# This program reads kernel page table dump to get the ground truth information
# for kernel module mappings. The resulting file will be compared with
# the result from DrK attack to prove its accuracy.

require 'json'

class StateDeterminer
  def initialize
    @state = :exec
    @start_addr = 0xffffffff81000000
    @end_addr = 0x0
    @output = []
  end

  def set_start(start)
    @start_addr = start
  end

  def get_flag(state)
    case state
    when :exec
      return 'X'
    when :read_only
      return 'R'
    when :writable
      return 'W'
    end
    return 'DN'
  end

  def push_output
    start_addr = ("0x%016x" % @start_addr)
    end_addr = ("0x%016x" % @end_addr)
    str = "#{start_addr}-#{end_addr}\t#{get_flag(@state)}"
    @output << str
  end

  def print_output_as_file(filename)
    File.open(filename, 'w') do |f|
      @output.each do |x|
        f.puts(x)
      end
    end
  end

  def determine_state(an_array)
    addr = an_array[0]
    mark = an_array[1]
    state = get_state(mark)
    if(state != @state)
      if(state == :read_only || state == :exec || state == :writable)
        @end_addr = addr.to_i(16) & 0xfffffffffffff000
        self.push_output
        @state = state
        @start_addr = addr.to_i(16) & 0xfffffffffffff000

      else
        #handle others
        #@end_addr = addr
      end
    else
      #@end_addr = addr
    end
  end

  def get_state(state_mark)
    m = state_mark
    return :exec if m == 't' || m == 'T'
    return :read_only if m == 'r' || m == 'R'
    return :read_only if m == 'b' || m == 'B'
    return :read_only if m == 'd' || m == 'D'
    return :dont_know
  end
end

# get kallsyms
system "sudo cp /proc/kallsyms ./"

# sort kallsyms
kallsyms = nil
File.open("kallsyms", 'r') do |f|
  kallsyms = f.readlines.map{|x| x.strip.split}.sort{|x,y| x[0]<=>y[0]}
end

sd = StateDeterminer.new
sd.set_start(0xffffffffc0000000)
modules = kallsyms.select{|x| x[0].to_i(16) > 0xffffffffbfffffff}
module_name_dict = {}
modules.each do |x|
  base_page_addr = x[0].to_i(16) & 0xfffffffffffff000
  module_name = x[3].scan(/\[([^\]]+)\]/).flatten[0]
  module_name_dict[base_page_addr] = module_name
end


modules.each do |x|
  sd.determine_state x
end

# get kernel page table.
system("sudo cp /sys/kernel/debug/kernel_page_tables kpt; sudo chmod 644 ./kpt")
kpt = nil
File.open("kpt", 'r') do |f|
  kpt = f.readlines.map{|x| x.strip.split}
end

low_start = low_end = 0
vmalloc_start = vmalloc_end = 0
espfix_start = espfix_end = 0
efi = kernel_text_start = kernel_text_end = modules_start = modules_end = 0
kpt.each_with_index do |x,i|
  low_start = i+1 if(x[1] == 'Low')
  if x[1] == 'vmalloc()'
    low_end = i
    vmalloc_start = i+1
  end

  if x[1] == 'ESPfix'
    vmalloc_end = i
    espfix_start = i+1
  end

  if x[1] == 'EFI'
    espfix_end = i
    efi = i+1
  end

  if x[1] == 'High'
    kernel_text_start = i+1
  end

  if x[1] == 'Modules'
    kernel_text_end = i
    modules_start = i+1
  end

  if x[1] == 'End'
    modules_end = i
  end
end

modules_map_pt = kpt[modules_start...modules_end]

module_outputs = []
module_signature_dict = {}
m_start = m_end = 0
pri_state = nil

idx = 0
modules_map_pt.each do |x|
  idx += 1
  addr = x[0].split('_')
  addr_base = addr[0].to_i(16)
  addr_bound = addr[0].to_i(16)
  permission = nil
  if x[-2] == 'x'
    permission = :exec
  elsif x[-2] == 'NX'
    permission = :read
  else
    permission = :unmap
  end
  if(m_start == 0)
    m_start = addr_base
    m_end = addr_bound
    pri_state = permission
    next
  end

  if permission == pri_state && (idx != modules_map_pt.length)
    m_end = addr_bound
  else
    m_end = addr_base
    # print out current permission
    addr_str = "0x%016x-0x%016x" % [m_start, m_end]
    perm_str = nil
    case pri_state
    when :exec
      perm_str = 'X'
    when :read
      perm_str = 'NX'
    when :unmap
      perm_str = 'U'
    end
    name = module_name_dict[m_start]
    size = "%16x" % (m_end - m_start)
    output_str = "#{addr_str} #{perm_str}"
    if name != nil
      if(module_signature_dict[name] == nil)
        module_signature_dict[name] = {}
      end
      module_signature_dict[name][perm_str] = size
      output_str += " #{name} #{size}"
    end
    module_outputs << output_str
    m_start = addr_base
    m_end = addr_base
  end
  pri_state = permission
end

# print output
File.open("modules_ground_truth.out", 'w') do |f|
  f.puts("Ground Truth Page Table Mappings")
  outputs = []
  module_outputs.each do |x|
    arr = x.split(' ')
    if arr[0].split('-')[0] == '0xffffffffc0000000'
      next
    end
    if arr.length > 2
      if arr[1] == 'NX'
        outputs << arr[0..1].join(' ')
      else
        outputs << arr[0...-1].join(' ')
      end
    else
      outputs << x
    end
  end
  f.puts outputs
end

data = module_outputs
data.map!{|x| x.strip.split}

dict_by_name = {}
dict_by_size = {}

data.length.times do |i|
  line = data[i]
  if line.length > 2
    perm = line[1]
    if perm == 'NX'
      next
    end
    name = line[2]
    x_size = line[3]
    m_size = data[i+1][3]

    size_key = "#{x_size} #{m_size}"
    if dict_by_size[size_key] == nil
      dict_by_size[size_key] = []
    end
    dict_by_size[size_key] << name
    dict_by_name[name] = size_key
  end
end

fd = open('modules_size.txt', 'w')
fd.puts "{"
keys = dict_by_size.keys
keys.each do |k|
  lists = dict_by_size[k]
  if lists.size < 6
    fd.puts "\t'#{k}' : #{lists.inspect},"
  end
end
fd.puts "}"
fd.close
