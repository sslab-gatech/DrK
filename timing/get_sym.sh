#!/bin/sh
sudo cat /proc/kallsyms | grep "$1"
