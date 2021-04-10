from __future__ import print_function
import os
import sys

TRED = '\033[31m'
TYELLOW = '\033[33m'
ENDC = '\033[m'

SCRIPT_NAME = os.path.basename(__file__)
if os.geteuid() != 0:
    err_msg = " You need to be root to run " + script_name
    print(err_msg)
    sys.exit(5)

# main loop
ww_modes = {'2', '3', '6', '7'}
excl_flds = {'/proc/', '/dev/', '/sys/', '/tmp'}
root = "/"
delim = "#########################"
AUTHOR = "Fabrizio Pani"
EMAIL = "fabje AT centrum DOT cz"
LICENSE = "GPL v2"
curpos = ""
wwfiles = []

print(delim)
print(script_name)
print("Author: ", AUTHOR)
print("E-mail: ", EMAIL)
print("License:", LICENSE)
print("Looking for world writable files in ", root)
print("Please wait.  ")

try:
    for fld, subflds, os_files in os.walk(root, topdown=True):
        for os_file in os_files:
            pathfile = os.path.join(os.path.abspath(fld), os_file)
            valid_tree = True
            for i in excl_flds:
                if pathfile.find(i) == 0:
                    valid_tree = False

            pos = pathfile.rfind("/")
            oldpos = curpos
            curpos = pathfile[:pos +1]

            if valid_tree:
                if curpos != oldpos:
                    print("Searching in ", pathfile[:pos +1])
                try:
                    status = os.stat(pathfile)
                    mode = oct(status.st_mode)
                    o_mode = mode[len(mode) - 1]
                    if o_mode in ww_modes:
                        wwfiles.append(pathfile)
                except MemoryError:
                    print (TRED, "Out of memory exception.", ENDC)
                    sys.exit(11)
                except:
                    # all other errors, mainly I/O, are ignored
                    pass
            else:
                if curpos != oldpos:
                    print("Skipping ", pathfile[:pos +1])


except KeyboardInterrupt:
    err_msg = SCRIPT_NAME + ": exiting on keyboard signal."
    print(err_msg)
    sys.exit(127)


print("World Writable files found: ")
for wwfile in  wwfiles:
    print (TYELLOW, wwfile, ENDC)

print("Done")
print(delim)