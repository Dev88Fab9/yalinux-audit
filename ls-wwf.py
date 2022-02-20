from __future__ import print_function
import datetime
import os
import sys

TRED = '\033[31m'
TYELLOW = '\033[33m'
ENDC = '\033[m'

start_time = datetime.datetime.now()
SCRIPT_NAME = os.path.basename(__file__)
try:
    if os.geteuid() != 0:
        err_msg = " You need to be root to run {}".format(SCRIPT_NAME)
        print(err_msg)
        sys.exit(5)
except AttributeError:
       print("Unsupported OS or configuration!")
       sys.exit(1)

# main loop
WW_MODES = {'2', '3', '6', '7'}
excl_flds = {'/proc/', '/dev/', '/sys/', '/tmp', '/var/run', '/run'}
root = "/"
delim = "#########################"
AUTHOR = "Fabrizio Pani"
EMAIL = "fabje AT centrum DOT cz"
LICENSE = "GPL v2"
curpos = ""
wwfiles = []

print(delim)
print(SCRIPT_NAME)
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
                    # check "other" permission
                    o_mode = mode[len(mode) - 1]
                    if o_mode in WW_MODES:
                        wwfiles.append(pathfile)
                except IOError:
                    print (TYELLOW, ENDC)  
                    print (sys.exc_type) 
                    # it could be an issue limited to few resources, so pass
                    pass
                    # all other errors exit
                except MemoryError:
                    print (TRED, "Out of memory exception.", ENDC)
                    sys.exit(11)
                except RuntimeError:
                    print (TYELLOW, e, ENDC) 
                    print (sys.exc_type)
            else:
                if curpos != oldpos:
                    print("Skipping ", pathfile[:pos +1])
except KeyboardInterrupt:
    err_msg = "{} :  exiting on keyboard signal.".format(SCRIPT_NAME)
    print(err_msg)
    sys.exit(127)


print("World Writable files found: ")
for wwfile in  wwfiles:
    print (TYELLOW, wwfile, ENDC)
stop_time = datetime.datetime.now()
print("Execution time: {0}".format(stop_time - start_time))
print("Done")
print(delim)
