from __future__ import print_function
import argparse
import datetime
import os
import re
import sys
import time
ScriptName = os.path.basename(__file__)
CurrAbsPath = os.path.dirname(os.path.realpath(ScriptName))
sys.path.append(CurrAbsPath + "/libaudit")
try:
    from libaudit.osutils import *
    from libaudit.ui import set_ansiterm
except:
    print("Error while importing one or more modules.")
    sys.exit(1)
    
sshd_opts = ["clientalivecountmax", "compression", 
              "gssapiauthentication", "hostbasedauthentication",
              "ignorerhosts", "ignoreuserknownhosts", 
              "kerberosauthentication", "permitemptypasswords",
              "permitrootlogin", "permituserenvironment", "printlastlog",
              "protocol", "rhostsrsaauthentication", "strictmodes", 
              "useprivilegeseparation"]
#Note: macs and ciphers will be checked separately

#STIG correct values
sshd_opts_corr = [
                   "clientalivecountmax 0", 
                   "compression no", 
                   "gssapiauthentication no", 
                   "hostbasedauthentication no",
                   "ignorerhosts yes", 
                   "ignoreuserknownhosts yes", 
                   "kerberosauthentication no", 
                   "permitemptypasswords no",
                   "permitrootlogin no", 
                   "permituserenvironment no", 
                   "printlastlog yes", 
                   "protocol 2", 
                   "rhostsrsaauthentication no", 
                   "strictmodes yes",
                   "useprivilegeseparation no"
                   ]

safe_macs = [
             "hmac-sha2-256", 
             "hmac-sha2-256@openssh.com",
             "hmac-sha2-256-etm@openssh.com",
             "hmac-sha2-512",
             "hmac-sha2-512@openssh.com",
             "hmac-sha2-512-etm@openssh.com",
             "umac-128",
             "umac-128-etm@openssh.com",
             "umac-128@openssh.com",
             "hmac-sha1-etm@openssh.com",
             "hmac-ripemd160-etm@openssh.com",
             "hmac-ripemd160"
             "hmac-ripemd256-etm@openssh.com",
             "hmac-ripemd256",
             "hmac-ripemd320-etm@openssh.com",
             "hmac-ripemd320"
             ]
             
safe_ciphers = [
                "aes128-ctr",
                "aes128-ctr@openssh.com", 
                "aes192-ctr", 
                "aes192-ctr@openssh.com",
                "aes256-ctr",
                "aes256-ctr@openssh.com",
                "chacha20-poly1305@openssh.com",
                "chacha20-poly1305"
                "aes128-gcm",
                "aes128-gcm@openssh.com",
                "aes256-gcm",
                "aes256-gcm@openssh.com",
                "arcfour256",
                "arcfour128"
                ]
                
TCOLOR = set_ansiterm()    

    
nl = '\n' 
is_compliant = True   
import platform
if int(platform.python_version_tuple()[0]) < 3:
    PyMajVer = 2 
else:
    PyMajVer = 3 
PyMinVer = int(platform.python_version_tuple()[1])

old_ver_msg1 = """
Warning, you are using a DEPRECATED python version.
As of January 1st, 2020 Python 2 is no longer supported.
More info at https://www.python.org/doc/sunset-python-2/
"""
old_ver_msg2 = """
Warning, you are using a DEPRECATED and untested python version.
As of January 1st, 2020 Python 2 is no longer supported. 
More info at https://www.python.org/doc/sunset-python-2/
"""
old_ver_msg3 = """
Warning, you are using a DEPRECATED and too old python version.
As of January 1st, 2020 Python 2 is no longer supported. 
More info at https://www.python.org/doc/sunset-python-2/
"""

if PyMajVer == 2 and PyMinVer == 6:
    print(TCOLOR["TYELLOW"], old_ver_msg2, TCOLOR["RSTC"])
if PyMajVer == 2 and PyMinVer < 6:
    print(TCOLOR["TYELLOW"], old_ver_msg3, TCOLOR["RSTC"])
    print("Exiting...")
    sys.exit(11)
if PyMajVer == 2 and PyMinVer == 7:
    print(TCOLOR["TYELLOW"], old_ver_msg1, TCOLOR["RSTC"])
  

str_prolog = """ 
Script to audit the SSHD configuration for any security
deviation, currently based on the STIG recommendations; more on: 
https://stigviewer.com/stigs 
Note that this script is still in test mode and not complete.
No changes will be made to your system, but use it at your own risk.
Distributed under the GPL v3 

Usage: 
{0} -h    Display this help
{1} -c    Audit the OpenSSH (sshd) configuration

\n
""".format(ScriptName, ScriptName)


class CusArgumentParser(argparse.ArgumentParser):
    def print_help(self, file=None):
        if file is None:
            file = sys.stdout
        file.write(str_prolog)
            
            
def parse_args():
    """
        Parse command line arguments
        Returns them
    """
    
    parser = CusArgumentParser()
    parser.add_argument('-c', '--check',
                        action = 'store_true',
                        dest = 'check',
                        help = 'Check for security deviations (on sshd)'
                        )

    args = parser.parse_args()
    return args


def proc_err(ret_code, stdout, stderr):
    """
        Display error and exit
    """
    print(TCOLOR["TRED"], "Error while fetching the sshd configuration.", TCOLOR["RSTC"])    
    print(TCOLOR["TRED"], "Error message: ", stdout, TCOLOR["RSTC"])
    print(TCOLOR["TRED"], "Error message: ", stderr, TCOLOR["RSTC"])
    print(TCOLOR["TRED"], "Error code: ", ret_code, TCOLOR["RSTC"])

    sys.exit(ret_code)    
 
 
def check_sshd_config():
    """
        Check the OpenSSH configured options by running sshd -T
    """
    
    #Filtering only the values we are interested with
    print("\nChecking for sshd_config options..")
    ret_code, stdout, stderr = run_prg("sshd", "-T")
    if ret_code != 0:
        proc_err(ret_code, stdout, stderr)
    if PyMajVer >= 3:
        stdout = ''.join(map(chr, stdout))
        
    sshd_cfg_all_rows = stdout.split(nl)
    sshd_cfg_chk_rows = []
    for sshd_cfg_all_row in sshd_cfg_all_rows:
        for sshd_opt in sshd_opts:
            if sshd_cfg_all_row.startswith(sshd_opt):
                sshd_cfg_chk_rows.append(sshd_cfg_all_row)
                break
    for sshd_cfg_chk_row in sshd_cfg_chk_rows:
        sshd_cfg_chk_elem = sshd_cfg_chk_row.split()
        for sshd_opt_corr in sshd_opts_corr:
            if sshd_opt_corr.startswith(sshd_cfg_chk_elem[0]):
                corr_val = sshd_opt_corr.split()[1]
                if sshd_cfg_chk_elem[1] != corr_val:
                    sshd_cfg_chk_elem = str(sshd_cfg_chk_elem)
                    sshd_cfg_chk_elem = re.sub('[\[\]\']', '', 
                                               sshd_cfg_chk_elem)                                                       
                    sshd_cfg_chk_elem = sshd_cfg_chk_elem.replace(chr(44),
                                                                  chr(58))
                    print(TCOLOR["TYELLOW"], "The sshd option ", 
                          TCOLOR["BYELLOW"], sshd_cfg_chk_elem, TCOLOR["RSTC"],
                          TCOLOR["TYELLOW"], " is not compliant", 
                          TCOLOR["RSTC"])
                    is_compliant = False       
                break    

                
def check_macs():
    """
        Check for weak macs algorithms
    """
    
    print("\nChecking for weak MAC algorithms..")
    ret_code, stdout, stderr = run_piped_prg("sshd", "-T", "|", 
                                             "grep", "-w","macs")
    if ret_code != 0:
        proc_err(ret_code, stdout, stderr)   
    if PyMajVer >= 3:
        stdout = ''.join(map(chr, stdout))
        
    sshd_macs_pre = stdout.split()[1]  
    sshd_macs = sshd_macs_pre.split(chr(44)) 

    for safe_mac in safe_macs:
        if safe_mac in sshd_macs:
            sshd_macs.remove(safe_mac)
    if sshd_macs:
        print(TCOLOR["TYELLOW"], "Warning! The following unsafe MAC algorithms \
have been found:", TCOLOR["RSTC"])
        for sshd_mac in sshd_macs:
            print(TCOLOR["BYELLOW"], sshd_mac, TCOLOR["RSTC"])
        is_compliant = False    
    else:
        print(TCOLOR["TGREEN"], "MAC algorithms: OK", TCOLOR["RSTC"])
        
        
def check_ciphers():
    """
        Check for weak ciphers
    """
    global is_compliant
    print("\nChecking for weak ciphers..")
    ret_code, stdout, stderr = run_piped_prg("sshd", "-T", "|", 
                                             "grep","-w","ciphers")
    if ret_code != 0:
        proc_err(ret_code, stdout, stderr) 
    if PyMajVer >= 3:
        stdout = ''.join(map(chr, stdout))
         
    sshd_ciphers_pre = stdout.split()[1]  
    sshd_ciphers = sshd_ciphers_pre.split(chr(44)) 
    for safe_cipher in safe_ciphers:
        if safe_cipher in sshd_ciphers:
                sshd_ciphers.remove(safe_cipher)
    if sshd_ciphers:
        print(TCOLOR["TYELLOW"], "Warning! The following unsafe ciphers have \
been found.",
              TCOLOR["RSTC"])
        for sshd_cipher in sshd_ciphers:
            print(TCOLOR["BYELLOW"], sshd_cipher, TCOLOR["RSTC"])
        is_compliant = False
    else:
        print(TCOLOR["TGREEN"], "Ciphers are OK.", TCOLOR["RSTC"])    
        
        
def main():

    try:
        if os.getuid() != 0:
            print(TCOLOR["TRED"], "You need to have root privileges.", 
                  TCOLOR["RSTC"])
            sys.exit(5)
    except AttributeError:
        print(TCOLOR["TRED"], "Unsupported OS or config", TCOLOR["RSTC"])
        sys.exit(1)
        
    if not which_prg("sshd"):
        print(TCOLOR["TRED"], "sshd not found or not in the path.", 
              TCOLOR["RSTC"])
        sys.exit(1)
    
    if not (check_procrun("sshd")):
       print("Notice: The sshd process is not running.")
    else:
       print(TCOLOR["TGREEN"], "The sshd process is running: OK", 
             TCOLOR["RSTC"])
        
    check_sshd_config()
    check_macs()
    check_ciphers()

    if is_compliant:
        print(TCOLOR["TGREEN"], "\nsshd (OpenSSH) security settings are OK", 
        TCOLOR["RSTC"])
    else:
        print(TCOLOR["TYELLOW"], "\nsshd (OpenSSH) security settings are \
NOT OK", TCOLOR["RSTC"]) 


args = parse_args()
if args.check is None:
    print(TCOLOR["TYELLOW"], "Invalid cmdline args", TCOLOR["RSTC"])
    print(str_prolog)
    sys.exit()

if __name__ == "__main__":
    main() 