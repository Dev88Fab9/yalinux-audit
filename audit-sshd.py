"""
Script to audit the SSHD configuration for any security
deviation, currently based on the STIG recommendations; more on: 
https://stigviewer.com/stigs 
"""
from __future__ import print_function
import argparse
import os
import platform
import re
import sys
import traceback
ScriptName = os.path.basename(__file__)
CurrAbsPath = os.path.dirname(os.path.realpath(ScriptName))
sys.path.append(CurrAbsPath + "/libaudit")
try:
    from libaudit.osutils import *
    from libaudit.ui import set_ansiterm
except ImportError:
    print("Error while importing one or more modules.")
    sys.exit(1)
except RuntimeError:
    print("Error on one or more modules.")
    print(traceback.print_exc())
    
sshd_opts = [
             "clientalivecountmax", 
             "compression", 
             "gssapiauthentication", 
             "hostbasedauthentication",
             "ignorerhosts",
             "ignoreuserknownhosts", 
             "kerberosauthentication", 
             "permitemptypasswords",
             "permitrootlogin", 
             "permituserenvironment",
             "printlastlog",
             "protocol", 
             "rhostsrsaauthentication", 
             "strictmodes", 
             "useprivilegeseparation"
             ]
#Note: macs and ciphers will be checked separately

#STIG correct values
sshd_opts_corr = [
                   "clientalivecountmax 0", 
                   "compression no delayed",
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
TYELLOW = TCOLOR["TYELLOW"]
TRED = TCOLOR["TRED"]
TGREEN = TCOLOR["TGREEN"]
TRST = TCOLOR["RSTC"]
BYELLOW = TCOLOR["BYELLOW"]
NL = '\n'

if int(platform.python_version_tuple()[0]) < 3:
    PY_MAJ_VER = 2
else:
    PY_MAJ_VER = 3
PY_MIN_VER = int(platform.python_version_tuple()[1])

OLD_VER_MSG1 = """
Warning, you are using a DEPRECATED python version.
As of January 1st, 2020 Python 2 is no longer supported.
More info at https://www.python.org/doc/sunset-python-2/
"""
OLD_VER_MSG2 = """
Warning, you are using a DEPRECATED and untested python version.
As of January 1st, 2020 Python 2 is no longer supported. 
More info at https://www.python.org/doc/sunset-python-2/
"""
OLD_VER_MSG3 = """
Warning, you are using a DEPRECATED and too old python version.
As of January 1st, 2020 Python 2 is no longer supported. 
More info at https://www.python.org/doc/sunset-python-2/
"""

if PY_MAJ_VER == 2 and PY_MIN_VER == 6:
    print(TYELLOW, OLD_VER_MSG2, TRST)
if PY_MAJ_VER == 2 and PY_MIN_VER < 6:
    print(TYELLOW, OLD_VER_MSG3, TRST)
    print("Exiting...")
    sys.exit(11)
if PY_MAJ_VER == 2 and PY_MIN_VER == 7:
    print(TYELLOW, OLD_VER_MSG1, TRST)


str_prolog = """ 
Script to audit the SSHD configuration for any security
deviation, currently based on the STIG recommendations; more on: 
https://stigviewer.com/stigs 
Note that this script is still in test mode and not complete.
No changes will be made to your system, but use it at your own risk.
Distributed under the GPL v3 (https://www.gnu.org/licenses/gpl-3.0.en.html)

Usage: 
{0} -h    Display this help
{1} -c    Audit the OpenSSH (sshd) configuration

\n
""".format(ScriptName, ScriptName)


class CusArgumentParser(argparse.ArgumentParser):
    """
        Redifines custom argparse help message
    """
    def print_help(self, file=None):
        if file is None:
            file = sys.stdout
        file.write(str_prolog)
            
            
def parse_args():
    """
        Parses command line arguments
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
        Displays error and exit
    """
    
    print(TRED, "Error while fetching the sshd configuration.", TRST)    
    print(TRED, "Error message: ", stdout, TRST)
    print(TRED, "Error message: ", stderr, TRST)
    print(TRED, "Error code: ", ret_code, TRST)

    sys.exit(ret_code)


def check_sshd_config(is_compliant):
    """
        Checks the OpenSSH configured options by running sshd -T
        Returns is_compliant
    """

    
    print("\nChecking for sshd_config options")
    ret_code, stdout, stderr = run_prg("sshd", "-T")
    if ret_code != 0:
        proc_err(ret_code, stdout, stderr)
    if PY_MAJ_VER >= 3:
        stdout = ''.join(map(chr, stdout))

    sshd_cfg_all_rows = stdout.split(NL)
    sshd_cfg_chk_rows = []
    #Filtering out the options we are not interested to
    for sshd_cfg_all_row in sshd_cfg_all_rows:
        for sshd_opt in sshd_opts:
            if sshd_cfg_all_row.startswith(sshd_opt):
                sshd_cfg_chk_rows.append(sshd_cfg_all_row)
                break
    #main loop            
    for sshd_cfg_chk_row in sshd_cfg_chk_rows:
        sshd_cfg_chk_elem = sshd_cfg_chk_row.split()
        for sshd_opt_corr in sshd_opts_corr:
            if sshd_opt_corr.startswith(sshd_cfg_chk_elem[0]):
                corr_val = sshd_opt_corr.split()[1:]
                if not sshd_cfg_chk_elem[1] in corr_val:
                    sshd_cfg_chk_elem = str(sshd_cfg_chk_elem)
                    sshd_cfg_chk_elem = re.sub('[\[\]\']', '',
                                               sshd_cfg_chk_elem)
                    sshd_cfg_chk_elem = sshd_cfg_chk_elem.replace(chr(44),
                                                                  chr(58))                                        
                    print(TYELLOW, "The sshd option ",
                          BYELLOW, sshd_cfg_chk_elem, TRST, TYELLOW, 
                          " is not compliant", TRST)
                    is_compliant = False
                break
                
    if is_compliant:
        print(TYELLOW, "OK", TRST)  
        
    return is_compliant
    
    
def check_macs(is_compliant):
    """
        Checks for weak macs algorithms
        Returns is_compliant
    """

    print("\nChecking for weak MAC algorithms..")
    ret_code, stdout, stderr = run_piped_prg("sshd", "-T", "|", 
                                             "grep", "-w","macs")
    if ret_code != 0:
        proc_err(ret_code, stdout, stderr)
    if PY_MAJ_VER >= 3:
        stdout = ''.join(map(chr, stdout))
        
    sshd_macs_pre = stdout.split()[1]
    sshd_macs = sshd_macs_pre.split(chr(44))

    for safe_mac in safe_macs:
        if safe_mac in sshd_macs:
            sshd_macs.remove(safe_mac)
    if sshd_macs:
        print(TYELLOW, "Warning! The following unsafe MAC algorithms have been \
found:", TRST)
        for sshd_mac in sshd_macs:
            print(BYELLOW, sshd_mac, TRST)
        is_compliant = False
    else:
        print(TGREEN, "MAC algorithms: OK", TRST)
    
    return is_compliant
    

def check_ciphers(is_compliant):
    """
        Checks for weak ciphers
        Returns is_compliant
    """
    
    print("\nChecking for weak ciphers..", end = ' ')
    ret_code, stdout, stderr = run_piped_prg("sshd", "-T", "|", 
                                             "grep","-w","ciphers")
    if ret_code != 0:
        proc_err(ret_code, stdout, stderr)
    if PY_MAJ_VER >= 3:
        stdout = ''.join(map(chr, stdout))
         
    sshd_ciphers_pre = stdout.split()[1]
    sshd_ciphers = sshd_ciphers_pre.split(chr(44))
    for safe_cipher in safe_ciphers:
        if safe_cipher in sshd_ciphers:
            sshd_ciphers.remove(safe_cipher)
    if sshd_ciphers:
        print(TYELLOW, "Warning! The following unsafe ciphers have been found.",
              TRST)
        for sshd_cipher in sshd_ciphers:
            print(BYELLOW, sshd_cipher, TRST)
        is_compliant = False
    else:
        print(TGREEN, "OK", TRST)

    return is_compliant


def verify_sshd_config(is_compliant):
    """
        Verifies the sshd config 
    """
    
    ret_code, stdout, stderr = run_prg("sshd", "-t")
    if not ret_code == 0:
        return False
        
    return True    
    

def check_sshd_config_perms(is_compliant, config_file):
    """
        Verifies the sshd config permissions
    """
    
    status = os.stat(config_file)
    o_mode = oct(status.st_mode)[-1]
    g_mode = oct(status.st_mode)[-2]
    if not o_mode == 0 and g_mode == 0:
        return False
        
    return True
    
    
def check_sshd_hosts_keyfiles_perms(is_compliant):
    """
        Verifies the host keys files permissions
        Max 644 for a public key
        No permissions for group and others for private keys
    """
    ssh_path = "/etc/ssh/"
    ret_code, stdout, stderr = run_prg("ls", "-1", ssh_path)
    if not ret_code == 0:
        print(TYELLOW, "An error has occurred fetching the host keys files {0}"
        .format(stdout), TRST)
        is_compliant = False
        return is_compliant
        
    if PY_MAJ_VER >=3:
        stdout = ''.join(map(chr, stdout))
        
    keyfiles = stdout.split()
    invalid_pub_modes = [ 3, 6, 7 ]
    
    for keyfile in keyfiles:
        keyfile = ''.join([ssh_path, keyfile])
        try:
            status = os.stat(keyfile)
        except RuntimeError:
            print(TYELLOW, "Error processing file {}".format(keyfile), TRST)
        mode = oct(status.st_mode)
        o_mode = mode[-1]
        g_mode = mode[-2]
        if keyfile.endswith(".pub"):
            if o_mode in invalid_pub_modes or g_mode in invalid_pub_modes:
                is_compliant = False
                print(TYELLOW, "Invalid mode {0} for public key file {1}: it \
must not be writable by others or the group".format(mode, keyfile), TRST)
        else:
            if not o_mode or g_mode == 0:
                is_compliant = False
                print(TYELLOW, "Invalid mode {0} for private key file \
{1}: it must not be accessible by others or the group".format(mode, keyfile), 
TRST)

    return is_compliant
    
def main():
    """
        Main func
    """

    is_compliant = True
    try:
        if os.getuid() != 0:
            print(TRED, "You need to have root privileges.",
                  TRST)
            sys.exit(5)
    except AttributeError:
        print(TRED, "Unsupported OS or config", TRST)
        sys.exit(1)

    if not which_prg("sshd"):
        print(TRED, "sshd not found or not in the path.",
              TRST)
        sys.exit(1)

    if not check_procrun("sshd"):
        print("Notice: The sshd process is not running.")
    else:
        print("The sshd process is running:", end = ' ')
        print(TGREEN, "OK", TRST)     
        
    print("Checking for configuration errors:", end = ' ')    
    is_compliant = verify_sshd_config(is_compliant)
    if not is_compliant:
        print(TRED, "\nFatal: a configuration error was reported.", TRST)
        print(TRED, stdout, TRST)  
        print("Fix any issue and try again")
        sys.exit(1)
    else:
        print(TGREEN, "OK", TRST) 
    
    print("Checking configuration file permissions:", end = ' ')
    config_file = '/etc/ssh/sshd_config'
    is_compliant = check_sshd_config_perms(is_compliant, config_file)
    if is_compliant:
        print(TGREEN, "OK", TRST)
    else:
        print(TYELLOW, "Warning. The sshd_config file should be \
 accessible only by root.", TRST)
    
    print("Checking for host keys files permissions")
    is_compliant = check_sshd_hosts_keyfiles_perms(is_compliant)
    if is_compliant:
        print(TGREEN, "OK", TRST)
    is_compliant = check_sshd_config(is_compliant)
    is_compliant = check_macs(is_compliant)
    is_compliant = check_ciphers(is_compliant)

    if is_compliant:
        print(TGREEN, "\nsshd (OpenSSH) security settings are OK", TRST)
    else:
        print(TYELLOW, "\nsshd (OpenSSH) security settings are NOT OK", TRST) 


arguments = parse_args()
if arguments.check is None:
    print(TYELLOW, "Invalid cmdline args", TRST)
    print(str_prolog)
    sys.exit()

if __name__ == "__main__":
    main() 