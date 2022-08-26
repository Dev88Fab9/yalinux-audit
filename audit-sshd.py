from __future__ import print_function
import datetime
import os
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
    
nl = '\n' 
is_compliant = True   
import platform
if int(platform.python_version_tuple()[0]) < 3:
    PyMajVer = 2 
else:
    PyMajVer = 3 
    
sshd_opts = ["clientalivecountmax", "compression", 
              "gssapiauthentication", "hostbasedauthentication",
              "ignorerhosts", "ignoreuserknownhosts", 
              "kerberosauthentication", "permitemptypasswords",
              "permitrootlogin", "permituserenvironment", "printlastlog",
              "protocol", "rhostsrsaauthentication", "strictmodes", 
              "useprivilegeseparation"]
#Note: macs and ciphers will be checked separately

#STIG correct values
sshd_opts_corr = ["clientalivecountmax 0", "compression no", 
                   "gssapiauthentication no", "hostbasedauthentication no",
                   "ignorerhosts yes", "ignoreuserknownhosts yes", 
                   "kerberosauthentication no", "permitemptypasswords no",
                   "permitrootlogin no", "permituserenvironment no", 
                   "printlastlog yes", "protocol 2", "rhostsrsaauthentication no", 
                   "strictmodes yes","useprivilegeseparation no"]

safe_macs = ["hmac-sha2-256", 
             "hmac-sha2-256@openssh.com",
             "hmac-sha2-256-etm@openssh.com",
             "hmac-sha2-512",
             "hmac-sha2-512@openssh.com",
             "hmac-sha2-512-etm@openssh.com",
             "umac-128",
             "umac-128-etm@openssh.com",
             "umac-128@openssh.com",
             "hmac-sha1",
             "hmac-sha1@openssh.com",
             "hmac-sha1-etm@openssh.com",
             "hmac-ripemd160-etm@openssh.com",
             "hmac-ripemd160"]
             
safe_ciphers = ["aes128-ctr",
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
                "aes128-cbc",
                "aes192-cbc",
                "aes256-cbc",
                "blowfish-cbc",
                "cast128-cbc",
                "3des-cbc"]


TRED, TGREEN, TYELLOW, RSTC = set_ansiterm()

def proc_err(ret_code, stdout, stderr):
    print(TRED, "Error while fetching the sshd configuration.", RSTC)    
    print(TRED, "Error message: ", stdout, RSTC)
    print(TRED, "Error message: ", stderr, RSTC)
    print(TRED, "Error code: ", ret_code, RSTC)

    sys.exit(ret_code)    
    
    

def main():

    try:
        if os.getuid() != 0:
            print(TRED, "You need to have root privileges.", RSTC)
            sys.exit(5)
    except AttributeError:
        print(TRED, "Unsupported OS or config", RSTC)
        sys.exit(1)
        
    if not which_prg("sshd"):
        print(TRED, "sshd not found or not in the path.", RSTC)
        exit(1)
        
    print("Script to audit the SSHD configuration for any security deviation.")  
    print("Currently based on the STIG recommendations; more on: \
https://stigviewer.com/stigs")
    print("Note that this script is still in test mode and not complete.")
    print("No changes will be made to your system, but use it at your own risk")
    print("And according to the GPL v3.")
    print("Press CTRL+C in 10 seconds if you wish to EXIT!")
    time.sleep(10)
    
    
    if not (check_procrun("sshd")):
       print("Notice: The sshd process is not running.")
    else:
       print(TGREEN, "The sshd process is running: => OK", RSTC)
       
    ret_code, stdout, stderr = run_prg("sshd", "-T")
    if ret_code != 0:
        proc_err(ret_code, stdout, stderr)
    if PyMajVer >= 3:
        stdout = ''.join(map(chr, stdout))
    sshd_cfg_all_rows = stdout.split(nl)
    
    #Filtering only the values we are interested with
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
                    print(TYELLOW, "The sshd option ", sshd_cfg_chk_elem, 
                          " is not compliant", RSTC)
                    is_compliant = False       
                break    

    print("\nChecking for unsafe MAC algorithms..")
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
        print(TYELLOW, "Warning! The following unsafe MAC algorithms have been \
found:", RSTC)
        for sshd_mac in sshd_macs:
            print(sshd_mac)
        is_compliant = False    
    else:
        print(TGREEN, "MAC algorithms are OK", RSTC)
     
    print("\nChecking for unsafe ciphers..")
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
        print(TYELLOW, "Warning! The following unsafe ciphers have been found.",
              RSTC)
        for sshd_cipher in sshd_ciphers:
            print(sshd_cipher)
        is_compliant = False
    else:
        print(TGREEN, "ciphers are OK.", RSTC)    
        
    if is_compliant:
        print(TGREEN, "\nsshd (OpenSSH) security settings are OK", RSTC)
    else:
        print(TYELLOW, "\nsshd (OpenSSH) security settings are NOT OK", RSTC)
       
if __name__ == "__main__":
    main() 