try:
    import psutil
except ImportError:
    print("It looks like you need to install the python psutil module.")
    sys.exit(1) 
import subprocess


def check_procrun(ProcName):
    for proc in psutil.process_iter():
        try:
            if str(ProcName).lower() in str(proc.name).lower():
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass
    return False


def which_prg(PrgName):
    
    cmd = ['which', PrgName]
    p = subprocess.Popen(cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    p.wait()
    ret_code = p.returncode

    if ret_code == 0:
        return True
    else:
        return False

        
def run_prg(*PrgArgs):
    """
        Run a command 
        Returns exit code, standard error and standard output
    """
    cmd = list(PrgArgs)
    if not cmd:
        raise Exception("You must specify a command.")
    p = subprocess.Popen(cmd,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    p.wait()
    ret_code = p.returncode
    stdout, stderr = p.communicate()
    
    return ret_code, stdout, stderr
    
    
def run_piped_prg(*PrgArgs):
    """
       Pipe the STDOUT of a command to STDIN of the second command
       Returns exit code, standard error and standard output
    """
    PIPE = chr(124)
    pre_cmds = list(PrgArgs)
    how_many_pipes = pre_cmds.count(PIPE)
    if not PIPE in pre_cmds:
        raise Exception("Malformed cmdline arg: use run_prg instead.")
    if how_many_pipes >511:
        raise Exception("We limit to a resonable 512 processes.")
    i = pre_cmds.index(PIPE)
    if i == len(pre_cmds) - 1:
        raise Exception("Malformed cmdline arg: pipe as last char.")
    
    for in range(0, how_many_pipes):
        vars()[''.join["p",i]]
    
    firstcmd = pre_cmds[0: i]
    pipedcmd = pre_cmds[i + 1 : len(pre_cmds)]
   
    p1 = subprocess.Popen(firstcmd, stdout=subprocess.PIPE)
    p1.wait()
    p2 = subprocess.Popen(pipedcmd, stdin=p1.stdout, 
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p2.wait()
    ret_code = p2.returncode
    stdout, stderr = p2.communicate()
    return ret_code, stdout, stderr
