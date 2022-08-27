"""
   Module to provide some user interface service
"""


def set_ansiterm():
    """
    Set well known ANSI colors
    """
    
    TCOLORS = {
               "TRED" : '\033[31m', 
               "TGREEN" : '\033[32m', 
               "TYELLOW" : '\033[33m', 
               "RSTC" : '\033[m'
               }
    return TCOLORS