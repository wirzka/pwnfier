"""
pwnfier.py - Python 3.7.3
   *Author: Andrea Grigoletto - wirzka
   *E-mail: wiirzka@gmail.com
   *Git: https://github.com/wirzka.

Usage:
  pwnfier.py  (-a) (([-A MAIL] | [-P MAIL]) [-f <filepath>])
  pwnfier.py  (-n) (([-b DOMAIN] | [-B] | [-p PASSWORD]) [-f <filepath>])
  pwnfier.py  -h | --help

Options:
  
  User input:
  -a --auth          Use authenticated mode, MUST provide API key
  -n --notauth       Use non authenticated mode, do not provide API key
  -f --file          File
  
  Type of query:
  -b --breach        Give a domain, look for its specific breaches
  -B --breaches      Retrieve all breaches
  -p --passwd        Check for password
  -P  --Pasted       Check if the given mail is on Pasted websites
  -A --AllBreach     Check all the given mail's breached accounts
  -h --help          Show this screen


"""

import sys
import re
from os import system
import time
import pprint
import json
from docopt import docopt
from PwnFR import *
from art import tprint

#============ API KEY  ===============#
pwn = PwnFR(api_key=None)

#========== GLOBAL VARS ==============#

# # list for storing given email from cmd line or file
emails = []

# API key file path
apiFile = ''
# #========= CLASS SECTION =============#
class color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

# #======== FUNCTION SECTION ===========#


# # function to parse the file containing the e-mails
# def scanFileMail():

#     with open(fileMail, encoding='utf-8') as fm:

#         # getting the lines from the file
#         for line in fm:
#             fm.strip()
#             emails.append(line)

# # function to output the details of all the active external connections and  populate ip2check list
# def printResVerb():
#     global ip2add, ip2check
#     print('\033[92m\n' + '-' * 15 + 'VERBOSE MODE ACTIVATED' + '-' * 14 + '\033[00m')
#     for id in range(0,len(id_list)):
#         print(color.PURPLE + color.BOLD + "{:<15s}".format('ID ' + str(id+1) + color.END))
#         print(color.BOLD + '{:<18s}'.format('Protocol:') + color.END + '{:<24s}'.format(id_list[id][0]))
#         print(color.BOLD + '{:<18s}'.format('Local IP-PORT:') + color.END + '{:<24s}'.format(id_list[id][1]))
#         print(color.BOLD + '{:<18s}'.format('External IP-PORT:') + color.END + '{:<24s}'.format(id_list[id][2]))
#         print(color.BOLD + '{:<18s}'.format('Status:') + color.END + '{:<24s}\n'.format(id_list[id][3]))

#         ip2add = id_list[id][2].split(':', 1)[0]
#         ip2check.append(ip2add)

# def breachedaccount():
#     # for email in len(emails):
#     #     try:
#     #         data = pwn.breachedaccount(email)
#     #         print data  
#     #     except:
#     #         print('Something went wrong.')

# # def breaches(filter=None):
# #     # for
# # def breach():
# # def dataclass():
# # def pasteaccount():

# # function that prints the results from AbusedIPDB
# def printIP(ip, abuse_res):
#     stat = ''
         
#     if abuse_res.abuseConfidenceScore > 30 and abuse_res.abuseConfidenceScore < 50:
#         # cyan
#         stat = color.CYAN + '[Maybe check it]' + color.END
#         stat_dict["Maybe check it"] += 1
    
#     elif abuse_res.abuseConfidenceScore > 50 and abuse_res.abuseConfidenceScore < 60:
#         # yellow
#         stat = color.YELLOW + '[Check it]' + color.END
#         stat_dict["Check it"] += 1

#     elif abuse_res.abuseConfidenceScore > 60:
#         # red
#         stat = color.RED + '[Absolutely check it!]' + color.END
#         stat_dict["Absolutely check it!"] += 1

#     else:
#         # green
#         stat = color.GREEN + '[Good]' + color.END
#         stat_dict["Good"] += 1
        
#     print(color.BOLD + color.PURPLE + '\n Results for IP ' + ip + color.END)
#     print(color.BOLD + '{:<18s}'.format('- IP') + color.END + '{:<30}'.format(abuse_res.ipAddress))
#     print(color.BOLD + '{:<18s}'.format('- Public:') + color.END + '{:<30}'.format(str(abuse_res.isPublic)))
#     print(color.BOLD + '{:<18s}'.format('- Whitelisted:') + color.END + '{:<30}'.format(str(abuse_res.isWhitelisted)))
#     try:
#         print(color.BOLD + '{:<18s}'.format('- Abuse score:') + color.END + '{:<30}'.format(str(abuse_res.abuseConfidenceScore) + ' ' + stat))
#     except:
#         print(color.BOLD + '{:<18s}'.format('- Abuse score:') + color.END + '{:<30}'.format('N/D'))
#     try:
#         print(color.BOLD + '{:<18s}'.format('- Total reports:') + color.END + '{:<30}'.format(str(abuse_res.totalReports)))
#     except:
#         print(color.BOLD + '{:<18s}'.format('- Total reports:') + color.END + '{:<30}'.format(' N/D'))
#     try:
#         print(color.BOLD + '{:<18s}'.format('- Last report:') + color.END + '{:<30}'.format(abuse_res.lastReportedAt))
#     except:
#         print(color.BOLD + '{:<18s}'.format('- Last report:') + color.END + '{:<30}'.format('never'))
#     try:
#         print(color.BOLD + '{:<18s}'.format('- Usage type:') + color.END + '{:<30}'.format(abuse_res.usageType))
#     except:
#         print('{:<18s}'.format('- Usage type:') + '{:<30}'.format('N/D'))

#     print(color.BOLD + '[!] Other info [!]' + color.END)
#     try:
#         print(color.BOLD + '{:<18s}'.format('- Domain:') + color.END + '{:<30}'.format(abuse_res.domain))
#     except:
#         print(color.BOLD + '{:<18s}'.format('- Domain:') + color.END + '{:<30}'.format(' N/D'))
#     try:
#         print(color.BOLD + '{:<18s}'.format('- Country code:') + color.END + '{:<30}'.format(abuse_res.countryCode))
#     except:
#         print(color.BOLD + '{:<18s}'.format('- Country code:') + color.END + '{:<30}'.format(' N/D'))
#     try:
#         print(color.BOLD + '{:<18s}'.format('- Country name:') + color.END + '{:<30}'.format(abuse_res.countryName))
#     except:
#         print(color.BOLD + '{:<18s}'.format('- Country name:') + color.END + '{:<30}'.format(' N/D'))
#     try:
#         print(color.BOLD + '{:<18s}'.format('- ISP:') + color.END + '{:<30}'.format(abuse_res.isp))
#     except:
#         print(color.BOLD + '{:<18s}'.format('- ISP:') + color.END + '{:<30}'.format(' N/D'))

# # function that generate the connections' statistics
# def stats():
#     print('\n\n' + color.GREEN + color.BOLD + '-' * 10 + 'CONNECTIONS\' STATS' + '-' * 10 + '\n')
#     for key, value in stat_dict.items():
#         if key == 'Absolutely check it!':
#             print(color.RED + color.BOLD + '{:<22s}:'.format(key) + color.END + '{:>3}'.format(value))
#         elif key == 'Check it':
#             print(color.YELLOW + color.BOLD + '{:<22s}:'.format(key) + color.END + '{:>3}'.format(value))
#         elif key == 'Maybe check it':
#             print(color.CYAN + color.BOLD + '{:<22s}:'.format(key) + color.END + '{:>3}'.format(value))
#         elif key == 'Good':
#             print(color.GREEN + color.BOLD + '{:<22s}:'.format(key) + color.END + '{:>3}'.format(value))
#         else:
#             print("Wtf")
#             sys.exit(0)

# # function that simply output an introduction message
def greetings():
    _ = system('cls')
    print(color.BLUE + color.BOLD)
    tprint("Pwnfier",font="graffiti")
    print(color.END)
    print(color.YELLOW + __doc__ + color.END)

# # function that toggle the disclaimer
# def disclaimer():
#     print('\033[93m\n\n[!] Be Aware:\033[00m\n\
# \033[93m|\033[00m\033[94m While you\'re getting any negative result, it doesn\'t mean that there aren\'t leaks.\033[00m\n\
# \033[93m|\033[00m\033[94m It means that the current connections are not identified as suspicious on AbuseIPDB!\033[00m\n\
# \033[93m|\033[00m \n\
# \033[93m|\033[00m\033[94m AbuseIPDB and other tools like it are useful to gain some infos on IPs\033[00m\n\
# \033[93m|\033[00m\033[94m e.g.: suspicious, behaviour, domain details, etc\033[00m\n\
# \033[93m|\033[00m\033[94m BUT you should be careful to block IP or take some actions just by reviewing a score.\033[00m\n\
# \033[93m|\033[00m\033[94m Go deeper, get more intel and then take some actions, maybe.\033[00m\n\
# \033[93m[!]\033[00m')

#=========== QUERER FUNCTION ============#
# function to query for all breachedaccount of a given mail
def breachedaccount(mail):
    res = pwn.breachedaccount(mail)
    # for data in res:
        # implementare funzione per stampa JSON

# function to query for all pasted mail
def pasted(mail):
    res = pwn.pasteaccount(mail)
    # for data in res:
        # implementare funzione per stampa JSON


# function to query for all domain's breaches
def breach(domain):
    res = pwn.breach(domain)
    # for data in res:
        # implementare funzione per stampa JSON


# function to retrieve all breaches
def breaches():
    res = pwn.breaches()
    # for data in res:
        # implementare funzione per stampa JSON


# function to check the given password
def pwdCheck(pwd):
    res = pwn.checkPwd(pwd)
    # for data in res:
        # implementare funzione per stampa JSON

#============ CHECKER FUNCTIONS =============#

# function to look for API key
def searchAPI():
    try:
        with open(apiFile, mode='r', encoding='utf-8') as aF:
            k = aF.readline()
        if k:
            print('API key found: ',k)
    except FileNotFoundError:
        while 1:
            k = input('[!] File not found! Please, manually paste here the API key: ')
            if k:
                return k

# def checkMailFile():
# def checkDomFile():
# def checkPwdFile():

#============== PRINTER FUNCTIONS =============#
# main function
def main(arguments):
     # ouput the intro message
    greetings()

    # start by handling a bit the given arguments
    # if user has provided the auth mode
    if arguments['--auth']:
        # checking if the API key is set in the code
        if pwn._api_key == None:
            # if not, look for the default file (check doc on github)
            pwn._api_key = searchAPI()
        
        # if user want to retrieve all the breaches
        if arguments['--AllBreach']:
            # if the file has not been provided, skip and take the
            # argument parameter
            if not arguments['--file']:
                breachedaccount(arguments['MAIL'])
            else:
                # if file's been provided, go check if the file is ok (exist, format)
                checkMailFile()
        
        # if user want to check for any pasted mail
        elif arguments['--Pasted']:
            # if the file has not been provided, skip and take the
            # argument parameter
            if not arguments['--file']:
                pasted(arguments['MAIL'])
            else:
                # if file's been provided, go check if the file is ok (exist, format)
                checkMailFile()
    
    # if the user has not provided the auth mode
    elif arguments['--notauth']:
        # giving None value tu _api_key var
        pwn._api_key = None
        
        if arguments['--breach']:
            # if the file has not been provided, skip and take the
            # argument parameter
            if not arguments['--file']:
                breach(arguments['DOMAIN'])
            else:
                # if file's been provided, go check if the file is ok (exist, format)
                checkDomFile()
        
        elif arguments['--breaches']:
            breaches()

        elif arguments['--passwd']:
            # if the file has not been provided, skip and take the
            # argument parameter
            if not arguments['--file']:
                pwdCheck(arguments['PASSWD'])
            else:
                # if file's been provided, go check if the file is ok (exist, format)
                checkPwdFile()
    
   
    
    # printing disclaimer
    # disclaimer()

# #========= END FUNCTION SECTION =======#

if __name__ == "__main__":
    try:
        arguments = docopt(__doc__, version='0.1.0')
        print(arguments)
        main(arguments)
    except KeyboardInterrupt:
        print("\n\033[91m[!] You have interrupted the stuff with your keyboard, bye. [!]\033[00m")
        time.sleep(3)
        sys.exit(0)
    