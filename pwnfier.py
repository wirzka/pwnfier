"""
pwnfier.py - Python 3.7.3
   *Author: Andrea Grigoletto - wirzka
   *E-mail: wiirzka@gmail.com
   *Git: https://github.com/wirzka.

Usage:
  pwnfier.py  (-a) (([-A MAIL] | [-P MAIL]) [-f FILEPATH])
  pwnfier.py  (-n) (([-b NAME] | [-B] [--filter DOMAIN] | [-p PASSWORD]) [-f FILEPATH])
  pwnfier.py  -h | --help

Options:
  
  User input:
  -a --auth          Use authenticated mode, MUST provide API key
  -n --notauth       Use non authenticated mode, do not provide API key
  -f --file          Insert the file name or absolute path
  -F --filter        Insert the domain to filter e.g. adobe.com

  
  Type of query:
  -b --breach        Give a domain, look for its specific breaches
  -B --breaches      Retrieve all breaches from HIBP
  -p --passwd        Check for password
  -P --Pasted        Check if the given mail is on Pasted websites
  -A --AllBreach     Check all the given mail's breached accounts
  -h --help          Show this screen

  Some examples:
  pwnfier.py -aAf mailFile.txt
  pwnfier.py -nBF yahoo.com
  pwnfier.py -nb  Adobe
"""

import sys
import re
from os import system, getcwd
import time
import pprint
import json
from docopt import docopt
from PwnFR import *
from art import tprint

#============ API KEY  ===============#
pwn = PwnFR(api_key='')

#========== GLOBAL VARS ==============#

# list for storing given email from cmd line or file
emails = []

# list for the domain to look for
doms = []

# API key file path
apiFile = ''

# file position and name where the script will save all the breaches
outputBreachFile = getcwd() + '\\allBreaches.txt'

# message for the disclaimer
goodbye_string ="""[!] Be Aware
 |   If you can't find a site's or account's breach here, it could already/still be breached. 
 |   Do not reuse passwords for important accounts. Follow Bruce Schneier's method or at least 
 |   use strong password and store them in a safe place. But remind: everything can be hacked.
 |   Stay safe.                                           
[!]  
"""

email_regex = ("([a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]+)")

#========= CLASS SECTION =============#
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


#======== FANCY FUNCTIONS ===========#

# function that prints the title
def title():
    _ = system('cls')
    print(color.BLUE + color.BOLD)
    tprint("Pwnfier",font="graffiti")
    print(color.END)

# function to print the helper message
def helper():
    print(color.YELLOW + __doc__ + color.END)

# function to output the greetings title + helper
def greetings():
    title()
    helper()   

# TODO =========== AUTH FUNCTION ============#
# function to query for all breachedaccount of a given mail
def breachedaccount(mails):
    try:
        print(color.YELLOW + color.BOLD + '[-] Querying HIBP [-]' + color.END)
        for mail in mails:
            res = pwn.breachedaccount(mail)
            print(res)
        # for data in res:
            # implementare funzione per stampa JSON
    except:
        print('Something went wrong. Check logs.')

# function to query for all pasted mail
def pasted(mail):
    res = pwn.pasteaccount(mail)
    # for data in res:
        # implementare funzione per stampa JSON


#============= NOT AUTH FUNCTION ==============#
# function to query for all domain's breaches
def breach(domain='',file=''):
    title()
    if domain:
        try:
            print(color.YELLOW + color.BOLD + '[-] Querying HIPB for {}`s breach [-]'.format(domain) + color.END)
            time.sleep(2)
            res = pwn.breach(domain)
            if res:
                print(color.RED + color.BOLD +'[!] Found breach for {} [!]'.format(domain) + color.END)
                print(color.RED + color.BOLD + color.DARKCYAN +'[-] Printing details [-]' + color.END)
                printBreach(res)
            else:
                print(color.GREEN + color.BOLD + '[!] Good news, still no known breach [!]\n' + color.END)
        except:
            print(color.RED + color.BOLD+ '[!] Aborting query, something went wrong. Plug the damned wire![!]' + color.END)
    else:
        print(color.YELLOW + color.BOLD + '[-] Querying HIPB for multiple sites` breach [-]' + color.END)
        try:
            for dom in range(0, len(doms)):
                time.sleep(2)
                res = pwn.breach(doms[dom])
                if res:
                    print(color.RED + color.BOLD +'[!] Found breach for {} [!]'.format(doms[dom]) + color.END)
                    print(color.RED + color.BOLD + color.DARKCYAN +'[-] Printing details [-]' + color.END)
                    printBreach(res)
                    # printMultiSiteBreach(res)
                else:
                    print(color.GREEN + color.BOLD + '\n[!] Good news, still no known breach for {} [!]\n'.format(doms[dom]) + color.END)
        except:
            print(color.RED + color.BOLD+ '[!] Aborting query, something went wrong. Plug the damned wire![!]' + color.END)
    # res.
    # for data in res:
        # implementare funzione per stampa JSON


# function to retrieve all breaches
def breaches(filter=None):
    title()
    # if it is filter it will be prompted to scree, otherwise it will saved on a file
    if filter:
        print(color.YELLOW + color.BOLD + '[-] Looking for {}`s breaches [-]'.format(filter) + color.END)
        res = pwn.breaches(filter)
        print(color.RED + color.BOLD + '[!] Found {} breaches for {} [!]'.format(len(res), filter) + color.END)
        print(color.RED + color.BOLD + color.DARKCYAN +'[-] Printing details [-]' + color.END)
        for data in range(0,len(res)):
            printBreach(res[data])
    else:
        print(color.YELLOW + color.BOLD + '[-] Retrieving all the breaches [-]' + color.END)
        res = pwn.breaches()
        print(color.RED + color.BOLD + '[!] Found {} breaches in total [!]'.format(len(res)) + color.END)
        try:
            print(color.YELLOW + color.BOLD + '[-] Writing the JSON data to the file {} [-]'.format(outputBreachFile) + color.END)
            with open(outputBreachFile, mode='w') as aB:
                json.dump(res, aB) 
            print(color.GREEN + color.BOLD + '[!] File created successfuly [!]\n' + color.END)
        except:
            print(color.RED + color.BOLD + '[!] File creation failed, sorry [!]\n' + color.END)
    # pprint.pprint(res)   
    # for data in res:
        # implementare funzione per stampa JSON


# TODO function to check the given password
def pwdCheck(pwd):
    res = pwn.checkPwd(pwd)
    print(res)
    # for data in res:
        # implementare funzione per stampa JSON

#============ CHECKER FUNCTIONS =============#

# function to look for API key
def searchAPI():
    print(color.YELLOW + color.BOLD + "[-] Searching the API file [-]" + color.END)
    try:
        with open(apiFile, mode='r', encoding='utf-8') as aF:
            k = aF.readline()
        if k:
            print(color.BOLD + '[+] API key found: {} [+]'.format(k) + color.END)
    except FileNotFoundError:
        while 1:
            k = input(color.RED + color.BOLD + '[-] File not found! [-]\nPlease, manually paste here the API key: ' + color.END)
            if k:
                return k

# function to parse the file containing the e-mails
def checkMailFile(fileMail):
    global emails
    # local list to temporaly store emails
    email = []
    title()
    print(color.YELLOW + color.BOLD + '[-] Looking for the mail file {} [-]'.format(fileMail) + color.END)
    try:
        with open(fileMail, mode='rt') as fm:
            print(color.GREEN + color.BOLD + '[+] Mail file found [+]' + color.END)
            print(color.YELLOW + color.BOLD + '[-] Parsing the file [-]' + color.END)
            # getting the lines from the file
            try:
                for line in fm:
                    if re.findall(email_regex, str(line)):
                        email.append(re.findall(email_regex, str(line)))
                for mail in email:
                    for m in mail:
                        emails.append(m)
            except:
                print(color.RED + color.BOLD + '[!] Failed! Aborting... [!]' + color.END)
                time.sleep(2)
                return 0
            print(color.GREEN + color.BOLD + '[+] File parsed successfuly [+]' + color.END)
    except FileNotFoundError:
        print(color.RED + '[!] The file has not been found, please check it! [!]' + color.END)
        return 0
    emails = list(set(emails))
    return 1

# function to parse the file containing the websites
def checkDomFile(fileDom):
    global doms
    title()
    print(color.YELLOW + color.BOLD + '[-] Looking for the domain file {} [-]'.format(fileDom) + color.END)
    try:
        # parsing the file containing the domains to check
        with open(fileDom, encoding='UTF-8', mode='r') as fd:
            print(color.GREEN + color.BOLD + '[+] Domains` file found [+]' + color.END)
            print(color.YELLOW + color.BOLD + '[-] Parsing the file [-]' + color.END)
            # getting the lines from the file
            try:
                for line in fd:
                    line.strip()
                    # cleaning the mail format
                    if '\n' in line:
                        line = str(line[:-1])
                    doms.append(line)
            except:
                print(color.RED + color.BOLD + '[!] Failed! Aborting... [!]' + color.END)
                time.sleep(2)
                return 0
            print(color.GREEN + color.BOLD + '[+] File parsed successfuly [+]' + color.END)
    except FileNotFoundError:
        print(color.RED + '[!] The file has not been found, please check it! [!]' + color.END)
        return 0
    doms = list(set(doms))
    print(doms)
    return 1

# TODO def checkPwdFile():

def disclaimer():
    print(color.BOLD + color.PURPLE + goodbye_string + color.END)

#============== PRINTER FUNCTIONS =============#

def printBreach(breach):
    print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format(breach['Title']))
    print(color.BOLD + '{:<18s}'.format(' Domain:') + color.END + '{:<24s}'.format(breach['Domain']))
    print(color.BOLD + '{:<18s}'.format(' Breach Date:') + color.END + '{:<24s}'.format(breach['BreachDate']))
    print(color.BOLD + '{:<18s}'.format(' Added Date:') + color.END + '{:<24s}'.format(breach['AddedDate']))
    classes = ', '.join(breach['DataClasses'])
    print(color.BOLD + '{:<18s}'.format(' Data breached:') + color.END + '{:<24s}'.format(classes))
    if breach['IsVerified']:
        print(color.BOLD + '{:<18s}'.format(' Verified:') + color.END + '{:<24s}'.format('Yes'))
    else:
        print(color.BOLD + '{:<18s}'.format(' Verified:') + color.END + '{:<24s}'.format('Nope'))
    print(color.BOLD + '{:<18s}'.format(' Pwn Count:') + color.END + '{:<24d}\n'.format(breach['PwnCount']))

#===================== MAIN ==================#

# main function
def main(arguments):
    # show the intro message
    greetings()

    # start by handling a bit the given arguments
    # AUTHENTICATED REQUESTS
    if arguments['--auth']:
        # checking if the API key is set in the code
        if pwn._api_key == None:
            # if not, look for the default file (check doc on github)
            pwn._api_key = searchAPI()
        
        # if user want to retrieve all the breaches for a given account
        if arguments['--AllBreach']:
            # checking if the user has inserted the argument or not
            if arguments['MAIL']:
                
                # if the file has not been provided, skip and take the argument parameter
                if not arguments['--file']:
                    breachedaccount(arguments['MAIL'])
                
                else:
                    # if file's been provided, go check if the file is ok (exist, format)
                    if checkMailFile(arguments['MAIL']):
                        breachedaccount(emails)
            
            else:
                print(color.RED + color.BOLD+ '[!] No arguments found, ejecting... [!]\n' + color.END)
        
        # if user want to check for any pasted mail
        elif arguments['--Pasted']:
            # checking if the user has inserted the argument or not
            if arguments['MAIL']:
                
                # if the file has not been provided, skip and take the argument parameter
                if not arguments['--file']:
                    pasted(arguments['MAIL'])
                
                else:
                    # if file's been provided, go check if the file is ok (exist, format)
                    checkMailFile(arguments['MAIL'])
            
            else:
                print(color.RED + color.BOLD+ '[!] No arguments found, ejecting... [!]\n' + color.END)
    
    # NOT AUTHENTICATED REQUESTS
    elif arguments['--notauth']:
        # giving None value to _api_key var
        pwn._api_key = None
        
        # -b --breach Give a domain, look for its specific breaches
        if arguments['--breach']:
            #TODO implement check for print multiple breaches
            # checking if the user has given the argument or not
            if arguments['NAME']:
                    
                    # if the file has not been provided, skip and take the
                    # argument parameter
                    if not arguments['--file']:
                        """
                        breach(x,y)
                        If x (arguments) == True then y (file) == False
                        and viceversa few step under
                        """
                        breach(arguments['NAME'],0)
                    
                    else:
                        # if file's been provided, go check if the file is ok
                        if checkDomFile(arguments['NAME']):
                            breach(0,doms)
            
            else:
                print(color.RED + color.BOLD+ '[!] No arguments found, ejecting... [!]\n' + color.END)

        # -B --breaches      Retrieve all breaches from HIBP
        elif arguments['--breaches']:
            # checking for any filter
            if arguments['--filter']:
                if arguments['DOMAIN']:
                    # giving the domain to look for to breaches()
                    breaches(arguments['DOMAIN']) 
            else:
                # calling breaches without any filter, it will retrieve all breaches
                breaches()

        elif arguments['--passwd']:
            # if the file has not been provided, skip and take the
            # argument parameter
            if arguments['PASSWORD']:
                if not arguments['--file']:
                    pwdCheck(arguments['PASSWORD'])
                else:
                    # if file's been provided, go check if the file is ok (exist, format)
                    checkPwdFile(arguments['PASSWORD'])
            else:
                print(color.RED + color.BOLD+ '[!] No arguments found, ejecting... [!]\n' + color.END)
    
    # printing disclaimer
    disclaimer()

# #========= END FUNCTION SECTION =======#

if __name__ == "__main__":
    try:
        arguments = docopt(__doc__ , version='0.1.0')
        print(arguments)
        main(arguments)
    except KeyboardInterrupt:
        print("\n\033[91m[!] You have interrupted the stuff with your keyboard, bye. [!]\033[00m")
        time.sleep(3)
        sys.exit(0)
