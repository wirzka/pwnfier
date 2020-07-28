#!/usr/bin/python3
"""
pwnfier.py - Python 3.7.3
   *Author: Andrea Grigoletto - wirzka
   *E-mail: wiirzka@gmail.com
   *Git: https://github.com/wirzka.

Usage:
  pwnfier.py  (-a) (([-A MAIL] | [-P MAIL]) [-f FILEPATH] [-S])
  pwnfier.py  (-n) (([-b NAME] | [-B] [--filter DOMAIN]) [-f FILEPATH] [-S])
  pwnfier.py  (-n) (-p PASSWORD [-f FILEPATH] [-H] [-S])
  pwnfier.py  -h | --help

Options:
  
  User input:
  -a --auth          Use authenticated mode, MUST provide API key
  -n --notauth       Use non authenticated mode, do not provide API key
  -f --file          Insert the file name or absolute path
  -F --filter        Insert the domain to filter e.g. adobe.com
  
  Type of query:
  -b --breach        Give a domain, look for its specific breaches
  -B --breaches      Retrieve all breaches from HIBP (filter with -F)
  -p --passwd        Check for password's leak
  -P --Pasted        Check if the given mail is on Pasted websites
  -A --AllBreach     Check all the given mail's breaches
  -H --hash          If you want to give only directly the password's hash

  Misc:
  -S --save          Save the output to standard file pwnfier_results.json
  -h --help          Show this screen

  Some examples:
  pwnfier.py -aAf mailFile.txt
  pwnfier.py -nBF yahoo.com
  pwnfier.py -nb  Adobe
"""

import hashlib
import json
import pprint
import re
import sys
import time
from art import tprint
from docopt import docopt
import os
import PwnFR


#============ API KEY  ===============#
pwn = PwnFR.PwnFR(api_key='')

#========== GLOBAL VARS ==============#

# API key file path
apiFile = ''

# preconfigured filename for the Save to file option
accountBreachFile = 'pwnfier_account.json'
pastedAccount = 'pwnfier_pasted.json'
breachFile = 'pwnfier_breach_res.json'
breachesFile = 'pwnfier_breaches_res.json'
passwordFile = 'pwnfier_pwd_res.json'

# time to wait before launching consequent API requests, refer to HIBP documentation for more detail
# DO NOT GO UNDER 1.5 sec
stress_freq = 2

# list used to handle the data that must be saved
listToSave = []

#  dictionary to store pwned pwds statistics
pwned_pwd = {
    'Pwned passwords' : 0,
    'Passwords not pwned yet' : 0
}

# regex pattern for email
email_regex = ("([a-zA-Z0-9._%+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]+)")

# regex pattern for domain
dom_regex = ("^(((([A-Za-z0-9]+){1,63}\.)|(([A-Za-z0-9]+(\-)+[A-Za-z0-9]+){1,63}\.))+){1,255}$")

# message for the disclaimer
goodbye_string ="""\n[!] Be Aware
 |   If you can't find a site's or account's breach here, it could already/still be breached. 
 |   Do not reuse passwords for important accounts. Follow Bruce Schneier's method or at least 
 |   use strong password and store them in a safe place. But remind: everything can be hacked.
 |   Stay safe.                                           
[!]  
"""

#========= COLOR OPTION =============#
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


# ======== FANCY FUNCTIONS ===========#

# function that prints the title
def title():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(color.BLUE + color.BOLD)
    tprint("Pwnfier",font="graffiti")
    print(color.END)

# function to print the helper message
def helper():
    print( __doc__)

# function to output the greetings title + helper
def greetings():
    title()
    helper()   

# function to print the final disclaimer
def disclaimer():
    print(color.BOLD + color.PURPLE + goodbye_string + color.END)


# =========== AUTH FUNCTION ============ #
# function to query for all breachedaccount of a given mail
def breachedaccount(mails, save):
    # checking if the given argument is one (str) or more then one (list)
    if type(mails) == str:
        try:
            print(color.YELLOW + color.BOLD + '[-] Querying HIBP for {}\'s breach [-]'.format(mails) + color.END)
            time.sleep(stress_freq)
            # querying HIBP
            res = pwn.breachedaccount(mails)
            # checking if there is content and printing the result
            if res:
                # if the user doesn't want to output to file
                if not save:
                    print(color.RED + color.BOLD +'[!] Found breach for {} [!]'.format(mails) + color.END)
                    print(color.RED + color.BOLD + color.DARKCYAN +'[-] Printing details [-]' + color.END)
                    for breach in res:
                        printAccountBreach(breach)
                else:
                    for breach in res:
                        listToSave.append(breach.copy())
            else:
                print(color.GREEN + color.BOLD + '[!] Good news, still no known breach [!]' + color.END)
        except:
            print(color.RED + color.BOLD+ '[!] Aborting query, something went wrong. Plug the damned wire![!]' + color.END)
    
    elif type(mails) == list:
        print(color.YELLOW + color.BOLD + '[-] Querying HIPB for multiple accounts\' breach [-]\n' + color.END)
        try:
            # looping through the mail list
            for mail in range(0, len(mails)):
                # time to wait before every requests
                time.sleep(stress_freq)
                # querying HIBP
                res = pwn.breachedaccount(mails[mail])
                # checking if there is content and printing the result
                if not save:
                    if res:
                        print(color.RED + color.BOLD +'[!] Found breach for {} [!]'.format(mails[mail]) + color.END)
                        print(color.RED + color.BOLD + color.DARKCYAN +'[-] Printing details [-]' + color.END)
                        for breach in res:
                            printAccountBreach(breach)
                    else:
                        print(color.GREEN + color.BOLD + '[!] Good news, still no known breach for {} [!]'.format(mails[mail]) + color.END)
                else:
                    if not res:
                        listToSave.append({mails[mail] : ' Not breached yet'})
                    else:
                        listToSave.append({mails[mail] : res})
        except:
            print(color.RED + color.BOLD + '[!] Aborting query, something went wrong. Plug the damned wire![!]' + color.END)
    else:
        # handling the case where the argument could have been corrupted/missing for any strange reason
        raise Exception(color.RED + color.BOLD +'[!] No data to work with! [!]' + color.END) 
  
# function to query for all pasted mail
def pasted(mails, save):
    # checking if the given argument is one (str) or more then one (list)
    if type(mails) == str:
        try:
            print(color.YELLOW + color.BOLD + '[-] Querying HIBP for {}\' pastes [-]'.format(mails) + color.END)
            time.sleep(stress_freq)
                # querying HIBP
            res = pwn.pasteaccount(mails)
                # checking if there is content and printing the result
            if not save:
                if res:
                    print(color.RED + color.BOLD +'[!] Found pastes for {} [!]'.format(mails) + color.END)
                    print(color.RED + color.BOLD + color.DARKCYAN +'[-] Printing details [-]' + color.END)
                    printAccountPastes(res)
                else:
                    print(color.GREEN + color.BOLD + '[!] Good news, still no known paste [!]\n' + color.END)
            else:
                for past in res:
                    listToSave.append(past.copy())
        except:
            print(color.RED + color.BOLD+ '[!] Aborting query, something went wrong. Plug the damned wire![!]' + color.END)
    
    elif type(mails) == list:
        print(color.YELLOW + color.BOLD + '[-] Querying HIPB for multiple accounts\' paste [-]' + color.END)
        try:
            # looping through the mail list
            for mail in range(0, len(mails)):
                time.sleep(stress_freq)
                # querying HIBP
                res = pwn.pasteaccount(mails[mail])
                # checking if there is content and printing the result
                    # checking if there is content and printing the result
                if not save:
                    if res:
                        print(color.RED + color.BOLD +'[!] Found pastes for {} [!]'.format(mails[mail]) + color.END)
                        print(color.RED + color.BOLD + color.DARKCYAN +'[-] Printing details [-]' + color.END)
                        printAccountPastes(res)
                    else:
                        print(color.GREEN + color.BOLD + '[!] Good news, still no known paste for {} [!]'.format(mails[mail]) + color.END)
                else:
                    if not res:
                        listToSave.append({mails[mail] : ' Not pasted yet'})
                    else:
                        listToSave.append({mails[mail] : res})
        except:
            print(color.RED + color.BOLD+ '[!] Aborting query, something went wrong. Plug the damned wire![!]' + color.END)
    else:
        # handling the case where the argument could have been corrupted/missing for any strange reason
        raise Exception(color.RED + color.BOLD +'[!] No data to work with! [!]' + color.END)

#============= NOT AUTH FUNCTION ============#
# function to query for all domain's breaches
def breach(names, save):
    global listToSave
    if type(names) == str:
        try:
            print(color.YELLOW + color.BOLD + '[-] Querying HIPB for {}\'s breach [-]'.format(names) + color.END)
            time.sleep(stress_freq)
            res = pwn.breach(names)
            
            if res:
                if not save:
                    print(color.RED + color.BOLD +'[!] Found breach for {} [!]'.format(names) + color.END)
                    print(color.RED + color.BOLD + color.DARKCYAN +'[-] Printing details [-]' + color.END)
                    printBreach(res)
                if save:
                    print(color.RED + color.BOLD +'[!] Found breach for {} [!]'.format(names) + color.END)
                    print(color.RED + color.BOLD + color.DARKCYAN +'[-] Look file for details [-]' + color.END)
                    listToSave.append(res)
            else:
                print(color.GREEN + color.BOLD + '[!] Good news, still no known breach [!]\n' + color.END)
        except:
            print(color.RED + color.BOLD+ '[!] Aborting query, something went wrong. Plug the damned wire![!]' + color.END)
        print(listToSave)
        
    elif type(names) == list:
        print(color.YELLOW + color.BOLD + '[-] Querying HIPB for multiple sites\' breach [-]' + color.END)
        try:
            for name in range(0, len(names)):
                time.sleep(stress_freq)
                res = pwn.breach(names[name])
                if res:
                    if not save:
                        print(color.RED + color.BOLD +'[!] Found breach for {} [!]'.format(names[name]) + color.END)
                        print(color.RED + color.BOLD + color.DARKCYAN +'[-] Printing details [-]' + color.END)
                        printBreach(res)
                        # printMultiSiteBreach(res)
                    if save:
                        print(color.RED + color.BOLD +'[!] Found breach for {} [!]'.format(names[name]) + color.END)
                        print(color.RED + color.BOLD + color.DARKCYAN +'[-] Look file for details [-]' + color.END)
                        listToSave.append(res)
                        
                else:
                    print(color.GREEN + color.BOLD + '[!] Good news, still no known breach for {} [!]'.format(names[name]) + color.END)
        except:
            print(color.RED + color.BOLD+ '[!] Aborting query, something went wrong. Plug the damned wire![!]' + color.END)
    else:
        raise Exception(color.RED + color.BOLD +'[!] No data to work with! [!]' + color.END) 

# function to retrieve all breaches
def breaches(save, filter=None):
    title()
    # if it is filter it will be prompted to scree, otherwise it will saved on a file
    if filter:
        print(color.YELLOW + color.BOLD + '[-] Looking for {}\'s breaches [-]'.format(filter) + color.END)
        res = pwn.breaches(filter)
        print(color.RED + color.BOLD + '[!] Found {} breaches for {} [!]'.format(len(res), filter) + color.END)
        if not save:
            print(color.RED + color.BOLD + color.DARKCYAN +'[-] Printing details [-]' + color.END)
            for data in range(0,len(res)):
                printBreach(res[data])
        else:
            print(color.RED + color.BOLD + color.DARKCYAN +'[-] Saving details to the file {} [-]'.format(breachesFile) + color.END)
            for data in range(0,len(res)):
                listToSave.append(res.copy())
    else:
        print(color.YELLOW + color.BOLD + '[-] Retrieving all the breaches [-]' + color.END)
        res = pwn.breaches()
        print(color.RED + color.BOLD + '[!] Found {} breaches in total [!]'.format(len(res)) + color.END)
        for data in range(0,len(res)):
                listToSave.append(res.copy())

# function to query the given password/s
def pwdCheck(pwds, save, hash=False):
    global listToSave
    if type(pwds) == str:
        flag = False
        print(color.YELLOW + color.BOLD + '[-] Querying HIPB for pwned password [-]' + color.END)
        time.sleep(2)
        if not hash:
            sha1 = pwdHasher(pwds)
            res = pwn.checkPwd(sha1[:5])
            hashTrunks = res.decode().splitlines(False)
            for recs in range(0,len(hashTrunks)):
                if sha1[5:].upper() == hashTrunks[recs].split(':')[0]:
                    flag = True
                    break
                else:
                    flag = False
        else:
            res = pwn.checkPwd(pwds[:5])
            hashTrunks = res.decode().splitlines(False)
            for recs in range(0,len(hashTrunks)):
                if pwds[5:].upper() == hashTrunks[recs].split(':')[0]:
                    flag = True
                    break
                else:
                    flag = False                
        print(pwds)
        # if the hashes are equal the pwd has been pwned
        if flag:
            print(color.RED + color.BOLD +'{:<26s} {} [!]'.format('[!] Found pwned password:',pwds) + color.END)
            if save:
                listToSave.append({pwds:'Yes'})
        else:
            print(color.GREEN + color.BOLD + '{:<26s} {} [!]'.format('[!] Not pwned yet:',pwds) + color.END)
            if save:
                listToSave.append({pwds:'No'})  
          
            
    elif type(pwds) == list:
        n_pwd = len(pwds)
        flag = False
        print(color.YELLOW + color.BOLD + '[-] Querying HIPB for multiple pwned passwords [-]' + color.END)
        for pwd in pwds:
            time.sleep(2)
            if not hash:
                sha1 = pwdHasher(pwd)
                res = pwn.checkPwd(sha1[:5])
                hashTrunks = res.decode().splitlines(False)
                for recs in range(0,len(hashTrunks)):
                    if sha1[5:].upper() == hashTrunks[recs].split(':')[0]:
                        flag = True 
                        break
                    else:
                        flag = False
            else:
                res = pwn.checkPwd(pwd[:5])
                hashTrunks = res.decode().splitlines(False)
                for recs in range(0,len(hashTrunks)):
                    if pwd[5:].upper() == hashTrunks[recs].split(':')[0]:
                        flag = True
                        break
                    else:
                        flag = False   
            if flag:
                print(color.RED + color.BOLD +'{:<26s} {} [!]'.format('[!] Found pwned passwords:', pwd) + color.END)
                pwned_pwd['Pwned passwords'] += 1
                if save:  
                    listToSave.append({ pwd : 'Yes'})
            else:
                print(color.GREEN + color.BOLD + '{:<26s} {} [!]'.format('[!] Not pwned yet:', pwd) + color.END)
                pwned_pwd['Passwords not pwned yet'] += 1
                if save:
                    listToSave.append({pwds:'No'})    
    else:
        raise Exception(color.RED + color.BOLD +'[!] No data to work with! [!]' + color.END)

# =========== UTILITY FUNCTIONS =============#
# Password hasher
def pwdHasher(pwd):
  sha1 = hashlib.sha1(pwd.encode('utf-8')).hexdigest()
  return sha1

# function to save the results on a JSON file
def save2File(data, file):
    json_data = json.dumps(data)
    try:
        print(color.YELLOW + color.BOLD + '[-] Writing the JSON data to the file {} [-]'.format(file) + color.END)
        with open(file, mode='w', encoding='UTF-8') as of:
            of.write(json_data)
        print(color.GREEN + color.BOLD + '[!] File created successfuly [!]' + color.END)
    except:
        print(color.RED + color.BOLD + '[!] File creation failed, sorry [!]' + color.END)

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

# function to parse & check  the file containing the e-mails
def checkMailFile(fileMail):
    # local list to temporaly store emails
    emails = []
    email = []
    title()
    print(color.YELLOW + color.BOLD + '[-] Looking for the mail file {} [-]'.format(fileMail) + color.END)
    try:
        with open(fileMail, mode='rt') as fm:
            print(color.GREEN + color.BOLD + '[+] Mail file found [+]' + color.END)
            print(color.YELLOW + color.BOLD + '[-] Parsing the file [-]' + color.END)
            # getting the lines from the file
            # try:
            for line in fm:
                if re.findall(email_regex, str(line)):
                    email.append(re.findall(email_regex, str(line)))
            for mail in email:
                for m in mail:
                    emails.append(m)
            # except:
                # print(color.RED + color.BOLD + '[!] Failed! Aborting... [!]' + color.END)
                # time.sleep(2)
                # return 0
            print(color.GREEN + color.BOLD + '[+] File parsed successfuly [+]' + color.END)
    except FileNotFoundError:
        print(color.RED + '[!] The file has not been found, please check it! [!]' + color.END)
        return 0
    # removing duplicated entries
    emails = list(set(emails))
    return emails

# function to parse & check  the file containing the websites
def checkDomFile(fileDom):
    title()
    doms = []
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
    # removing duplicated entries
    doms = list(set(doms))
    return doms

# function to parse & check the file containing the passwords
def checkPwdFile(filePwd):
    pwds = []
    title()
    print(color.YELLOW + color.BOLD + '[-] Looking for the passwords file {} [-]'.format(filePwd) + color.END)
    try:
        # parsing the file containing the domains to check
        with open(filePwd, encoding='UTF-8', mode='r') as fp:
            print(color.GREEN + color.BOLD + '[+] Passwords\' file found [+]' + color.END)
            print(color.YELLOW + color.BOLD + '[-] Parsing the file [-]' + color.END)
            # getting the lines from the file
            try:
                for line in fp:
                    line.strip()
                    # cleaning the mail format
                    if '\n' in line:
                        line = str(line[:-1])
                    pwds.append(line)
            except:
                print(color.RED + color.BOLD + '[!] Failed! Aborting... [!]' + color.END)
                time.sleep(1)
                return 0
            print(color.GREEN + color.BOLD + '[+] File parsed successfuly [+]' + color.END)
    except FileNotFoundError:
        print(color.RED + '[!] The file has not been found, please check it! [!]' + color.END)
        return 0
        # removing duplicated entries
    pwds = list(set(pwds))
    return pwds

# function to check if file exists and it is not empty
def emptyFile(file):
    # Check if file exist and it is empty
    return os.path.exists(file) and os.stat(file).st_size == 0

#============== PRINTER FUNCTIONS =============#

def printBreach(breach):
    try:
        print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format(breach['Title']))
    except:
        print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format('None'))
    try:
        print(color.BOLD + '{:<18s}'.format(' Domain:') + color.END + '{:<24s}'.format(breach['Domain']))
    except:
        print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format('None'))
    try:
        print(color.BOLD + '{:<18s}'.format(' Breach Date:') + color.END + '{:<24s}'.format(breach['BreachDate']))
    except:
        print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format('None'))
    try:
        print(color.BOLD + '{:<18s}'.format(' Added Date:') + color.END + '{:<24s}'.format(breach['AddedDate']))
    except:
        print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format('None'))
    try:
        classes = ', '.join(breach['DataClasses'])
        print(color.BOLD + '{:<18s}'.format(' Data breached:') + color.END + '{:<24s}'.format(classes))
    except:
        print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format('None'))
    try:
        if breach['IsVerified']:
            print(color.BOLD + '{:<18s}'.format(' Verified:') + color.END + '{:<24s}'.format('Yes'))
        else:
            print(color.BOLD + '{:<18s}'.format(' Verified:') + color.END + '{:<24s}'.format('Nope'))
    except:
        print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format('None'))
    try:
        print(color.BOLD + '{:<18s}'.format(' Pwn Count:') + color.END + '{:<24d}\n'.format(breach['PwnCount']))
    except:
        print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format('None'))

def printAccountBreach(breach):
    # try:
    print(color.BOLD + '{:<6s}'.format(' Name: ') + color.END + '{:<15s}'.format(breach['Name']))
    # except:
    #     print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format('None'))

def printAccountPastes(res):
    for record in res:
        try:
            print(color.BOLD + '{:<15s}'.format(' Source: ') + color.END + '{:<20s}'.format(record['Source']))
        except:
            print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format('None'))
        try:
            print(color.BOLD + '{:<15s}'.format(' Id: ') + color.END + '{:<20s}'.format(record['Id']))
        except:
            print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format('None'))
        try:
            print(color.BOLD + '{:<15s}'.format(' Title: ') + color.END + '{:<20s}'.format(record['Title']))
        except:
            print(color.BOLD + '{:<15s}'.format(' Title: ') + color.END + '{:<20s}'.format('None'))
        try:
            print(color.BOLD + '{:<15s}'.format(' Date: ') + color.END + '{:<20s}'.format(record['Date']))
        except:
            print(color.BOLD + '{:<15s}'.format(' Date: ') + color.END + '{:<20s}'.format('None'))
        try:
            print(color.BOLD + '{:<15s}'.format(' EmailCount: ') + color.END + '{:<20d}'.format(record['EmailCount']))
        except:
            print(color.BOLD + '{:<18s}'.format(' Title:') + color.END + '{:<24s}'.format('None'))

def pwdStats():
    print('\n' + color.YELLOW + color.BOLD + '[*] Pwned passwords\' stats [*]')
    for key, value in pwned_pwd.items():
        if key == 'Passwords not pwned yet':
            print(color.GREEN + color.BOLD + '{:<24s}:'.format(key) + color.END + '{:>3}'.format(value))
        elif key == 'Pwned passwords':
            print(color.RED + color.BOLD + '{:<24s}:'.format(key) + color.END + '{:>3} \n'.format(value))
        else:
            print("Wtf\n")
            sys.exit(0)

#===================== MAIN ==================#

# main function
def main(arguments):
    # show the intro message
    greetings()
    if arguments['--save']:
        save = True
    else:
        save = False
    # start by handling a bit the given arguments
    # AUTHENTICATED REQUESTS
    if arguments['--auth']:
        # checking if the API key is set in the code
        if pwn._api_key == None:
            # if not, look for the default file (check doc on github)
            pwn._api_key = searchAPI()
        
        # if user want to retrieve all the breaches for a given account
        if arguments['--AllBreach']:
            title()
            # checking if the user has inserted the argument or not
            if arguments['MAIL']:
                
                # if the file has not been provided, skip and take the argument parameter
                if not arguments['--file']:
                    breachedaccount(arguments['MAIL'], save)
                
                else:
                    # if file's been provided, go check if the file is ok (exist, format)
                    if not emptyFile(arguments['MAIL']):
                        emails = checkMailFile(arguments['MAIL'])
                        if emails:
                            breachedaccount(emails, save)
                    else:
                        print(color.RED + color.BOLD+ '[!] File not found or empty! [!]\n' + color.END)
                if save:
                    save2File(listToSave, accountBreachFile)
            else:
                print(color.RED + color.BOLD+ '[!] No arguments found, ejecting... [!]\n' + color.END)
        
        # if user want to check for any pasted mail
        elif arguments['--Pasted']:
            title()
            # checking if the user has inserted the argument or not
            if arguments['MAIL']:
                
                # if the file has not been provided, skip and take the argument parameter
                if not arguments['--file']:
                    pasted(arguments['MAIL'], save)
                
                else:
                    # if file's been provided, go check if the file is ok (exist, format)
                    if not emptyFile(arguments['MAIL']):
                        pastes = checkMailFile(arguments['MAIL'])
                        if pastes:
                            pasted(pastes, save)
                    else:
                        print(color.RED + color.BOLD+ '[!] File not found or empty! [!]\n' + color.END)
                if save:
                    save2File(listToSave, pastedAccount)
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
                    # title()
                    breach(arguments['NAME'], save)
                else:

                    # if file's been provided, go check if the file is ok
                    if not emptyFile(arguments['NAME']):
                        names = checkDomFile(arguments['NAME'])
                        if names:
                            breach(names, save)
                            
                    else:
                        print(color.RED + color.BOLD+ '[!] File not found or empty! [!]\n' + color.END)
                if save:
                    save2File(listToSave, breachFile)
            else:
                print(color.RED + color.BOLD+ '[!] No arguments found, ejecting... [!]\n' + color.END)

        # -B --breaches      Retrieve all breaches from HIBP
        elif arguments['--breaches']:
            # checking for any filter
            if arguments['--filter']:
                if arguments['DOMAIN']:
                    # giving the domain to look for to breaches()
                    breaches(save, arguments['DOMAIN']) 
            else:
                # calling breaches without any filter, it will retrieve all breaches
                breaches(save)
            try:
                save2File(listToSave, breachesFile)
            except:
                print(color.RED + color.BOLD + '[!] Failed calling the save2File function [!]' + color.END)

        elif arguments['--passwd']:
            # if the file has not been provided, skip and take the
            # argument parameter
            if arguments['PASSWORD']:
                # check if there isn't any file provided
                if not arguments['--file']:
                    title()
                    # check if hash option has been provided
                    if arguments['--hash']:
                        pwdCheck(arguments['PASSWORD'], save, True)
                    else:
                        pwdCheck(arguments['PASSWORD'], save, False)
                else:
                    # if file's been provided, go check if the file is ok (exist, format)
                    if not emptyFile(arguments['PASSWORD']):
                        pwds = checkPwdFile(arguments['PASSWORD'])
                        if pwds:
                            # check if hash option has been provided
                            if arguments['--hash']:
                               pwdCheck(pwds, save, True)
                            else:
                                pwdCheck(pwds, save, False)
                        # print a simple response summary
                        pwdStats()
                    else:
                        print(color.RED + color.BOLD+ '[!] File not found or empty! [!]\n' + color.END)
                if save:
                    save2File(listToSave, passwordFile)
            else:
                print(color.RED + color.BOLD+ '[!] No arguments found, ejecting... [!]\n' + color.END)
            
    # printing disclaimer
    disclaimer()

#===================================#

if __name__ == "__main__":
    try:
        arguments = docopt(__doc__ , version='0.1.0')
        main(arguments)
    except KeyboardInterrupt:
        print("\n\033[91m[!] You have interrupted the stuff with your keyboard, bye. [!]\033[00m")
        time.sleep(1)
        sys.exit(0)
