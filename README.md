```
                           _____ .__
______  __  _  __  ____  _/ ____\|__|  ____  _______ 
\____ \ \ \/ \/ / /    \ \   __\ |  |_/ __ \ \_  __ \
|  |_> > \     / |   |  \ |  |   |  |\  ___/  |  | \/
|   __/   \/\_/  |___|  / |__|   |__| \___  > |__|   
|__|                  \/                  \/
```
# PwnFier

Python command line tool to look for:
* All breaches for an account
* All breached sites on HIBP | All breaches for a given domain (e.g. adobe.com)
* All breaches for a given site | All breaches for a given name (e.g. Adobe)
* All pastes for an account
* Pwned passwords


*For more detail, please go to [HIBP API overview](https://haveibeenpwned.com/API/v3)*
### How it works
This is how the script gears run:
1. The script takes the args parsed from the command line
2. Checks if the user has provided an authenticated request or not
3. Checks if the user has provided the argument or a file as input & check if the file is good
4. Sends the query to HIBP with the API
5. Shows the result | Saves result to file

### Prerequisites & dependecies

* Python version: `3.7`
* [HIBP](https://haveibeenpwned.com) API KEY for authenticated requests
* [Docopt](http://docopt.org/) as command-line interface description language
* [Art](https://github.com/sepandhaghighi/art) for the ASCII art

### How to use it
```
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
  -S --save          Save the output to standard file
  -h --help          Show this screen

  Some examples:
  pwnfier.py -aAf mailFile.txt
  pwnfier.py -nBF yahoo.com
  pwnfier.py -nb  Adobe
```
### File's format
The file that the user wants to pass must be formatted as the following:
| Data        | File extension   | Format  |
| ------------- |:-------------:| ------:|
| API          | .txt  | 1 LINE |
| Domains          | .txt  | OEPL |
| Names | .txt  | OEPL  |
| Passwords | .txt  | OEPL |
| E-Mails | .txt      | AYW |

*OEPL: One Entry Per Line*

*AYW: As You Want, the script will grab every regex matching e-mail*
### Standard ouput file
At the beginning of the code, you can find the variables to set to choose the output file's name and path.
The extension is JSON.
The default path is the current working directory.

Default names are:
| Type of query        | File extension |
| ------------- |:-------------:| 
| All breaches          | pwnfier_account.json |
| Pastes          | pwnfier_pasted.json |
| Single breach | pwnfier_breach_res.json |
| All breaches | pwnfier_breaches_res.json |
| Pwned passwords | pwnfier_pwd_res.json |

#### The *all breaches* query if not filtered will automatically save the output to file.

## Purpose of this tool
Monitoring the confidentiality of any account.
I've created it just for educational purpose and I am not a professional dev.

Feel free to show me better ways to do it.

## Authors

* **Andrea Grigoletto** - [Wirzka](https://github.com/wirzka)

## Acknowledgments

* Thanks to [HIBP](https://haveibeenpwned.com) for the service offered
* Thanks to [Vsecades](https://github.com/vsecades) as he inspired me for the API module
