# PwnFier

Python command line tool to look for:
* All breaches for an account
* All breached sites on HIBP | All breaches for a given domain (e.g. adobe.com)
* All breaches for a given site | All breaches for a given name (e.g. Adobe)
* All pastes for an account
* Pwned passwords

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
```

## Purpose of this tool
Monitoring the confidentiality of any account.
I've created this tool just for educational purpose.
Feel free to show me better way to do it.

## Authors

* **Andrea Grigoletto** - [Wirzka](https://github.com/wirzka)

## Acknowledgments

* Thanks to [HIBP](https://haveibeenpwned.com) for the service offered
* Thanks to [Vsecades](https://github.com/vsecades) as he inspired me for the API module
