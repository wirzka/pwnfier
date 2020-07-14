# PwnFier

Python command line tool to look for:
* All breaches for an account
* All breached sites on the DB
* All breaches for a given site
* All pastes for an account
* Pwned passwords

### How it works
This is how the script gears run:
1. The script take the args parsed from the command line
2. Check if the user has provided an authenticated request or not
3. Check if the user has provided a file as input & check if the file is good
4. Launch the query to HIBP with the API
5. Shows the results

### Prerequisites & dependecies

* Python version: `3.7`
* [HIBP](https://haveibeenpwned.com) API KEY for authenticated requests
* [AbusedIpDB](https://github.com/vsecades/AbuseIpDb) by [Vsecades](https://github.com/vsecades)
* [Docopt](http://docopt.org/) as command-line interface description language
* [Art](https://github.com/sepandhaghighi/art) for the ASCII art
### How to use it
Once you satisfy all the prerequisites, just launch it and let him do the magic.

## Purpose of this tool
Monitoring the confidentiality of any account.
I've created this tool just for educational purpose.
Feel free to show me better way to do it.

## Authors

* **Andrea Grigoletto** - [Wirzka](https://github.com/wirzka)

## Acknowledgments

* Thanks to [HIBP](https://haveibeenpwned.com) for the service offered
* Thanks to [Vsecades](https://github.com/vsecades) as he inspired me for the API module
