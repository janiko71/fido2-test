import os, sys, logging
import argparse
import requests, jwt
import fido2

from colorama import Fore, Back, Style 

# colorama constants
TERM_UNDERLINE = '\033[04m'
TERM_RESET     = '\033[0m'

# URL of FIDO2 repository
# ---
FIDO_URL = "https://mds2.fidoalliance.org/"

# Define your log level
# ---
LOG_LEVEL = logging.INFO



def get_token():

    #
    # Read acces token from file or from command line
    #

    try:

        with open("access-token", "r") as f:
            token = f.read()

    except FileNotFoundError:

        logging.info("No file containing access token, trying to get it from command line")

    logging.info("Find file containing access token, token is " + Fore.RESET + token)

    return token


def read_fido2_jwt():

    #
    # Call FIDO2 repository
    #

    token = get_token()

    curl_url = FIDO_URL + "?token=" + token

    try:

        u = "" #requests.get(curl_url)

        status_code = u.status_code
        reason      = u.reason
        content     = u.content
        logging.info("Status code : {} ({})".format(status_code, reason))
        logging.info("Content lenght (encoded) : {} bytes".format(len(content)))

    except requests.HTTPError as httpe:

        print(httpe)


def parse_args(argv):

    parser = argparse.ArgumentParser(description="ertzrtz")
    parser.add_argument("-t", "--token", help="token used for FIDO2 repository API call")
    args = parser.parse_args()
    logging.info(args)

def main(argv):

    # Set log options
    # ---
    str_format = format=Fore.RESET + '%(asctime)s %(levelname)s ' + Fore.LIGHTWHITE_EX + '%(message)s'
    logging.basicConfig(format=str_format, level=LOG_LEVEL)

    # Arguments
    # ---
    parse_args(argv)        

    # GO!
    # ---
    logging.info("Line command arguments : " + str(argv))
    read_fido2_jwt()



#
# This is the end of everything
# 

if __name__ == "__main__":

    main(sys.argv[1:])

