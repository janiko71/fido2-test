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
FIDO_URL = "https://ms2.fidoalliance.org/"

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

    logging.info("Find file containing access token, token is " + Fore.LIGHTWHITE_EX + token)

    return token


def read_fido2_jwt(token):

    #
    # Call FIDO2 repository
    #

    curl_url = FIDO_URL + "?token=" + token

    try:

        u = requests.get(curl_url, allow_redirects=False)

        status_code = u.status_code
        reason      = u.reason
        content     = u.content
        logging.info("Status code : " + Fore.LIGHTWHITE_EX + "{} ({})".format(status_code, reason))
        logging.info("Content lenght (encoded) : {} bytes".format(len(content)))

        if (status_code == 200):
            # Got an answer, no problem
            return content
        elif (status_code == 302):
            # Redirection, probably the token is not valid anymore
            logging.warning("The FIDO2 site responded, but the token may be invalid. No data retrieved.")
        else:
            logging.error("Something went wrong with the FIDO2 site. No data retrieved.")

    except requests.exceptions.ConnectionError as err:

        logging.error("Something very bad happened with the API call. " + str(err))


def parse_args(argv):

    parser = argparse.ArgumentParser(description="Read datas from FIDO2 repository")
    parser.add_argument("-t", "--token", help="token used for FIDO2 repository API call")
    args = parser.parse_args()
    logging.info(args)
    
    return args


def main(argv):

    # Set log options
    # ---
    str_format = format=Fore.LIGHTWHITE_EX + '%(asctime)s %(levelname)s ' + Fore.RESET + '%(message)s'
    logging.basicConfig(format=str_format, level=LOG_LEVEL)

    # Arguments
    # ---
    args = parse_args(argv)  

    # If token in args, ignore file "access_token"
    if (args.token):
        token = args.token
        logging.info("Found token in arguments, ignoring access_token file")
    else:
        token = get_token()      

    # GO!
    # ---
    logging.info("Line command arguments : " + str(argv))
    raw_data = read_fido2_jwt(token)



#
# This is the end of everything
# 

if __name__ == "__main__":

    print()
    main(sys.argv[1:])

