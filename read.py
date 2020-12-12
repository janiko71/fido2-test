import os, sys, logging
import signal
import json
import binascii, base64
import argparse
import requests, jwt
import fido2

from colorama import Fore, Back, Style 

from cryptography import x509
from cryptography.hazmat.backends import default_backend

import res.device as device
import res.repository as repository
import res.const as const



def get_token():

    #
    # Read acces token from file or from command line
    #

    token = None

    try:

        with open("access_token", "r") as f:
            token = f.read()
        logging.info("Find file containing access token, token is " + Fore.LIGHTWHITE_EX + token)

    except FileNotFoundError:

        logging.info("No file containing access token, trying to get it from command line")

    return token


def parse_args(argv):

    #
    # Parsing command line arguments, if any
    #

    parser = argparse.ArgumentParser(description="Read datas from FIDO2 repository")
    parser.add_argument("-t", "--token", help="token used for FIDO2 repository API call")
    args = parser.parse_args()
    logging.info(args)
    
    return args


def signal_handler(sig, frame):

    # Just to prevent verbose aborting

    print('\nCtrl+C detected, aborting silently...')
    sys.exit(0)


def main(argv):

    # Set log options
    # ---
    str_format = format=Fore.LIGHTWHITE_EX + '%(asctime)s %(levelname)s ' + Fore.RESET + '%(message)s'
    logging.basicConfig(format=str_format, level=const.LOG_LEVEL)

    # Arguments
    # ---
    args = parse_args(argv)  

    # If token in args, ignore file "access_token"
    if (args.token):
        token = args.token
        logging.info("Found token in arguments, ignoring access_token file")
    else:
        token = get_token()
        if not(token):
            logging.error("No token found. Aborting.")
            sys.exit(2) 

    # GO!
    # ---

    logging.info("Line command arguments : " + str(argv))

    raw_data = repository.read_fido2_jwt(token)
    '''
    with open("test.jwt","r") as f:
        raw_data = f.read()
    '''
    repository.decode_jwt(raw_data, token)



#
# This is the end of everything
# 

if __name__ == "__main__":

    print()
    signal.signal(signal.SIGINT, signal_handler)
    
    try:
        main(sys.argv[1:])
    finally:
        print(Fore.RESET)

