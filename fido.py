'''

    Python to read FIDO repository. This repository contains all know FIDO devices with their certification status. This 
    program only aims at gathering all information for all devices, displaying them in a "human-readable" format.

    The first call gets the TOC (Table Of Content) with references to all devices.

    Then, for each device, we call the API to get information about the device, especially the certification status
    and the CA Root Certificate used for the device. This mean that you can verify the device's certificate using 
    this CA Root Certificate. If the signature is valid, the device is the expected one. 

    HOWTO
    =====
    First you need to get a token to call the FIDO API. Go to https://mds2.fidoalliance.org/, register, and get the token.
    You can either put it in a 'access_token' file in the same directory that 'fido.py', or you can put it as argument in
    the command line, like this : 

            py fido.py --token XXXXXXXXXXXXXXXXXXXXXXX

'''





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
    parser.add_argument("-o", "--output", help="filename for the result (in JSON format)")
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
    #logging.basicConfig(format=str_format, level=const.LOG_LEVEL, filename="result.log")

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

    # If an output file is specified, the whole result will be copied (in JSON format)
    if (args.output):
        filename = args.output
    else:
        filename = None

    # GO!
    # ---

    logging.info("Line command arguments : " + str(argv))

    raw_data = repository.read_fido2_jwt(token)
    #
    #--> For testing purpose, you can use a file instead of a real API call
    #    Comment the previous line, uncomment below. To get a test file, call
    #    the URL displayed in the logs, store the result in a file, and open
    #    the file here.
    #
    '''    
    with open("test.jwt","r") as f:
        raw_data = f.read()
    '''
    repository.analyze_response(raw_data, token, filename)



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

