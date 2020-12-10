import os, sys, logging, getopt
import requests, jwt
import fido2

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

        token = ""

    logging.info("Got token : " + token)

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


def main(argv):

    # Set log options
    # ---
    logging.basicConfig(format='%(asctime)s %(message)s', level=LOG_LEVEL)

    # Arguments
    # ---
    try:

        opts, args = getopt.getopt(argv,"t",["token="])

    except getopt.GetoptError:

        print("Usage: read.py --token=<token>")
        sys.exit(2)

    token = None
    
    for opt, arg in options:
        if opt in ('-t', '--token'):
            token = arg        

    # GO!
    # ---
    logging.info("Line command arguments : " + str(argv))
    read_fido2_jwt()



#
# This is the end of everything
# 

if __name__ == "__main__":

    main(sys.argv[1:])

