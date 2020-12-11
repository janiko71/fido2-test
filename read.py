import os, sys, logging
import binascii
import argparse
import requests, jwt
import fido2

from colorama import Fore, Back, Style 

from cryptography import x509
from cryptography.hazmat.backends import default_backend

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

    token = None

    try:

        with open("access_token", "r") as f:
            token = f.read()
        logging.info("Find file containing access token, token is " + Fore.LIGHTWHITE_EX + token)

    except FileNotFoundError:

        logging.info("No file containing access token, trying to get it from command line")

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

    #
    # Parsing command line arguments, if any
    #

    parser = argparse.ArgumentParser(description="Read datas from FIDO2 repository")
    parser.add_argument("-t", "--token", help="token used for FIDO2 repository API call")
    args = parser.parse_args()
    logging.info(args)
    
    return args


def decode_jwt(data):

    #
    # Decoding JWT Header
    #

    jh = jwt.get_unverified_header(data)
    logging.info("Header | Algo : " + Fore.LIGHTWHITE_EX + "{}".format(jh['alg']))
    logging.info("Header | Type : " + Fore.LIGHTWHITE_EX + "{}".format(jh['typ']))

    # https://tools.ietf.org/html/rfc7515#page-11
    # The "x5c" (X.509 certificate chain) Header Parameter contains the X.509 public key certificate or certificate chain [RFC5280]
    # corresponding to the key used to digitally sign the JWS.

    x5c = jh['x5c']

    #
    # Sender certificate
    #

    raw_cert = bytes('-----BEGIN CERTIFICATE-----\n' + x5c[0] + '\n-----END CERTIFICATE-----', 'UTF8')
    cert = x509.load_pem_x509_certificate(raw_cert, default_backend())

    logging.info("Header | Cert. issuer : " + Fore.LIGHTWHITE_EX + "{}".format(cert.issuer.rfc4514_string()))
    logging.info("Header | Cert. subject : " + Fore.LIGHTWHITE_EX + "{}".format(cert.subject.rfc4514_string()))
    logging.info("Header | Cert. serial number : " + Fore.LIGHTWHITE_EX + "{}".format(cert.serial_number))
    logging.info("Header | Cert. not valid before : " + Fore.LIGHTWHITE_EX + "{}".format(cert.not_valid_before))
    logging.info("Header | Cert. not valid after : " + Fore.LIGHTWHITE_EX + "{}".format(cert.not_valid_after))
    logging.info("Header | Cert. version : " + Fore.LIGHTWHITE_EX + "{}".format(cert.version))
    logging.info("Header | Cert. signature : " + Fore.LIGHTWHITE_EX + "{}".format(binascii.hexlify(cert.signature, ':')))
    logging.info("Header | Cert. signature algo. : " + Fore.LIGHTWHITE_EX + "{}".format(cert.signature_algorithm_oid._name))
    logging.info("Header | Cert. signature hash algo. : " + Fore.LIGHTWHITE_EX + "{}".format(cert.signature_hash_algorithm.name))
    logging.info("Header | Cert. extensions : " + Fore.LIGHTWHITE_EX + "{}".format(cert.extensions))

    '''
         crypto.verify(
            self.ca.cert,
            cert.signature,
            cert.tbs_certificate_bytes,
            'sha256') 
    '''
    #
    # CA Certificate
    #

    raw_ca_cert = bytes('-----BEGIN CERTIFICATE-----\n' + x5c[1] + '\n-----END CERTIFICATE-----', 'UTF8')
    ca_cert = x509.load_pem_x509_certificate(raw_cert, default_backend())

    logging.info("Header | CA Cert. issuer : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.issuer.rfc4514_string()))
    logging.info("Header | CA Cert. subject : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.subject.rfc4514_string()))
    logging.info("Header | CA Cert. serial number : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.serial_number))
    logging.info("Header | CA Cert. not valid before : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.not_valid_before))
    logging.info("Header | CA Cert. not valid after : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.not_valid_after))
    logging.info("Header | CA Cert. version : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.version))
    logging.info("Header | CA Cert. signature : " + Fore.LIGHTWHITE_EX + "{}".format(binascii.hexlify(ca_cert.signature, ':')))
    logging.info("Header | CA Cert. signature algo. : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.signature_algorithm_oid._name))
    logging.info("Header | CA Cert. signature hash algo. : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.signature_hash_algorithm.name))
    logging.info("Header | CA Cert. extensions : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.extensions))

    #
    # Decoding JWT Data
    #

    jd = jwt.decode(data, verify=False)
    entries = jd['entries']

    logging.info("Data | no : " + Fore.LIGHTWHITE_EX + "{}".format(jd['no']))
    logging.info("Data | Next update : " + Fore.LIGHTWHITE_EX + jd['nextUpdate'])
    logging.info("Data | Nb of entries : " + Fore.LIGHTWHITE_EX + str(len(entries)))

    for entry in entries:
        logging.info("Data | --------------------------------------------------------------------")
        if ('aaid' in entry):
            logging.info("Data | Entry aaid : " + Fore.LIGHTWHITE_EX + "{}".format(entry['aaid']))
        if ('url' in entry):
            logging.info("Data | Entry url : " + Fore.LIGHTWHITE_EX + "{}".format(entry['url']))
        if ('timeOfLastStatusChange' in entry):
            logging.info("Data | Entry last status change : " + Fore.LIGHTWHITE_EX + "{}".format(entry['timeOfLastStatusChange']))
        if ('hash' in entry):
            logging.info("Data | Entry hash : " + Fore.LIGHTWHITE_EX + "{}".format(entry['hash']))

        # NEXT STEP: Call URL with token, show information, verify certificate


    logging.info("Legal : " + Fore.LIGHTWHITE_EX + jd['legalHeader'])



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
        if not(token):
            logging.error("No token found. Aborting.")
            sys.exit(2) 

    # GO!
    # ---

    logging.info("Line command arguments : " + str(argv))

    ###raw_data = read_fido2_jwt(token)
    with open("test.jwt","r") as f:
        raw_data = f.read()
    decode_jwt(raw_data)


#
# This is the end of everything
# 

if __name__ == "__main__":

    print()
    main(sys.argv[1:])
    print(Fore.RESET)

