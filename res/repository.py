import os, sys, logging
import signal
import json
import binascii, base64
import argparse
import requests, jwt
import fido2

from colorama import Fore, Back, Style 

from cryptography import x509
from cryptography import exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import asymmetric
from cryptography.x509.extensions import Extension

import res.const as const
import res.device as device

def read_fido2_jwt(token):

    #
    # Call FIDO2 repository
    #

    curl_url = const.FIDO_URL + "?token=" + token

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


def decode_jwt(data, token):

    #
    # Decoding JWT Header
    #

    jh = jwt.get_unverified_header(data)
    logging.info("Header  | Algo : " + Fore.LIGHTWHITE_EX + "{}".format(jh['alg']))
    logging.info("Header  | Type : " + Fore.LIGHTWHITE_EX + "{}".format(jh['typ']))

    # https://tools.ietf.org/html/rfc7515#page-11
    # The "x5c" (X.509 certificate chain) Header Parameter contains the X.509 public key certificate or certificate chain [RFC5280]
    # corresponding to the key used to digitally sign the JWS.

    x5c = jh['x5c']

    #
    # Sender certificate
    #

    raw_cert = bytes('-----BEGIN CERTIFICATE-----\n' + x5c[0] + '\n-----END CERTIFICATE-----', 'UTF8')
    cert = x509.load_pem_x509_certificate(raw_cert, default_backend())

    const.display_cert(logging, "Header", "Cert.", cert)
    const.display_extentions(logging, "header", "TOC cert", cert.extensions)

    #
    # CA Certificate
    #

    raw_ca_cert = bytes('-----BEGIN CERTIFICATE-----\n' + x5c[1] + '\n-----END CERTIFICATE-----', 'UTF8')
    ca_cert = x509.load_pem_x509_certificate(raw_ca_cert, default_backend())

    const.display_cert(logging, "Header", "CA cert.", ca_cert)
    const.display_extentions(logging, "header", "CA cert.", cert.extensions)

    # Does the X509 certificate match the CA certificate's public key?
    ca_public_key = ca_cert.public_key()
    try:
        ca_public_key.verify(cert.signature, cert.tbs_certificate_bytes, asymmetric.ec.ECDSA(hashes.SHA256()))
        print("ok")
    except exceptions.InvalidSignature:
        print("beurk!")

    #
    # Decoding JWT Data
    #

    jd = jwt.decode(data, verify=False)
    entries = jd['entries']

    logging.info("Data    | no : " + Fore.LIGHTWHITE_EX + "{}".format(jd['no']))
    logging.info("Data    | Next update : " + Fore.LIGHTWHITE_EX + jd['nextUpdate'])
    logging.info("Data    | Nb of entries : " + Fore.LIGHTWHITE_EX + str(len(entries)))

    for entry in entries:

        logging.info("Data    | " + "-"*80)
        if ('aaid' in entry):
            logging.info("Data    | Entry aaid : " + Fore.LIGHTWHITE_EX + "{}".format(entry['aaid']))
        if ('url' in entry):
            device_url = entry['url']
            logging.info("Data    | Entry url : " + Fore.LIGHTWHITE_EX + "{}".format(entry['url']))
        if ('timeOfLastStatusChange' in entry):
            logging.info("Data    | Entry last status change : " + Fore.LIGHTWHITE_EX + "{}".format(entry['timeOfLastStatusChange']))
        if ('hash' in entry):
            logging.info("Data    | Entry hash : " + Fore.LIGHTWHITE_EX + "{}".format(binascii.hexlify(bytes(entry['hash'], 'UTF8'), ':')))
        if ('statusReports' in entry):
            analyse_status_report(entry['statusReports'])

        # NEXT STEP: Call URL with token, show information, verify certificate
        device_jwt = device.read_jwt(device_url, token)
        '''
        with open("detail.jwt","r") as f:
            device_jwt = f.read()
        '''
        device.decode_jwt(device_jwt)

    logging.info("Legal : " + Fore.LIGHTWHITE_EX + jd['legalHeader'][:100] + "...")
 

def analyse_status_report(data):

    #
    # Important part: analyzing status reports. May contain a list. We highlight the most recent.
    #

    last_date = None
    most_recent = None

    for certif in data:
        
        if last_date == None:
            most_recent = certif
        else:
            this_date = certif['effectiveDate']
            if (this_date > last_date):
                most_recent = certif

    if ('status' in most_recent.keys()):
        # https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-metadata-service-v1.2-rd-20171128.html#authenticatorstatus-enum
        device_status = certif['status']
        color = Fore.YELLOW
        if (device_status in const.GOOD_STATUS):
            color = Fore.LIGHTGREEN_EX
        elif (device_status in const.BAD_STATUS):
            color = Fore.LIGHTRED_EX
        logging.info("Data    | Most recent certif. status : " + color + "{}".format(certif['status']))

    if ('effectiveDate' in most_recent.keys()):
        logging.info("Data    | Most recent certif. date : " + Fore.LIGHTWHITE_EX + "{}".format(certif['effectiveDate']))
    if ('certificateNumber' in most_recent.keys()):
        logging.info("Data    | Most recent certif. number : " + Fore.LIGHTWHITE_EX + "{}".format(certif['certificateNumber']))
    if ('certificate' in most_recent.keys()):
        logging.info("Data    | Most recent certif. certificate : " + Fore.LIGHTWHITE_EX + "{}".format(certif['certificate']))
    if ('certificationDescriptor' in most_recent.keys()):
        logging.info("Data    | Most recent certif. descriptor : " + Fore.LIGHTWHITE_EX + "{}".format(certif['certificationDescriptor']))
    if ('url' in most_recent.keys()):
        logging.info("Data    | Most recent certif. url : " + Fore.LIGHTWHITE_EX + "{}".format(certif['url']))
    if ('certificationRequirementsVersion' in most_recent.keys()):
        logging.info("Data    | Most recent certif. req.version : " + Fore.LIGHTWHITE_EX + "{}".format(certif['certificationRequirementsVersion']))
    if ('certificationPolicyVersion' in most_recent.keys()):
        logging.info("Data    | Most recent certif. policy version : " + Fore.LIGHTWHITE_EX + "{}".format(certif['certificationPolicyVersion']))
    



def verify_toc_signature():

    #
    # https://fidoalliance.org/metadata/
    #
    # How do I verify the digital signature in the TOC?
    # - The root certificate from the FIDO Alliance is available at https://mds.fidoalliance.org/Root.cer
    # - To validate the digital certificates used in the digital signature, the certificate revocation information is available in the form of CRLs at the following locations
    # - http://mds.fidoalliance.org/Root.crl
    # - http://mds.fidoalliance.org/CA-1.crl
    #

    return


#
# Hey guys, this is a module
# 

if __name__ == "__main__":

    print("Don't ever call me, stupid!")
    sys.exit(1)

