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

    logging.info("Header  | Cert. issuer : " + Fore.LIGHTWHITE_EX + "{}".format(cert.issuer.rfc4514_string()))
    logging.info("Header  | Cert. subject : " + Fore.LIGHTWHITE_EX + "{}".format(cert.subject.rfc4514_string()))
    logging.info("Header  | Cert. serial number : " + Fore.LIGHTWHITE_EX + "{}".format(cert.serial_number))
    logging.info("Header  | Cert. not valid before : " + Fore.LIGHTWHITE_EX + "{}".format(cert.not_valid_before))
    logging.info("Header  | Cert. not valid after : " + Fore.LIGHTWHITE_EX + "{}".format(cert.not_valid_after))
    logging.info("Header  | Cert. version : " + Fore.LIGHTWHITE_EX + "{}".format(cert.version))
    logging.info("Header  | Cert. signature : " + Fore.LIGHTWHITE_EX + "{}".format(binascii.hexlify(cert.signature, ':')))
    logging.info("Header  | Cert. signature algo. : " + Fore.LIGHTWHITE_EX + "{}".format(cert.signature_algorithm_oid._name))
    logging.info("Header  | Cert. signature hash algo. : " + Fore.LIGHTWHITE_EX + "{}".format(cert.signature_hash_algorithm.name))
    const.display_extentions(logging, cert.extensions)

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

    logging.info("Header  | CA Cert. issuer : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.issuer.rfc4514_string()))
    logging.info("Header  | CA Cert. subject : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.subject.rfc4514_string()))
    logging.info("Header  | CA Cert. serial number : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.serial_number))
    logging.info("Header  | CA Cert. not valid before : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.not_valid_before))
    logging.info("Header  | CA Cert. not valid after : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.not_valid_after))
    logging.info("Header  | CA Cert. version : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.version))
    logging.info("Header  | CA Cert. signature : " + Fore.LIGHTWHITE_EX + "{}".format(binascii.hexlify(ca_cert.signature, ':')))
    logging.info("Header  | CA Cert. signature algo. : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.signature_algorithm_oid._name))
    logging.info("Header  | CA Cert. signature hash algo. : " + Fore.LIGHTWHITE_EX + "{}".format(ca_cert.signature_hash_algorithm.name))
    const.display_extentions(logging, cert.extensions)

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
    



#
# Hey guys, this is a module
# 

if __name__ == "__main__":

    print("Don't ever call me, stupid!")
    sys.exit(1)

