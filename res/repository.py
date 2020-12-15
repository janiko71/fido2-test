import os, sys, logging
import signal
import json
import binascii, base64
import argparse
import requests, jwt

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


def analyze_response(data, token, filename, filename_test_devices):

    #
    # Analyzing FIDO API response. If a filename is provided, the repository content will be written in JSON format.
    #

    json_file_content = {}
    json_readable_content = {}

    if (filename):
        logging.info("Found output argument, writing JSON result to " + Fore.LIGHTWHITE_EX + filename)
    else:
        logging.info("No arg for file output")

    #
    # Decoding JWT Header
    #

    jh = jwt.get_unverified_header(data)
    json_readable_header = {}

    logging.info(const.str_format.format("Header", "Algo", jh['alg']))
    logging.info(const.str_format.format("Header", "Type", jh['typ']))

    if (filename):
        # raw data
        json_file_content['header'] = jh
        # readable data
        readable_json = {}
        readable_json['alg'] = jh['alg']
        readable_json['typ'] = jh['typ']
        json_readable_header = readable_json

    # https://tools.ietf.org/html/rfc7515#page-11
    # The "x5c" (X.509 certificate chain) Header Parameter contains the X.509 public key certificate or certificate chain [RFC5280]
    # corresponding to the key used to digitally sign the JWS.

    x5c = jh['x5c']

    #
    # Sender certificate
    #

    raw_cert = bytes('-----BEGIN CERTIFICATE-----\n' + x5c[0] + '\n-----END CERTIFICATE-----', 'UTF8')
    cert = x509.load_pem_x509_certificate(raw_cert, default_backend())

    readable_cert = const.display_cert(logging, "Header", "Cert.", cert)
    readable_ext  = const.display_extentions(logging, "header", "TOC cert", cert.extensions)

    if (filename):
        # readable data
        json_readable_header['x5c'] = {}
        json_readable_header['x5c']['fido_cert'] = {}
        json_readable_header['x5c']['fido_cert']['cert_info'] = readable_cert
        json_readable_header['x5c']['fido_cert']['cert_extensions'] = readable_ext
    

    #
    # CA Certificate
    #

    raw_ca_cert = bytes('-----BEGIN CERTIFICATE-----\n' + x5c[1] + '\n-----END CERTIFICATE-----', 'UTF8')
    ca_cert = x509.load_pem_x509_certificate(raw_ca_cert, default_backend())

    readable_cert = const.display_cert(logging, "Header", "CA cert.", ca_cert)
    readable_ext  = const.display_extentions(logging, "header", "CA cert.", cert.extensions)

    if (filename):
        # readable data
        json_readable_header['x5c']['ca_cert'] = {}
        json_readable_header['x5c']['ca_cert']['cert_info'] = readable_cert
        json_readable_header['x5c']['ca_cert']['cert_extensions'] = readable_ext

    # 
    # Does the X509 certificate match the CA certificate's public key?
    # --> We assume we have an Elliptic Curve Key and SHA256 hash
    #

    ca_public_key = ca_cert.public_key()

    try:

        ca_public_key.verify(cert.signature, cert.tbs_certificate_bytes, asymmetric.ec.ECDSA(hashes.SHA256()))
        logging.info("The signature of the TOC certificate is verified by to CA Certificate")

    except exceptions.InvalidSignature:

        logging.error(Fore.LIGHTRED_EX + "*** ERROR : TOC certificate signature does not match the signature of the CA Certificate ***")
        logging.error(Fore.LIGHTRED_EX + "*** ERROR : TOC certificate signature does not match the signature of the CA Certificate ***")
        logging.error(Fore.LIGHTRED_EX + "*** ERROR : TOC certificate signature does not match the signature of the CA Certificate ***")
        print(Fore.RESET + "Aborting...")
        sys.exit(1)

    #
    # Decoding JWT Data
    #

    jd = jwt.decode(data, verify=False)
    entries = jd['entries']
    json_readable_data = {}

    logging.info(const.str_format.format("Data", "no", jd['no']))
    logging.info(const.str_format.format("Data", "Next update", jd['nextUpdate']))
    logging.info(const.str_format.format("Data", "Nb of entries", str(len(entries))))
    logging.info("Legal : " + Fore.LIGHTWHITE_EX + jd['legalHeader'][:300] + "...")

    for entry in entries:

        logging.info("Data    | " + "-"*80)
        if ('aaid' in entry):
            logging.info(const.str_format.format("Data", "aaid", entry['aaid']))
        if ('url' in entry):
            device_url = entry['url']
            logging.info(const.str_format.format("Data", "url", entry['url']))
        if ('timeOfLastStatusChange' in entry):
            logging.info(const.str_format.format("Data", "Entry last status change", entry['timeOfLastStatusChange']))
        if ('hash' in entry):
            logging.info(const.str_format.format("Data", "Entry hash", binascii.hexlify(bytes(entry['hash'], 'UTF8'), ':')))
        if ('statusReports' in entry):
            analyse_status_report(entry['statusReports'])

        # NEXT STEP: Call URL with token, show information, verify certificate
        if (filename_test_devices):
            # Test mode
            with open(filename_test_devices,"r") as f:
                device_jwt = f.read()
        else:
            # Real API call
            device_jwt = device.read_jwt(device_url, token)

        device_detail = device.analyze_device(device_jwt)

        entry['detail'] = device_detail

    # Now we add the device's details in the global JSON
    if (filename):
        json_file_content["entries"] = entries
        json_readable_content['header'] = json_readable_header
        json_readable_content['data'] = json_readable_data
    
    # 
    # You asked for a file?
    #

    if (filename):

        # raw datas
        f = open(filename, "w", encoding="UTF8")
        f.write(json.dumps(json_file_content))
        f.close()

        # readable datas
        f = open(filename + ".read", "w", encoding="UTF8")
        f.write(json.dumps(json_readable_content))
        f.close()
 

def analyse_status_report(data):

    #
    # Important part: analyzing status reports. May contain a list. We display the most recent only.
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
        logging.info(const.str_format.format("Data", "Most recent certif. status", color + certif['status']))

    if ('effectiveDate' in most_recent.keys()):
        logging.info(const.str_format.format("Data", "Most recent certif. date", certif['effectiveDate']))
    if ('certificateNumber' in most_recent.keys()):
        logging.info(const.str_format.format("Data", "Most recent certif. number", certif['certificateNumber']))
    if ('certificate' in most_recent.keys()):
        logging.info(const.str_format.format("Data", "Most recent certificate", certif['certificate']))
    if ('certificationDescriptor' in most_recent.keys()):
        logging.info(const.str_format.format("Data", "Most recent certif. descriptor", certif['certificationDescriptor']))
    if ('url' in most_recent.keys()):
        logging.info(const.str_format.format("Data", "Most recent certif. url", certif['url']))
    if ('certificationRequirementsVersion' in most_recent.keys()):
        logging.info(const.str_format.format("Data", "Most recent certif. req.version", certif['certificationRequirementsVersion']))
    if ('certificationPolicyVersion' in most_recent.keys()):
        logging.info(const.str_format.format("Data", "Most recent certif. policy version", certif['certificationPolicyVersion']))
    
     


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

