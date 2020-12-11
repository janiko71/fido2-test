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


def read_device_jwt(url, token):

    #
    # Call repository for one device
    #

    curl_url = url + "?token=" + token

    try:

        logging.info("     | Calling for device information : " + Fore.LIGHTWHITE_EX + "{}".format(curl_url))
        u = requests.get(curl_url, allow_redirects=True)

        status_code = u.status_code
        reason      = u.reason
        content     = u.content
        logging.info("     | Device Status code : " + Fore.LIGHTWHITE_EX + "{} ({})".format(status_code, reason))
        logging.info("     | Device Content lenght (encoded) : {} bytes".format(len(content)))

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


def decode_jwt(data, token):

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
            device_url = entry['url']
            logging.info("Data | Entry url : " + Fore.LIGHTWHITE_EX + "{}".format(entry['url']))
        if ('timeOfLastStatusChange' in entry):
            logging.info("Data | Entry last status change : " + Fore.LIGHTWHITE_EX + "{}".format(entry['timeOfLastStatusChange']))
        if ('hash' in entry):
            logging.info("Data | Entry hash : " + Fore.LIGHTWHITE_EX + "{}".format(entry['hash']))

        # NEXT STEP: Call URL with token, show information, verify certificate
        device_jwt = read_device_jwt(device_url, token)
        '''
        with open("detail.jwt","r") as f:
            device_jwt = f.read()
        '''
        decode_device_jwt(device_jwt)

    logging.info("Legal : " + Fore.LIGHTWHITE_EX + jd['legalHeader'][:100] + "...")


def decode_device_jwt(data):

    #
    # Decoding JWT Header. Just base64. No payload here.
    #

    base64_bytes = base64.b64decode(data, '-_') # Some infos are strangely encoded...
    device = json.loads(base64_bytes)

    str_format = "     | Device {} : " + Fore.LIGHTWHITE_EX + "{}"

    #
    # Displaying information
    #
    # Reference : https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#idl-def-MetadataStatement
    #
    # Values are defined in a FIDO registry : https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html
    # 

    # Key: aaid
    # ---
    # See https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html#authenticator-attestation-id-aaid-typedef
    #
    # Authenticator Attestation ID. This field MUST be set if the authenticator implements FIDO UAF.
    # The AAID is a string with format "V#M", where
    #   "#" is a separator
    #   "V" indicates the authenticator Vendor Code. This code consists of 4 hexadecimal digits.
    #   "M" indicates the authenticator Model Code. This code consists of 4 hexadecimal digits.
    #

    key = 'aaid'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))


    # Key: description 
    # ---
    # Human-readable, short description of the authenticator, in English)
    #

    key = 'description'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))


    # Key: isSecondFactorOnly
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-isSecondFactorOnly
    #
    # Indicates if the authenticator is designed to be used only as a second factor, i.e. requiring some other authentication method as a first factor (e.g. username+password).
    #

    key = 'isSecondFactorOnly'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))


    # Key: matcherProtection
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-matcherProtection
    #
    # A 16-bit number representing the bit fields defined by the MATCHER_PROTECTION constants in the FIDO Registry of Predefined Values
    #
    #   MATCHER_PROTECTION_SOFTWARE 0x0001 
    #       This flag must be set if the authenticator's matcher is running in software. Exclusive in authenticator metadata with MATCHER_PROTECTION_TEE, MATCHER_PROTECTION_ON_CHIP
    #   MATCHER_PROTECTION_TEE 0x0002
    #       This flag should be set if the authenticator's matcher is running inside the Trusted Execution Environment [TEE]. Mutually exclusive in authenticator metadata with MATCHER_PROTECTION_SOFTWARE, MATCHER_PROTECTION_ON_CHIP
    #   MATCHER_PROTECTION_ON_CHIP 0x0004
    #       This flag should be set if the authenticator's matcher is running on the chip. Mutually exclusive in authenticator metadata with MATCHER_PROTECTION_TEE, MATCHER_PROTECTION_SOFTWARE
    # 

    key = 'matcherProtection'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))


    # Key: protocolFamily
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-protocolFamily
    #
    # The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported. If this field is missing, the assumed protocol family is "uaf". Metadata Statements for
    # U2F authenticators must set the value of protocolFamily to "u2f" and FIDO 2.0/WebAuthentication Authenticator implementations must set the value of protocolFamily to "fido2".
    # 

    key = 'protocolFamily'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))


    # Key: upv
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-upv
    #
    # The FIDO unified protocol version(s) (related to the specific protocol family) supported by this authenticator. See [UAFProtocol] for the definition of the Version structure.
    # 

    key = 'upv'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))


    # Key: tcDisplay (transaction confirmation display)
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-tcDisplay
    #
    # A 16-bit number representing a combination of the bit flags defined by the TRANSACTION_CONFIRMATION_DISPLAY constants in the FIDO Registry of Predefined Values [FIDORegistry].
    # This value must be 0, if transaction confirmation is not supported by the authenticator.
    #

    key = 'tcDisplay'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))

    # Key: tcDisplayContentType
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-tcDisplayContentType
    #
    # Supported MIME content type [RFC2049] for the transaction confirmation display, such as text/plain or image/png.
    # This value must be present if transaction confirmation is supported, i.e. tcDisplay is non-zero.
    # 

    key = 'tcDisplayContentType'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))

    # Key: userVerificationDetails
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-userVerificationDetails
    #
    # A list of alternative VerificationMethodANDCombinations. Each of these entries is one alternative user verification method. Each of these alternative user verification 
    # methods might itself be an "AND" combination of multiple modalities.
    # All effectively available alternative user verification methods must be properly specified here. A user verification method is considered effectively available if this 
    # method can be used to either:
    #  - enroll new verification reference data to one of the user verification methods
    #  - unlock the UAuth key directly after successful user verification
    # 

    key = 'userVerificationDetails'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))

    # Key: assertionScheme
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-assertionScheme
    #
    # A list of alternative VerificationMethodANDCombinations. Each of these entries is one alternative user verification method. Each of these alternative user verification methods 
    # might itself be an "AND" combination of multiple modalities.
    # All effectively available alternative user verification methods must be properly specified here. A user verification method is considered effectively available if this method 
    # can be used to either:
    #   - enroll new verification reference data to one of the user verification methods 
    #   - unlock the UAuth key directly after successful user verification
    # 

    key = 'assertionScheme'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))

    # Key: attachmentHint
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-attachmentHint
    #
    # A 32-bit number representing the bit fields defined by the ATTACHMENT_HINT constants in the FIDO Registry of Predefined Values. The ATTACHMENT_HINT constants are flags 
    # in a bit field represented as a 32 bit long. They describe the method an authenticator uses to communicate with the FIDO User Device. These constants are reported and 
    # queried through the UAF Discovery APIs [UAFAppAPIAndTransport], and used to form Authenticator policies in UAF protocol messages. Because the connection state and topology 
    # of an authenticator may be transient, these values are only hints that can be used by server-supplied policy to guide the user experience, e.g. to prefer a device that is 
    # connected and ready for authenticating or confirming a low-value transaction, rather than one that is more secure but requires more user effort.
    #
    # ATTACHMENT_HINT_INTERNAL 0x0001
    #	This flag may be set to indicate that the authenticator is permanently attached to the FIDO User Device.A device such as a smartphone may have authenticator functionality 
    #   that is able to be used both locally and remotely. In such a case, the FIDO client must filter and exclusively report only the relevant bit during Discovery and when 
    #   performing policy matching. This flag cannot be combined with any other ATTACHMENT_HINT flags.
    # ATTACHMENT_HINT_EXTERNAL 0x0002
    #	This flag may be set to indicate, for a hardware-based authenticator, that it is removable or remote from the FIDO User Device. A device such as a smartphone may 
    #   have authenticator functionality that is able to be used both locally and remotely. In such a case, the FIDO UAF Client must filter and exclusively report only the 
    #   relevant bit during discovery and when performing policy matching. This flag must be combined with one or more other ATTACHMENT_HINT flag(s).
    # ATTACHMENT_HINT_WIRED 0x0004
    #	This flag may be set to indicate that an external authenticator currently has an exclusive wired connection, e.g. through USB, Firewire or similar, to the FIDO User Device.
    # ATTACHMENT_HINT_WIRELESS 0x0008
    #	This flag may be set to indicate that an external authenticator communicates with the FIDO User Device through a personal area or otherwise non-routed wireless protocol, 
    #   such as Bluetooth or NFC.
    # ATTACHMENT_HINT_NFC 0x0010
    #	This flag may be set to indicate that an external authenticator is able to communicate by NFC to the FIDO User Device. As part of authenticator metadata, or when reporting 
    #   characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag should also be set as well.
    # ATTACHMENT_HINT_BLUETOOTH 0x0020
    #	This flag may be set to indicate that an external authenticator is able to communicate using Bluetooth with the FIDO User Device. As part of authenticator metadata, or 
    #   when reporting characteristics through discovery, if this flag is set, the ATTACHMENT_HINT_WIRELESS flag should also be set.
    # ATTACHMENT_HINT_NETWORK 0x0040
    #	This flag may be set to indicate that the authenticator is connected to the FIDO User Device over a non-exclusive network (e.g. over a TCP/IP LAN or WAN, as opposed 
    #   to a PAN or point-to-point connection).
    # ATTACHMENT_HINT_READY 0x0080
    #	This flag may be set to indicate that an external authenticator is in a "ready" state. This flag is set by the ASM at its discretion. 
    #

    key = 'attachmentHint'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))

    # Key: attestationRootCertificates
    # ---
    # Each element of this array represents a X.509 certificate that is a valid trust anchor for this authenticator model. The array does not represent a certificate chain, but 
    # only the trust anchor of that chain. 
    #
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-attestationRootCertificates
    #

    key = 'attestationRootCertificates'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))

    # Key: attestationTypes
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-attestationTypes
    #
    # The supported attestation type(s). (e.g. ATTESTATION_BASIC_FULL(0x3E07), ATTESTATION_BASIC_SURROGATE(0x3E08)).
    # 

    key = 'attestationTypes'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))

    # Key: authenticationAlgorithm
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-authenticationAlgorithm
    # 
    # The preferred authentication algorithm supported by the authenticator. This value must be non-zero.
    #

    key = 'authenticationAlgorithm'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))

    # Key: authenticatorVersion
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-authenticatorVersion
    #
    # Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified in this metadata statement.
    # 

    key = 'authenticatorVersion'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))

    # Key: icon
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-icon
    #
    # RFC2397-encoded PNG icon for the Authenticator.
    # 

    key = 'icon'
    if (key in device):
        logging.info(str_format.format(key, "found"))
    else:
        logging.info(str_format.format(key, "not found"))

    # Key: legalHeader
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-legalHeader
    #
    # The legalHeader, if present, contains a legal guide for accessing and using metadata, which itself may contain URL(s) pointing 
    # to further information, such as a full Terms and Conditions statement.
    # 

    key = 'legalHeader'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)[:100] + "..."))

    # Key: publicKeyAlgAndEncoding
    # ---
    #
    # 

    key = 'publicKeyAlgAndEncoding'
    if (key in device):
        logging.info(str_format.format(key, device.get(key)))



def signal_handler(sig, frame):

    # Just to prevent verbose aborting

    print('\nCtrl+C detected, aborting silently...')
    sys.exit(0)


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

    #raw_data = read_fido2_jwt(token)
    #'''
    with open("test.jwt","r") as f:
        raw_data = f.read()
    #'''
    decode_jwt(raw_data, token)


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

