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


def read_jwt(url, token):

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



def decode_jwt(data):

    #
    # Decoding JWT Header. Just base64. No payload here.
    #

    base64_bytes = base64.b64decode(data, '-_') # Some infos are strangely encoded...
    device = json.loads(base64_bytes)

    str_format = "     | Device {} : " + Fore.LIGHTWHITE_EX + "{}"
    str_format_red = "     | " + Fore.LIGHTRED_EX + "Device {} : " + "{}"

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

    device_key = 'aaid'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: aaguid
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-aaguid
    #     https://fidoalliance.org/specs/fido-v2.0-ps-20150904/fido-key-attestation-v2.0-ps-20150904.html#aaguid-extension
    #
    # The Authenticator Attestation GUID. This field must be set if the authenticator implements FIDO 2.
    # 

    device_key = 'aaguid'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # key: description 
    # ---
    # Human-readable, short description of the authenticator, in English)
    #

    device_key = 'description'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # key: alternativeDescriptions 
    # ---
    # A list of human-readable short descriptions of the authenticator in different languages.
    #

    device_key = 'alternativeDescriptions'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: isSecondFactorOnly
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-isSecondFactorOnly
    #
    # Indicates if the authenticator is designed to be used only as a second factor, i.e. requiring some other authentication method as a first factor (e.g. username+password).
    #

    device_key = 'isSecondFactorOnly'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: operatingEnv
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-operatingEnv
    #     https://fidoalliance.org/specs/fido-security-requirements-v1.1-fd-20171108/fido-authenticator-allowed-restricted-operating-environments-list-v1.1-fd-20171108.html
    #
    # Description of the particular operating environment that is used for the Authenticator.
    # 

    device_key = 'operatingEnv'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: verificationMethodDescriptor
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#verificationmethoddescriptor-dictionary
    #
    # A descriptor for a specific base user verification method as implemented by the authenticator.
    # 

    device_key = 'verificationMethodDescriptor'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: supportedExtensions
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-supportedExtensions
    #
    # List of extensions supported by the authenticator.
    # 

    device_key = 'supportedExtensions'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: matcherProtection
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-matcherProtection
    #     https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#matcher-protection-types
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

    device_key = 'matcherProtection'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: protocolFamily
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-protocolFamily
    #
    # The FIDO protocol family. The values "uaf", "u2f", and "fido2" are supported. If this field is missing, the assumed protocol family is "uaf". Metadata Statements for
    # U2F authenticators must set the value of protocolFamily to "u2f" and FIDO 2.0/WebAuthentication Authenticator implementations must set the value of protocolFamily to "fido2".
    # 

    device_key = 'protocolFamily'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: upv
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-upv
    #
    # The FIDO unified protocol version(s) (related to the specific protocol family) supported by this authenticator. See [UAFProtocol] for the definition of the Version structure.
    # 

    device_key = 'upv'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: isKeyRestricted
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-isKeyRestricted
    #
    # This entry is set to true, if the Uauth private key is restricted by the authenticator to only sign valid FIDO signature assertions.
    # This entry is set to false, if the authenticator doesn't restrict the Uauth key to only sign valid FIDO signature assertions. In this case, the calling application 
    # could potentially get any hash value signed by the authenticator.
    #
    # If this field is missing, the assumed value is isKeyRestricted=true
    # 

    device_key = 'isKeyRestricted'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: keyProtection
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-keyProtection
    #
    # A 16-bit number representing the bit fields defined by the KEY_PROTECTION constants in the FIDO Registry of Predefined Values. This value must be non-zero.
    # 

    device_key = 'keyProtection'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: cryptoStrength
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-cryptoStrength
    # 
    # The authenticator's overall claimed cryptographic strength in bits (sometimes also called security strength or security level). This is the minimum 
    # of the cryptographic strength of all involved cryptographic methods (e.g. RNG, underlying hash, key wrapping algorithm, signing algorithm, attestation 
    # algorithm), e.g. see [FIPS180-4], [FIPS186-4], [FIPS198-1], [SP800-38B], [SP800-38C], [SP800-38D], [SP800-38F], [SP800-90C], [SP800-90ar1], [FIPS140-2] etc.
    #

    device_key = 'cryptoStrength'
    if (device_key in device):
        logging.info(str_format_red.format(device_key, device.get(device_key)))


    # Key: authenticationAlgorithm
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-authenticationAlgorithm
    # 
    # The preferred authentication algorithm supported by the authenticator. This value must be non-zero.
    #

    device_key = 'authenticationAlgorithm'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: authenticationAlgorithms
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-authenticationAlgorithms
    # 
    # The list of authentication algorithms supported by the authenticator. Must be set to the complete list of the supported ALG_ constants defined in the FIDO 
    # Registry of Predefined Values if the authenticator supports multiple algorithms. Each value must be non-zero.
    #

    device_key = 'authenticationAlgorithms'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: publicKeyAlgAndEncoding
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-publicKeyAlgAndEncodings
    #
    # The list of public key formats supported by the authenticator during registration operations. 
    # 

    device_key = 'publicKeyAlgAndEncoding'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: isFreshUserVerificationRequired
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-isFreshUserVerificationRequired
    #
    # If true, user verification is required. Else, it is the responsibility of the App to ask for user consent.If this field is missing, the assumed value is true.
    #

    device_key = 'isFreshUserVerificationRequired'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: tcDisplay (transaction confirmation display)
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-tcDisplay
    #
    # A 16-bit number representing a combination of the bit flags defined by the TRANSACTION_CONFIRMATION_DISPLAY constants in the FIDO Registry of Predefined Values [FIDORegistry].
    # This value must be 0, if transaction confirmation is not supported by the authenticator.
    #

    device_key = 'tcDisplay'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: tcDisplayContentType
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-tcDisplayContentType
    #
    # Supported MIME content type [RFC2049] for the transaction confirmation display, such as text/plain or image/png.
    # This value must be present if transaction confirmation is supported, i.e. tcDisplay is non-zero.
    # 

    device_key = 'tcDisplayContentType'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: tcDisplayPNGCharacteristics
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-tcDisplayPNGCharacteristics
    #
    # A list of alternative DisplayPNGCharacteristicsDescriptor. 
    # 

    device_key = 'tcDisplayPNGCharacteristics'
    if (device_key in device):
        logging.debug(str_format.format(device_key, device.get(device_key)))


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

    device_key = 'userVerificationDetails'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))

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

    device_key = 'assertionScheme'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))

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

    device_key = 'attachmentHint'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: attestationRootCertificates
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-attestationRootCertificates
    #
    # Each element of this array represents a X.509 certificate that is a valid trust anchor for this authenticator model. The array does not represent a certificate chain, but 
    # only the trust anchor of that chain. 
    #

    device_key = 'attestationRootCertificates'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: attestationCertificateKeyIdentifiers
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-attestationCertificateKeyIdentifiers
    #
    # A list of the attestation certificate public key identifiers encoded as hex string.
    # 

    device_key = 'attestationCertificateKeyIdentifiers'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: attestationTypes
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-attestationTypes
    #
    # The supported attestation type(s). (e.g. ATTESTATION_BASIC_FULL(0x3E07), ATTESTATION_BASIC_SURROGATE(0x3E08)).
    # 

    device_key = 'attestationTypes'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))


    # Key: authenticatorVersion
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-authenticatorVersion
    #
    # Earliest (i.e. lowest) trustworthy authenticatorVersion meeting the requirements specified in this metadata statement.
    # 

    device_key = 'authenticatorVersion'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)))

    # Key: icon
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-icon
    #
    # RFC2397-encoded PNG icon for the Authenticator.
    # 

    device_key = 'icon'
    if (device_key in device):
        logging.info(str_format.format(device_key, "found"))
    else:
        logging.info(str_format.format(device_key, "not found"))


    # Key: legalHeader
    # ---
    # See https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-metadata-statement-v2.0-rd-20180702.html#widl-MetadataStatement-legalHeader
    #
    # The legalHeader, if present, contains a legal guide for accessing and using metadata, which itself may contain URL(s) pointing 
    # to further information, such as a full Terms and Conditions statement.
    # 

    device_key = 'legalHeader'
    if (device_key in device):
        logging.info(str_format.format(device_key, device.get(device_key)[:100] + "..."))



#
# Hey guys, this is a module
# 

if __name__ == "__main__":

    print("Don't ever call me, stupid!")
    sys.exit(1)

