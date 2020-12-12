import logging

# colorama constants
TERM_UNDERLINE = '\033[04m'
TERM_RESET     = '\033[0m'

# URL of FIDO2 repository
# ---
FIDO_URL = "https://mds2.fidoalliance.org/"

# Define your log level
# ---
LOG_LEVEL = logging.INFO

# FIDO STATUS
GOOD_STATUS = {'FIDO_CERTIFIED','FIDO_CERTIFIED_L1','FIDO_CERTIFIED_L2','FIDO_CERTIFIED_L3','FIDO_CERTIFIED_L4','FIDO_CERTIFIED_L5','FIDO_CERTIFIED_L1'}
BAD_STATUS = {'NOT_FIDO_CERTIFIED','REVOKED','USER_VERIFICATION_BYPASS','ATTESTATION_KEY_COMPROMISE','USER_KEY_REMOTE_COMPROMISE','USER_KEY_PHYSICAL_COMPROMISE'}


# Formatting
sep = " | "

# Device constants

class MatcherProtection:

    #
    # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#matcher-protection-types
    #

    values = {
        '0x0001': 'SOFTWARE',
        '0x0002': 'TEE',
        '0x0004': 'ON_CHIP',
    }

    def __init__(self, value):
        self.value = value

    def __str__(self):

        res = ""
        found = False

        for key in self.values.keys():

            if (self.value & eval(key)):
                res += sep if found else ""
                res += self.values[key]
                found = True

        return res

    def __repr__(self):

        return str(self)


class UserVerificationMethod:

    # 
    # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#user-verification-methods
    # 

    values = {
        '0x00000001': 'PRESENCE',
        '0x00000002': 'FINGERPRINT',
        '0x00000004': 'PASSCODE',
        '0x00000008': 'VOICEPRINT',
        '0x00000010': 'FACEPRINT',
        '0x00000020': 'LOCATION',
        '0x00000040': 'EYEPRINT',
        '0x00000080': 'PATTERN',
        '0x00000100': 'HANDPRINT',
        '0x00000200': 'NONE',
        '0x00000400': 'ALL'
    }

    def __init__(self, value):
        self.value = value

    def __str__(self):

        res = ""
        found = False

        for key in self.values.keys():

            if (self.value & eval(key)):
                res += sep if found else ""
                res += self.values[key]
                found = True

        return res

    def __repr__(self):

        return str(self)


class KeyProtection:

    # 
    # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#key-protection-types
    # 

    values = {
        '0x00000001': 'SOFTWARE',
        '0x00000002': 'HARDWARE',
        '0x00000004': 'TEE',
        '0x00000008': 'SECURE_ELEMENT',
        '0x00000010': 'REMOTE_HANDLE'
    }

    def __init__(self, value):
        self.value = value

    def __str__(self):

        res = ""
        found = False

        for key in self.values.keys():

            if (self.value & eval(key)):
                res += sep if found else ""
                res += self.values[key]
                found = True

        return res

    def __repr__(self):

        return str(self)


class AuthenticationAlgorithms:

    # 
    # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#authentication-algorithms
    # 

    values = {
        '0x00000001': 'SECP256R1_ECDSA_SHA256_RAW',
        '0x00000002': 'SECP256R1_ECDSA_SHA256_DER',
        '0x00000003': 'RSASSA_PSS_SHA256_RAW',
        '0x00000004': 'RSASSA_PSS_SHA256_DER',
        '0x00000005': 'SECP256K1_ECDSA_SHA256_RAW',
        '0x00000006': 'SECP256K1_ECDSA_SHA256_DER',
        '0x00000007': 'SM2_SM3_RAW',
        '0x00000008': 'RSA_EMSA_PKCS1_SHA256_RAW',
        '0x00000009': 'RSA_EMSA_PKCS1_SHA256_DER',
        '0x0000000A': 'RSASSA_PSS_SHA384_RAW',
        '0x0000000B': 'RSASSA_PSS_SHA512_RAW',
        '0x0000000C': 'RSASSA_PKCSV15_SHA256_RAW',
        '0x0000000D': 'RSASSA_PKCSV15_SHA384_RAW',
        '0x0000000E': 'RSASSA_PKCSV15_SHA512_RAW',
        '0x0000000F': 'RSASSA_PKCSV15_SHA1_RAW',
        '0x00000010': 'SECP384R1_ECDSA_SHA384_RAW',
        '0x00000011': 'SECP521R1_ECDSA_SHA512_RAW',
        '0x00000012': 'ED25519_EDDSA_SHA256_RAW',
    }

    def __init__(self, value):
        self.value = value

    def __str__(self):

        res = ""
        found = False
        
        if type(self.value) == int:

            for key in self.values.keys():

                if (self.value & eval(key)):

                    res += sep if found else ""
                    res += self.values[key] 
                    found = True

        else:

            for algo in self.value:

                for key in self.values.keys():

                    if (algo == eval(key)):

                        res += sep if found else ""
                        res += self.values[key] 
                        found = True

        return res

    def __repr__(self):

        return str(self)



class tcDisplay:

    # 
    # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#transaction-confirmation-display-types
    # 

    values = {
        '0x00000001': 'ANY',
        '0x00000002': 'PRIVILEGED_SOFTWARE',
        '0x00000004': 'TEE',
        '0x00000008': 'HARDWARE',
        '0x00000010': 'REMOTE'
    }

    def __init__(self, value):
        self.value = value

    def __str__(self):

        res = ""
        found = False

        for key in self.values.keys():

            if (self.value & eval(key)):
                res += sep if found else ""
                res += self.values[key]
                found = True

        return res

    def __repr__(self):

        return str(self)


class AuthenticatorAttachmentHints:
    
    # 
    # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#authenticator-attachment-hints
    # 

    values = {
        '0x00000001': 'INTERNAL',
        '0x00000002': 'EXTERNAL',
        '0x00000004': 'WIRED',
        '0x00000008': 'WIRELESS',
        '0x00000010': 'NFC',
        '0x00000020': 'BLUETOOTH',
        '0x00000040': 'NETWORK',
        '0x00000080': 'READY',
        '0x00000080': 'READY_STATE',
        '0x00000100': 'WIFI_DIRECT'
    }

    def __init__(self, value):
        self.value = value

    def __str__(self):

        res = ""
        found = False

        for key in self.values.keys():

            if (self.value & eval(key)):
                res += sep if found else ""
                res += self.values[key]
                found = True

        return res

    def __repr__(self):

        return str(self)



class AuthenticatorAttestation:
    
    # 
    # https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-registry-v2.0-rd-20180702.html#authenticator-attestation-types
    #
    # Can be a list.
    # 

    values = {
        '0x3E07': 'BASIC_FULL',
        '0x3E08': 'BASIC_SURROGATE',
        '0x3E09': 'ECDAA',
        '0x3E0A': 'ATTCA'
    }

    def __init__(self, value):
        self.value = value

    def __str__(self):

        res = ""
        found = False

        for attestation in self.value:

            for key in self.values.keys():

                if (attestation == eval(key)):
                    res += sep if found else ""
                    res += self.values[key]
                    found = True

        return res

    def __repr__(self):

        return str(self)

