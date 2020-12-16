# Copyright (c) 2018 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

# https://herrjemand.medium.com/verifying-fido2-responses-4691288c8770

"""
Connects to the first FIDO device found (starts from USB, then looks into NFC),
creates a new credential for it, and authenticates the credential.
This works with both FIDO 2.0 devices as well as with U2F devices.
On Windows, the native WebAuthn API will be used.
"""
from __future__ import print_function, absolute_import, unicode_literals

from fido2.hid import CtapHidDevice
from fido2.client import Fido2Client, WindowsClient
from fido2.server import Fido2Server
from getpass import getpass
import sys, json, copy, binascii,uuid
import ctypes

from cryptography import x509
from cryptography.hazmat.primitives import serialization

try:
    from fido2.pcsc import CtapPcscDevice
except ImportError:
    CtapPcscDevice = None


def enumerate_devices():
    for dev in CtapHidDevice.list_devices():
        yield dev
    if CtapPcscDevice:
        for dev in CtapPcscDevice.list_devices():
            yield dev


use_prompt = False
pin = None
uv = "discouraged"

if WindowsClient.is_available() and not ctypes.windll.shell32.IsUserAnAdmin():
    # Use the Windows WebAuthn API if available, and we're not running as admin
    client = WindowsClient("https://example1.com")
else:
    # Locate a device
    for dev in enumerate_devices():
        client = Fido2Client(dev, "https://example1.com")
        if client.info.options.get("rk"):
            use_prompt = not (CtapPcscDevice and isinstance(dev, CtapPcscDevice))
            break
    else:
        print("No Authenticator with support for resident key found!")
        sys.exit(1)

    # Prefer UV if supported
    if client.info.options.get("uv"):
        uv = "preferred"
        print("Authenticator supports User Verification")
    elif client.info.options.get("clientPin"):
        # Prompt for PIN if needed
        pin = getpass("Please enter PIN: ")
    else:
        print("PIN not set, won't use")


server = Fido2Server({"id": "example1.com", "name": "Example RP"}, attestation="direct")

user = {"id": b"user_id", "name": "John Doe"}

# Prepare parameters for makeCredential
create_options, state = server.register_begin(
    user,
    resident_key=True,
    user_verification=uv,
    authenticator_attachment="cross-platform",
)

# Create a credential
if use_prompt:
    print("\nTouch your authenticator device now...\n")

result = client.make_credential(create_options["publicKey"], pin=pin)

js = {}

attestation_object = result[0]
client_data = result[1]
js_result_auth = {}
js_result_auth['attestation_object'] = {}
js_result_auth['attestation_object']['att_statement'] = {}
js_result_auth['attestation_object']['att_statement']['alg'] = attestation_object.att_statement['alg']
js_result_auth['attestation_object']['att_statement']['sig'] = str(binascii.hexlify(attestation_object.att_statement['sig']))
x5c = []
for elem in attestation_object.att_statement['x5c']:
    c = x509.load_der_x509_certificate(elem)
    x5c.append(str(c.public_bytes(serialization.Encoding.PEM)))
js_result_auth['attestation_object']['att_statement']['x5c'] = copy.copy(x5c)
js_result_auth['attestation_object']['data'] = str(attestation_object.data)
js_result_auth['attestation_object']['auth_data'] = {}
auth_data = attestation_object.auth_data
js_result_auth['attestation_object']['auth_data']['counter'] = auth_data.counter
js_result_auth['attestation_object']['auth_data']['extensions'] = auth_data.extensions
js_result_auth['attestation_object']['auth_data']['flags'] = auth_data.flags
js_result_auth['attestation_object']['auth_data']['credential_data'] = {}
js_result_auth['attestation_object']['auth_data']['credential_data']['aaguid'] = str(uuid.UUID(bytes=auth_data.credential_data.aaguid))
js_result_auth['attestation_object']['auth_data']['credential_data']['credential_id'] = str(binascii.hexlify(auth_data.credential_data.credential_id))
js_result_auth['attestation_object']['auth_data']['credential_data']['public_key'] = str(auth_data.credential_data.public_key)
js_result_auth['attestation_object']['auth_data']['credential_data']['public_key_hash_algo'] = str(auth_data.credential_data.public_key._HASH_ALG)
js_result_auth['attestation_object']['auth_data']['extensions'] = auth_data.extensions
js_result_auth['attestation_object']['auth_data']['flags'] = auth_data.flags
js_result_auth['attestation_object']['fmt'] = attestation_object.fmt
js_result_auth['client_data'] = {}
js_result_auth['client_data']['b64'] = client_data.b64
js_result_auth['client_data']['challenge'] = str(binascii.hexlify(client_data.challenge))
js_result_auth['client_data']['data'] = client_data.data
js_result_auth['client_data']['hash'] = str(client_data.hash)

js['result_auth'] = js_result_auth

# Complete registration
auth_data = server.register_complete(
    state, client_data, attestation_object
)
credentials = [auth_data.credential_data]

js_auth_data = {}
js_auth_data['counter'] = auth_data.counter 
js_auth_data['extensions'] = auth_data.extensions 
js_auth_data['flags'] = auth_data.flags
cred_data = auth_data.credential_data 
js_auth_data['credential_data'] = {}
js_auth_data['credential_data']['aaguid'] = str(uuid.UUID(bytes=cred_data.aaguid))
js_auth_data['credential_data']['credential_id'] = str(binascii.hexlify(cred_data.credential_id))
js_auth_data['credential_data']['public_key'] = str(cred_data.public_key)
js_auth_data['rp_id_hash'] = str(binascii.hexlify(auth_data.rp_id_hash))

js['auth_data'] = js_auth_data

print("New credential created!")

# Prepare parameters for getAssertion
request_options, state = server.authenticate_begin(user_verification=uv)

# Authenticate the credential
if use_prompt:
    print("\nTouch your authenticator device now...\n")

selection = client.get_assertion(request_options["publicKey"], pin=pin)
result_assertion_response = selection[0]  # There may be multiple responses, get the first.
result_client_data = selection[1]
assertion_response = result_assertion_response[0]
js_assertion = {}
js_assertion['attestation_response'] = {}
js_assertion['attestation_response']['auth_data'] = {}
js_assertion['attestation_response']['auth_data']['counter'] = assertion_response.auth_data.counter
js_assertion['attestation_response']['auth_data']['credential_data'] = assertion_response.auth_data.credential_data
js_assertion['attestation_response']['auth_data']['extensions'] = assertion_response.auth_data.extensions
js_assertion['attestation_response']['auth_data']['flags'] = assertion_response.auth_data.flags
js_assertion['attestation_response']['credential_id'] = str(binascii.hexlify(assertion_response.credential['id']))
js_assertion['attestation_response']['credential_type'] = str(assertion_response.credential['type'])
js_assertion['attestation_response']['data'] = str(assertion_response.data)
js_assertion['attestation_response']['number_of_credentials'] = str(assertion_response.number_of_credentials)
js_assertion['attestation_response']['signature'] = str(binascii.hexlify(assertion_response.signature))
js_assertion['attestation_response']['user'] = str(assertion_response.user)
js_assertion['client_data'] = {}
js_assertion['client_data']['b64'] = result_client_data.b64
js_assertion['client_data']['challenge'] = str(binascii.hexlify(result_client_data.challenge))
js_assertion['client_data']['hash'] = str(binascii.hexlify(result_client_data.hash))
js_assertion['client_data']['data'] = result_client_data.data

js['assertion'] = js_assertion

f = open('donnees_echangees.txt','w')
f.write(json.dumps(js, indent=4))
f.close()

print("USER ID:", assertion_response.user)
print("Cred.ID:", assertion_response.credential)

# Complete authenticator
server.authenticate_complete(
    state,
    credentials,
    assertion_response.credential['id'],
    result_client_data,
    assertion_response.auth_data,
    assertion_response.signature,
)

print("Credential authenticated!")

#
# Now we need to verify device's cert with CA Root certificate from FIDO2 repository
#

with open("", "r", "UTF8") as f:
    repository = json.load(f.read())
#