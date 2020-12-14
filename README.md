# fido2-test

This program reads the FIDO repository. This repository contains all known FIDO devices with their certification status. This 
program only aims at gathering all information for all devices, displaying them in a "human-readable" format.

# How it works
The first API call gets the TOC (Table Of Content) with references for all devices.

Then, for each device, we call the API to get information about the device, especially the certification status
and the CA Root Certificate used for the device. This mean that you can verify the device's certificate using 
this CA Root Certificate. If the signature is valid, the device is the expected one. 

# HOWTO
First you need to get a token to call the FIDO API. Go to https://mds2.fidoalliance.org/, register, and get the token.
You can either put it in a 'access_token' file in the same directory that 'fido.py', or you can put it as argument in
the command line, like this : 

    py fido.py --token XXXXXXXXXXXXXXXXXXXXXXX

If you want to have an output file with all devices details, add -o argument.

    py fido.py --token XXXXXXXXXXXXXXXXXXXXXXX -o result.json

