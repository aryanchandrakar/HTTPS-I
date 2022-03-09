import base64
from pubnub.callbacks import SubscribeCallback
from pubnub.enums import PNStatusCategory
from pubnub.pnconfiguration import PNConfiguration
from pubnub.pubnub import PubNub
import time
import os
from Crypto.Cipher import AES
from colorama import init, Fore, Back, Style
import LSBsteg as lsb
import scapy.all as scapy
from scapy.layers import http

# ******************** information representation ********************
init(autoreset=True)
print(Style.BRIGHT + Back.WHITE + Fore.BLACK +"-- SERVER --")
print(Style.BRIGHT + Back.BLACK + Fore.RED +"-- Server Log -- ")

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




# *************************************** Connecting client server **********************************************************
## Sending response
def my_publish_callback(envelope, status):
    # Check whether request successfully completed or not
    if not status.is_error():
        pass


## Receiving requests
class MySubscribeCallback(SubscribeCallback):
    def presence(self, pubnub, presence):
        pass
    def status(self, pubnub, status):
        pass

    #  ------- fetching url ------------
    def url(self,packet):
        return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

    def get_url(self,pkt):
        if pkt.haslayer(http.HTTPRequest):
            response = (self.url(pkt))
            return response

    # -------- processing request -------
    def message(self, pubnub, message):
        try:
            msg=message.message
            msgbyte = msg.encode()  # utf-8 str to byte
            msgback = msgbyte[2:1070]  # slicing byte
            bytestr = base64.b64decode(msgback)  # utf-8 byte to base-64 byte

            ciphertext = bytestr[:768] # dividing bytes
            AesIV = bytestr[768:784]
            Authtag = bytestr[768:800]
            encryptedMsg = (ciphertext, AesIV, Authtag) # forming message

            imgbyte = decrypt_AES_GCM(encryptedMsg, secretKey) # decrypting message
            msgdecode = lsb.convert_decode_byte2img(imgbyte) # decoding request from image pixels

            print (Style.BRIGHT + Back.BLACK + Fore.YELLOW +"\n[+] Request from client :-")
            print(Style.BRIGHT + Back.BLACK + Fore.WHITE +str(msgdecode))
            print(Style.BRIGHT + Back.BLACK + Fore.GREEN +"[*] Fetching URLs")

            response=self.get_url(scapy.Ether(msgdecode)) # call fetching url function
            self.send_response(str(response)) # sending response

        except Exception:
            pass

    def send_response(self,url): # sending response
        print(Style.BRIGHT + Back.YELLOW + Fore.RED +"\n[+] Sending response: "+Style.BRIGHT + Back.BLACK + Fore.BLUE+ url +Style.BRIGHT + Back.BLACK + Fore.BLUE)
        pubnub.publish().channel("chan-1").message(url).pn_async(my_publish_callback)



pubnub.add_listener(MySubscribeCallback())
pubnub.subscribe().channels("chan-1").execute()
