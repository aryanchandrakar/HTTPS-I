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

pnconfig.publish_key = 'add_your_key_here' # use keyset used in server.py here
pnconfig.subscribe_key = 'add_your_key_here' # use keyset used in server.py here
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
            print(Style.BRIGHT +Back.YELLOW+ Fore.RED + "\n[!] Request received :"
                  +Style.RESET_ALL+Style.BRIGHT + Fore.CYAN + " "+msg+Style.RESET_ALL)

            msgbyte = msg.encode()  # utf-8 str to byte
            msgback = msgbyte[2:1070]  # slicing byte
            bytestr = base64.b64decode(msgback)  # utf-8 byte to base-64 byte

            print(Style.BRIGHT + Fore.YELLOW + "[*] Decrypting text")
            ciphertext = bytestr[:768] # dividing bytes
            AesIV = bytestr[768:784]
            Authtag = bytestr[768:800]
            encryptedMsg = (ciphertext, AesIV, Authtag) # forming message

            print(Style.BRIGHT + Fore.YELLOW + "[*] Converting text into image")
            imgbyte = decrypt_AES_GCM(encryptedMsg, secretKey) # decrypting message

            print(Style.BRIGHT + Fore.YELLOW + "[*] Decoding request from image")
            msgdecode = lsb.convert_decode_byte2img(imgbyte) # decoding request from image pixels

            print (Style.RESET_ALL+Style.BRIGHT +Back.RED+ Fore.YELLOW +"\n[+] Fetched request from client :"+
                   Style.RESET_ALL+Style.BRIGHT + Fore.WHITE +" "+str(msgdecode))
            print(Style.BRIGHT + Fore.YELLOW +"\n[*] Fetching URLs")

            response=self.get_url(scapy.Ether(msgdecode)) # call fetching url function
            self.send_response(str(response)) # sending response


        except Exception:
            pass

    def send_response(self,url): # sending response
        print(Style.RESET_ALL + Style.BRIGHT + "\n-------------------------------------------------------")
        print(Style.BRIGHT + Back.WHITE + Fore.BLUE +"\n[+] Sending response:"+Style.RESET_ALL+Style.BRIGHT + Fore.GREEN+" "+ url +Style.RESET_ALL)
        print(Style.RESET_ALL + Style.BRIGHT + "\n-------------------------------------------------------")
        pubnub.publish().channel("chan-1").message(url).pn_async(my_publish_callback)



pubnub.add_listener(MySubscribeCallback())
pubnub.subscribe().channels("chan-1").execute()

