# HTTPS-I
## Image Protected Hypertext Transfer Protocol - Secure

_(by - Aryan Chandrakar **18BCI0174**)_


The currently used HTTPS communication protocols is called the secure version of HTTP using the SSL certificates, which on itself relies on Diffie-Hellman key exchange, making the bypassing of the same pretty easy as shown in implementation. Few of the top websites having a high request percentage on daily basis have started using HSTS where the website is forced to interact over HTTPS connections helping them from the downgrade attack, still these websites are vulnerable to spoof attack, with adversary personifying themselves as the legitimate website and stealing the sensitive information, the solution to which is discussed in upcoming part. The HTTPS-I protocol works to solve the issue, in addition to not allowing attacks like cookie theft, session hijack and MITM attacks. The structure of the protocol is quite simple yet costing for the sender and receiver on the processing side. It requires a bit more of computation when compared to HTTPS but offers a better front for safety of the user. It does the same by introducing the option of not just encrypting the content like the one being done in HTTPS but also hiding the content from the plain sight, with no proof of data being shared between the users, instead just a few random bytes which even if compromised has no way of telling what the byte represents nor what does the representation contains.

![image](https://user-images.githubusercontent.com/49098125/171038124-42ba78f2-7b61-48ad-b831-1628f08ff010.png)

To describe the protocol in shorts steps we can conclude as follows-
1. Client generates the request
	* The request gets hidden in an image
	* The image is converted to bytes
	* The bytes are encrypted using AES 
	* The encrypted bytes are sent to Server A
2. The encrypted bytes are received and decrypted by Server A with a hash check
	* The decrypted bytes are converted into image
	* The image is decoded to fetch the request hidden in it
3. The requested data is collected from the host server A.
4. The response from the host server is encoded into image
	* The image is converted to bytes and encrypted using AES
	* The encrypted data is sent to client
5. The cipher is decrypted and the hash is matched
	* The decrypted bytes are converted to image to fetch the response data from the same. 

## Implementation
### Import Libraries

Import the required libraries using `pip3 install [library_name]`

Required libraries-
* pubnub
* Crypto
* binascii
* colorma
* scapy
* cv2
* numpy
* docopt
* PIL

### Create key sets

Form 3 different pairs of keyset at the [pubnub's website](https://admin.pubnub.com/#/login) in order to configure the network. _(this mimics HTTPS connection)_

The key would look like - 
* Publish key - `pub-c-254457e7-0f7d-47fc-1234-3b08a21577c8`
* Suscribe key - `sub-c-bf3a2d30-88b9-11fd-9f2b-a2cedba671e8`

### RSA keys

If need you can create your own pair of RSA keyset using [_Encryption.py_](https://github.com/aryanchandrakar/Trunk-Routing-Protocol/blob/a634e8ebf2cd548347040f35d88c07b08369c13c/Encryption.py) else can use the one used in the code.
Keys used in the code are fetched from .privkey and .pubkey files keep them saved.

### Running the Protocol

The protocol runs on the server created between the host website and the client as shown in the figure above.
1. In order to run the simulation of the same open up 2 terminals and a your browser window.
2. Run the file [Server.py](Server.py) and [Client.py](Client.py) on the termianls using `python3 file_name.py`. Both the files access the other python libraries themselves to run hassle free.
3. Once both the scripts are running one can go on to searching anything on the browser.
4. In order to test the security of the same use [sniffer.py](sniffer.py) formed to sniff the network to fetch and read the communication packets.

### [OUTPUT](https://github.com/aryanchandrakar/HTTPS-I/tree/main/OUTPUT)
1. As we start browsing across website you could see the request being generated on the Client's terminal.
2. The request can be seen getting encoded into image, encrypted and base changed before sending to the server.
3. On the Server's terminal the request can be seen being received, being decrypted, converted into image and getting decoded to fetch the request.
4. Once the request is fetched the server sends the response back to client to complete the transaction.
  * Refer OUTPUT file for reference to how it works.  
