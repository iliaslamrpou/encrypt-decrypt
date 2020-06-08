# encrypt-decrypt

# RSA & AES encrypt/decrypt


This repository contains c++ code for LINUX environment about the encryption and decryption using the OpenSSL libs <br/>
For all of the tools the C++ code is included on this repository<br/>


**teliasED_sender.c** : The c++ code for the sender
**teliasED_receiver.c** : The c++ code for the receiver
**teliasED.c** : A c++ code that contains both codes and simulate the sendr and the receiver on the same code

Web Page: (https://iliaslamrpou.github.io/knapsack)

## Instructions:

**File:teliasED_sender.exe** :

The file should be in the same folder with the public key.
It accepts a parameter that is the name of the public key file
#	teliasED_sender <publicKeyFilename>
Without the parameter the code will try to read the key from the file named public.pem.
The sender's key can be predefined by the code or read from the disk.
After executing the code, two files will be created:
*rsaOut.txt*: Contains the sender's key encrypted
*aesOut.txt*: Contains the HMAC-SHA256 of the rsaOut.txt file encrypted with AES.
The above two files will be sent to the recipient for decryption.
Below we see the files that are created as a result of executing the code in a Linux environment (CygWin64)

**File teliasED_receiver.exe:**

The recipient must have this file in the same folder with the private key as well as with the above two files rsaOut.txt and aesOut.txt that he will receive from the sender.
It accepts a parameter that is the name of the private key file

#teliasED_sender <publicKeyFilename>

If the parameter is omitted, an attempt will be made to read the file named private.key
The code reads the three files and compares the results.
Finally, it sends a confirmation or failure message.
In case the key has not been altered, it saves it with the name sender.key.

All of these files has to be to the same folder<br/>


## Required hardware and software:
CPU: 32/64bit<br/>
Linux<br/>
Ram: 2Gb<br/>

## Licence: 
This code is created by **Ilias Lamprou** & **Telis Zacharis**
You can use this code for educational use<br/>


`Jun 8 2020`
