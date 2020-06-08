# RSA & AES encrypt/decrypt example code (OpenSSL)

This repository contains c++ code for LINUX environment about encryption and decryption using the OpenSSL libs <br/>
For all of the tools the C++ code is included in this repository<br/>


**teliasED_sender.c** : The c++ code for the sender<br/>
**teliasED_receiver.c** : The c++ code for the receiver<br/>
**teliasED.c** : A c++ code that contains both codes and simulates the sender and the receiver on the same code<br/>


## Instructions:

File:**teliasED_sender.exe** :

The file should be in the same folder with the public key.<br/>
It accepts a parameter that is the name of the public key file<br/><br/>
**	teliasED_sender** publicKeyFilename<br/><br/>
Without the parameter the code will try to read the key from the file named *public.pem*.<br/>
The sender's key can be predefined by the code or read from the disk.<br/>
After executing the code, two files will be created:<br/>
    **rsaOut.txt**: Contains the sender's key encrypted<br/>
    **aesOut.txt**: Contains the HMAC-SHA256 of the rsaOut.txt file encrypted with AES.<br/>
The above two files will be sent to the recipient for decryption.<br/>
Below we see the files that are created as a result of executing the code in a Linux environment (CygWin64)<br/>

File **teliasED_receiver.exe:**<br/>
The recipient must have this file in the same folder with the private key as well as with the above two files rsaOut.txt and aesOut.txt that he will receive from the sender.<br/>
It accepts a parameter that is the name of the private key file<br/><br/>

**teliasED_sender** privateKeyFilename<br/>

If the parameter is omitted, an attempt will be made to read the file named *private.key*
The code reads the three files and compares the results.
Finally, it sends a confirmation or failure message.
In case the key has not been altered, it saves it with the name sender.key.

All of these files have to be in the same folder<br/>


## Required hardware and software:
CPU: 32/64bit<br/>
Linux<br/>
Ram: 2Gb<br/>

## Licence: 
This code is created by **Ilias Lamprou** & **Telis Zacharis**<br/><br/>
You can use this code for educational purposes<br/>


`Jun 8 2020`
