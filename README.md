# AesRsa [python 2.7]

The following programm implements AES in GCM mode to provide encryption and decryption and RSA algorithm for user integrity and confidentilality.

	The encryption & decryption is done by AES GCM mode with a gnenerated key of 256bits.

	The encryption of the key is done by RSA and the provided public key of the reciever. 

	The signature is the RSA encryption of the cyphered text SHA 256 with the private key of the sender 

The generated ciphered file is the serialization of an object from the class CipherStructure containing The encryption of the neccessary keys to decrypt the ciphered text, the signature and ofcourse the encrypted text.

 ### The decryption is processed as follows:
  
	  Deserializing the ciphered file 
	  verifying the signarure: if the verification failed the program will exit with message ">> ERROR signature verification failed" otherwise it will proceed 
	  decrypting the key, the initializing vector and the tag
	  decrypting the ciphered text and store it to the provided file 




### Execution example


#### Encription
	python fcrypt.py -e ./KeyA/A_certificate.crt ./KeyB/B_privateKey.key ./Test/plain.txt ./Test/ciphertext.txt

#### Decryption
	python fcrypt.py -d ./KeyA/A_privateKey.key ./KeyB/B_certificate.crt ./Test/ciphertext.txt ./Test/plain.txt
