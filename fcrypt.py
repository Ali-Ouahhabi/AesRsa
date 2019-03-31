import sys
import os
import string
import random

from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import utils

import base64

import __builtin__

from cipher_structure import CipherStructure

example = ''' python fcrypt.py -e ./KeyA/A_certificate.crt ./KeyB/B_privateKey.key ./Test/plain.txt ./Test/ciphertext.txt
python fcrypt.py -d ./KeyA/A_privateKey.key ./KeyB/B_certificate.crt ./Test/ciphertext.txt ./Test/plain.txt '''


public_key_data = None
private_key_data = None
plaintext_file = None
plaintext_data = None
ciphertext_file = None
ciphertext_data = None

exc = getattr(__builtin__, "IOError", "FileNotFoundError")
padding_ = padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def enc():
    global plaintext_data, ciphertext_file
    # symmetric keys generation
    key = os.urandom(32)  # in bytes, 256 bits
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    cipher_text = encryptor.update(plaintext_data) + encryptor.finalize()  # plain text encryption
    tag = encryptor.tag
    tag_s = base64.b64encode(tag)

    public_key = get_pub_key()                                              # getting the public key

    # encrypting tag, key, iv
    tag_encrypted = public_key.encrypt(tag_s, padding_)
    key_encrypted = public_key.encrypt(key, padding_)
    iv_encrypted = public_key.encrypt(iv, padding_)

    # signing the message
    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash, default_backend())
    hasher.update(cipher_text)
    digest = hasher.finalize()

    private_key = get_prv_key()
    sig = private_key.sign(digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                           utils.Prehashed(chosen_hash))

    cipher__ = CipherStructure(cipher_text, key_encrypted, iv_encrypted, tag_encrypted, sig)

    cipher__.dump_to_file(ciphertext_file) # storing the cipher into the desalinated file


def dec():
    global plaintext_file

    public_key = get_pub_key()                                          # getting the public key

    private_key = get_prv_key()                                         # getting the private key

    tls = CipherStructure.load_from_file(ciphertext_file)               # loading the ciphered file to CipherStructure

    chosen_hash = hashes.SHA256()
    hasher = hashes.Hash(chosen_hash, default_backend())
    hasher.update(tls.get_ciphered_text())
    digest = hasher.finalize()
    try:                                                                # verifying signature
        verification = public_key.verify(tls.get_signature(), digest, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                                                                  salt_length=padding.PSS.MAX_LENGTH),
                                         utils.Prehashed(chosen_hash))
    except:
        print ">> ERROR signature verification failed"

    key = private_key.decrypt(tls.get_key(), padding_)                      # decrypting key
    iv = private_key.decrypt(tls.get_initialization_vector(), padding_)     # decrypting iv
    tag = private_key.decrypt(tls.get_tag_sentence(), padding_)             # decrypting tag
    tag = base64.b64decode(tag)                                             # decoding tag

    cipher2 = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher2.decryptor()

    plain_text = decryptor.update(tls.get_ciphered_text()) + decryptor.finalize()  # Decrypting ciphered text

    plaintext_file.write(plain_text)


def random_string(string_length):
    """Generate a random string of fixed length """
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(string_length))


def get_pub_key():
    global public_key_data
    key = x509.load_pem_x509_certificate(public_key_data, default_backend()).public_key()
    if isinstance(key, rsa.RSAPublicKey):
        return key
    else:
        print " private key error"
        sys.exit()


def get_prv_key():
    global private_key_data
    key = load_pem_private_key(private_key_data, password=None, backend=default_backend())
    if isinstance(key, rsa.RSAPrivateKey):
        return key
    else:
        print " public key key error"
        sys.exit()


def enc_arg():

    global public_key_data, private_key_data, plaintext_data, ciphertext_file
    try:
        public_key_data = open(sys.argv[2], "r").read()
    except exc:
        print "File {} was not found".format(sys.argv[2])
        sys.exit()

    try:
        private_key_data = open(sys.argv[3], "r").read()
    except exc:
        print "File {} was not found".format(sys.argv[3])
        sys.exit()

    try:
        plaintext_data = open(sys.argv[4], "r").read()
    except exc:
        print "File {} was not found".format(sys.argv[4])
        sys.exit()

    if os.path.exists(sys.argv[5]):
        inp = raw_input(" file {} already exists do you want to overwrite it [Y|n]".format(sys.argv[5]))
        if inp == 'y' or inp == '':
            ciphertext_file = open(sys.argv[5], "wb")
        else:
            sys.exit()
    else:
        ciphertext_file = open(sys.argv[5], "w")


def dec_arg():

    global public_key_data, private_key_data, plaintext_file, ciphertext_file

    try:
        private_key_data = open(sys.argv[2], "r").read()
    except exc:
        print "File {} was not found".format(sys.argv[2])
        sys.exit()

    try:
        public_key_data = open(sys.argv[3], "r").read()
    except exc:
        print "File {} was not found".format(sys.argv[3])
        sys.exit()

    try:
        ciphertext_file = open(sys.argv[4], "rb")
    except exc:
        print "File {} was not found".format(sys.argv[4])
        sys.exit()

    if os.path.exists(sys.argv[5]):
        inp = raw_input(" file {} already exists do you want to overwrite it [Y|n] ".format(sys.argv[5]))
        if inp == 'y' or inp == '':
            plaintext_file = open(sys.argv[5], "w")
        else:
            sys.exit()
    else:
        plaintext_file = open(sys.argv[5], "w")


def main():
    global example
    if len(sys.argv) >= 6:
        if sys.argv[1] == '-e':
            enc_arg()
            enc()
        elif sys.argv[1] == '-d':
            dec_arg()
            dec()
    else:
        print "arge format"
        print "("
        print "(-e)  (public_key_file) (private_key_file) (plaintext_file) (ciphertext_file) "
        print "|"
        print "(-d) (private_key_filename) (public_key_filename) (ciphertext_file) (plaintext_file)"
        print ")"
        print "[", "-"*120
        print example
        print "-"*120, "]"


if __name__ == '__main__':
    main()
