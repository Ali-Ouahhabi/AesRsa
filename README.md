# AesRsa

python fcrypt.py -e ./KeyA/A_certificate.crt ./KeyB/B_privateKey.key ./Test/plain.txt ./Test/ciphertext.txt
python fcrypt.py -d ./KeyA/A_privateKey.key ./KeyB/B_certificate.crt ./Test/ciphertext.txt ./Test/plain.txt
