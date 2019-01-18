# kingcrypter

file_encrypt_util, now with 2x more paranoia!

Description: A file encryption library that utilizes a combination of symmetric and asymmetric encryption. Files are to be encrypted with an AES key, supplied by the user. The Initialization Vector is to consist of the difference between system time at the start and end of the data entry process prior to encryption. The IV is then, in turn, encrypted with a random RSA public key, which will not be stored.

In the end the output will consist the encrypted IV, the ciphertext, the plaintext's hash, the RSA private key and its size, encapsulated as an EncryptedOutput object.

Current development stage: Release. Probably final, probably not. Don't wait up.
