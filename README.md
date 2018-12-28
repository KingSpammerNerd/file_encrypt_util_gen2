# file_encrypt_util_gen2

file_encrypt_util, now with 2x more paranoia!

Planned: Develop a file encryption utility that utilizes a combination of symmetric and asymmetric encryption. Files are to be encrypted with an AES key, supplied by the user. The Initialization Vector is to consist of the system time, during encryption. The IV key is, in turn, encrypted with a random RSA public key, which will not be stored.

The encryption output file will be structures as follows: (Encrypted IV)%(Ciphertext)%(Hash of plaintext)

Current development stage: null. That's right, I haven't even started on it yet. Don't wait up.
