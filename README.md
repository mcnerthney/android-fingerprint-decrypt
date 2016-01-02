# android-fingerprint-decrypt
Android encrypting and decrypting with a fingerprint

An example that shows how to encrypt and decrypt a password using a fingerprint.

The main trick for decrypting is don't recreate the key if it already exists and using the iv from the encrypt. 

