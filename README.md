# EncoderDecoderServer

This application uses multiple executables and Unix Sockets to: Generate an encryption key, send file contents and encryption key over the network to an encryption daemon running, and daemon responds back with encrypted file contents. The decryption client and daemon works in a similar way, but in reverse to decrypt the encrypted file.

This application was developed as a part of a school OS class.

To run the program, the following steps need to be taken:
- Clone the git repository
- Run the makefile command `make all` to compile all of the related executables
- Generate an encryption key of specified length with the command `enc_key_generator <KeyLength> > keyFile`
- Start the encryption and decryption daemons on separate ports in the background with the commands `encrypt_daemon <Port> &` and `decrypt_daemon <Port> &`
- Encrypt a file with the encryption client by doing: `encrypt_client <plaintext file> <key file> <encrypt daemon port> > <Encrypted Text File>`
- Decrypt a file with the decryption client by running `decrypt_client <Encrypted Text File> <key file> <decrypt daemon port> > <New Plaintext File>`

So as an example:
```
make all
enc_key_generator 2000 > keyFile
encrypt_daemon 34567 &
decrypt_daemon 34568 &
encrypt_client myFile keyFile 34567 > encodedFile
decrypt_client encodedFile keyFile 34568 > myFile_v2
```
