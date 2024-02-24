# RSA Key Info

RSA Key Info is a Python script that extracts information from a given RSA public key file. It can display various details about the key, such as its length, modulus, and prime factors, as well as generate a private key from the extracted modulus.

This script was inspired by the [Breaking RSA](https://tryhackme.com/room/breakrsa) box from TryHackMe.

## Installation

To install RSA Key Info, you can use pip:

```bash
pip install rsa-key-info
```

## Usage

```bash
rsa_key_info.py -k <public_key_file> [-l] [-m] [-f] [-p]
```

- `-k`, `--key`: Path to the RSA public key file (required).
- `-l`, `--length`: Display the length of the RSA key.
- `-m`, `--modulus`: Display the modulus (n) of the RSA key.
- `-f`, `--factorize`: Factorize the modulus into two prime numbers (p and q).
- `-p`, `--private`: Generate a private key using the extracted modulus.

Example usage:

```bash
rsa_key_info.py -k id_rsa.pub -l -m -f -p 
```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.


## Acknowledgements

This script utilizes the pycryptodome library for RSA key handling.
