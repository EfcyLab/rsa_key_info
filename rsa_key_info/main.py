#!/usr/bin/env python

"""
Script: rsa_key_info.py
Author: EfcyLab
Inspired by: https://tryhackme.com/rooms/breakrsa room
Date: 2024-02-24
License: MIT License

Description:
This script extracts information from a given RSA key file, 
including the modulus, key length, and other details.

Usage:
rsa_key_info.py -k <public_key_file> [-l] [-m] [-f] [-p]
"""

import sys, os, pyfiglet
import argparse
from math import floor, isqrt
from Crypto.PublicKey import RSA
from Crypto.PublicKey.RSA import import_key

# title
os.system("clear")
banner = pyfiglet.figlet_format("RSA Key Info")
print(banner)
print("by EfcyLab (@EfcyLab), inspired by https://tryhackme.com/rooms/breakrsa room\n")

def get_key_length(public_key_file):
    """
    Gets the length of the RSA key from the public key file.
    
    Args:
        public_key_file (str): Path to the RSA public key file.
        
    Returns:
        int: The length of the RSA key.
    """
    try:
        # Load the public key
        public_key = import_key(open(public_key_file, 'r').read())
        
        # Get the key length
        key_length = public_key.size_in_bits()
        return key_length
    except FileNotFoundError:
        print("Error: Public key file not found.")
        sys.exit(1)
    except Exception as e:
        print("Error getting key length:", e)
        sys.exit(1)

def extract_modulus_from_public_key(public_key_file):
    """
    Extracts the modulus from a given RSA public key file.
    
    Args:
        public_key_file (str): Path to the RSA public key file.
        
    Returns:
        int: The modulus extracted from the public key.
    """
    try:
        # Load the public key
        public_key = import_key(open(public_key_file, 'r').read())
        
        # Extract the modulus from the public key
        modulus = public_key.n
        return modulus
    except FileNotFoundError:
        print("Error: Public key file not found.")
        sys.exit(1)
    except Exception as e:
        print("Error extracting modulus:", e)
        sys.exit(1)

def factorize(n):
    """
    Factorizes the integer n into two prime numbers p and q.
    
    Args:
        n (int): The integer to factorize.
        
    Returns:
        tuple: A tuple containing the prime factors p and q and their difference.
    """
    # since even numbers are always divisible by 2, one of the factors will always be 2
    if (n & 1) == 0:
        return (n // 2, 2)

    a = isqrt(n)

    # if n is a perfect square the factors will be ( sqrt(n), sqrt(n) )
    if a * a == n:
        return (a, a)

    # n = (a - b) * (a + b)
    # n = a^2 - b^2
    # b^2 = a^2 - n
    while True:
        a += 1
        _b = a * a - n
        b = int(isqrt(_b))
        if (b * b == _b):
            break

    return (a + b, a - b, 2 * b)

def generate_private_key(p, q, e=65537):
    """
    Generate a private key using the prime factors p and q, and the public exponent e.
    
    Args:
        p (int): First prime factor.
        q (int): Second prime factor.
        e (int): Public exponent.
        
    Returns:
        RSA._RSAobj: The generated private key.
    """
    n = p * q
    phi = (p - 1) * (q - 1)
    d = pow(e, -1, phi)  # Modular multiplicative inverse of e modulo phi

    key_params = {
        'n': n,
        'e': e,
        'd': d,
        'p': p,
        'q': q
    }

    return RSA.construct((n, e, d, p, q))

def display_and_save_key(key):
    """
    Displays the private key and asks the user if they want to save it 
    and if so, saves it to a file with permissions set to 600.
    
    Args:
        key (str): The private key to display and potentially save.
    """
    print(f"Generated Private Key:\n{key}")
    save = input("Do you want to save the private key? (yes/no): ").strip().lower()
    if save == "yes":
        filename = input("Enter the filename to save the private key: ").strip()
        with open(filename, 'w') as f:
            f.write(key)
        # Change permissions to 600
        os.chmod(filename, 0o600)
        print(f"Private key saved to {filename} with permissions set to 600.")

def main():
    parser = argparse.ArgumentParser(
        description="Extracts information from a given public RSA key file.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-k", "--key", help="Path to the RSA public key file", required=True)
    parser.add_argument("-l", "--length", help="Display the length of the RSA key", action="store_true")
    parser.add_argument("-m", "--modulus", help="Display the modulus (n) of the RSA key", action="store_true")
    parser.add_argument("-f", "--factorize", help="Factorize the modulus into two prime numbers (p and q)", action="store_true")
    parser.add_argument("-p", "--private", help="Generate a private key using the extracted modulus", action="store_true")
    args = parser.parse_args()

    modulus = extract_modulus_from_public_key(args.key)

    actions = {
        'length': lambda: print("RSA Key Length:", modulus.bit_length(), "bits"),
        'modulus': lambda: print("Modulus (n):", modulus),
        'factorize': lambda: print(f"p: {p[0]}\nq: {p[1]}\ndiff: {p[2]}") if (p := factorize(modulus)) else None,
        'private': lambda: display_and_save_key(generate_private_key(p[0], p[1]).export_key().decode()) if (p := factorize(modulus)) else None
    }

    for option, action in actions.items():
        if getattr(args, option):
            action()
                
if __name__ == "__main__":
    main()
