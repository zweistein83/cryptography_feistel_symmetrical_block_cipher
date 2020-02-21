# -*- coding: utf-8 -*-

"""
https://www.youtube.com/watch?v=FGhj3CGxl8I
L = 1. half of message
R = 2. half of message (add padding if odd)
						LR
					L      	 	R
				    |	   	 	|
			
				 xor	 	 	func   <- key1/salt1
				 
						 X   
						 
				  R            L xor funct(R key1)
				  
				  |            |
				 xor        func  <- key2/salt2
				 
				      X
						 
 L xor funct(R key1)      R xor funct (L xor funct (R key 1) key2)
 
					 X
			 
				 join parts
				 
			     ciphertext

"""

import hashlib


padding_char = "@"
text_encoding = "utf-8"


def pad_odd(txt):
	"""
	Adds 1 character right padding to input if it's length is odd.
	"""
	if len(txt) % 2 != 0:
		txt += padding_char
	return txt


def remove_pad(txt):
	"""
	Removes padding.
	"""
	if txt[-1] == padding_char:
		return txt[:-1]
	return txt
	

def to_bytes(txt):
	"""
	Converts from string to bytes.
	"""
	if type(txt) is bytes:
		return txt
	return bytes(txt, text_encoding)


		
def rolling_xor(in1, in2):
	"""
	Xor bytewise in1 against in2.
	"""
	# in2 must be the same length as in1 or parts of the message would not get encrypted/decrypted
	while len(in2) < len(in1):
		in2 = in2 * 2
	in2 = in2[:len(in1)]
	
	return bytes([a ^ b for a,b in zip(in1, in2)])


def salted_md5(txt, salt):
	"""
	Returns salted md5 as bytes
	Inputs:
		txt: message as string.
		salt: key/salt as string.
	"""
	md5_encoded = hashlib.md5(txt + to_bytes(salt))
	return md5_encoded.digest()


def encode_message(message, encryption_keys, crypto_func=salted_md5):
	"""
		Encodes/encrypts message.
		Inputs:
			message: 		The message that is going to be encrypted (string).

			encryption_keys: Different keys as strings. Use 2 or more different keys/salts.

			crypto_func: 	function that encrypts input in form (message, key/salt).
							- The crypto function must return bytes.

		Returns:
			Ciphertext as hexadecimal string.
	"""
	
	padded_message = pad_odd(message)
	message_bytes = to_bytes(padded_message)
	encoded_message = feistel_symmetrical_block_cipher(message_bytes, encryption_keys, crypto_func)
	return encoded_message.hex()


def decode_message(encoded_message, encryption_keys, crypto_func=salted_md5):
	"""
		Inputs:
			Decodes/decrypts encoded message. The encryption keys must be the same as used to encrypt the message.

			message: 		The message that is going to be decrypted (hex string).

			encryption_keys:Different keys as strings. Use 2 or more different keys/salts (list of strings).

			crypto_func: 	function that encrypts input in form (message, key/salt) (function).
							- The crypto function must return bytes.

		Returns:
			Decoded message string
	"""
	bytes_encoded = bytes.fromhex(encoded_message)
	decoded_message = feistel_symmetrical_block_cipher(bytes_encoded, encryption_keys[::-1], crypto_func)
	return remove_pad(decoded_message.decode(text_encoding))


def feistel_symmetrical_block_cipher(message, keys , crypto_func):
	"""
		Inputs:
			message: 		The message that is going to be encrypted or decrypted

			keys: 			Different keys as strings. Use 2 or more different keys/salts.

			crypto_func: 	function that encrypts input in form (message, key/salt).
							- The crypto function must return bytes.

		Returns:
			Encrypted or decrypted bytes
	"""
	second_half_index = (len(message) // 2 )

	n_left = message[:second_half_index]
	n_right = message[second_half_index:]
	for key in keys:
		n_right_tmp = n_right
		n_right = rolling_xor(n_left, crypto_func(n_right_tmp, key))
		n_left = n_right_tmp

	return n_right + n_left


message = "this is a test to check if the decoded message is the same as the original message after encoding and decryption"
keys = ["salt", "pepper", "oregano", "cinnamon", "any text at all"]

encoded = encode_message(message, keys)
decoded = decode_message(encoded, keys)

print("Original message:")
print(message)
print("\nEncoded message:")
print(encoded)
print("\nDecoded message:")
print(decoded)
