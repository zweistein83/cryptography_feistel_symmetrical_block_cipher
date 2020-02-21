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
	# better to use binary padding by bitshift left of bytes
	
	if len(txt) % 2 != 0:
		txt += padding_char
	return txt


def remove_pad(txt):
	if txt[-1] == padding_char:
		return txt[:-1]
	return txt
	

def to_bytes(txt):
	if type(txt) is bytes:
		return txt
	return bytes(txt, text_encoding)


		
def rolling_xor(in1, in2):	
	
	#in2 must be the same as in1 or parts of the message would not get encrypted/decrypted
	while len(in2) < len(in1):
		in2 = in2 * 2
	in2 = in2[:len(in1)]
	
	return bytes([a ^ b for a,b in zip(in1, in2)])


def salted_md5(txt, salt):	
	encoded = hashlib.md5(txt + to_bytes(salt))		
	return encoded.digest()


message = "this is a test to check if the decoded message is the same as the original message after encoding and decryption"

message = message

keys = ["salt", "pepper"]


def encode_message(message, keys, crypto_func=salted_md5):
	
	padded_message = pad_odd(message)
	message_bytes = to_bytes(padded_message)
	encoded_message = feistel_symmetrical_block_cipher(message_bytes, crypto_func, keys[0], keys[1])
	return encoded_message.hex()


def decode_message(encoded_message, keys, crypto_func=salted_md5):
	bytes_encoded = bytes.fromhex(encoded_message)
	decoded_message = feistel_symmetrical_block_cipher(bytes_encoded, crypto_func, keys[1], keys[0])
	return remove_pad(decoded_message.decode(text_encoding))	


def feistel_symmetrical_block_cipher(message, crypto_func, key1, key2):
	second_half_index = (len(message) // 2 )
	
	start_left = message[:second_half_index]
	start_right = message[second_half_index:]		
	
	n2_left = start_right #R
	n2_right = rolling_xor(start_left, crypto_func(start_right, key1)) 	
	
	n3_left = n2_right
	n3_right = rolling_xor(n2_left, crypto_func(n2_right, key2))
	
	return n3_right + n3_left
	

encoded = encode_message(message, keys)
decoded = decode_message(encoded, keys)

print("Original message:")
print(message)
print("\nEncoded message:")
print(encoded)
print("\nDecoded message:")
print(decoded)









