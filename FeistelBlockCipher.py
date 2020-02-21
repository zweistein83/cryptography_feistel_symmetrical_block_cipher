# -*- coding: utf-8 -*-

import hashlib


class FeistelBlockCipher:

	def __init__(self, padding_char = "@", text_encoding = "utf-8"):
		self.padding_char = padding_char
		self.text_encoding = text_encoding

	def pad_odd(self, txt):
		"""
		Adds 1 character right padding to input if it's length is odd.
		"""
		if len(txt) % 2 != 0:
			txt += self.padding_char
		return txt

	def remove_pad(self, txt):
		"""
		Removes padding.
		"""
		if txt[-1] == self.padding_char:
			return txt[:-1]
		return txt

	def to_bytes(self, txt):
		"""
		Converts from string to bytes.
		"""
		if type(txt) is bytes:
			return txt
		return bytes(txt, self.text_encoding)

	def rolling_xor(self, in1, in2):
		"""
		Xor bytewise in1 against in2.
		"""
		# in2 must be the same length as in1 or parts of the message would not get encrypted/decrypted
		while len(in2) < len(in1):
			in2 = in2 * 2
		in2 = in2[:len(in1)]

		return bytes([a ^ b for a,b in zip(in1, in2)])

	def salted_md5(self, txt, salt):
		"""
		Returns salted md5 as bytes
		Inputs:
			txt: message as string.
			salt: key/salt as string.
		"""
		md5_encoded = hashlib.md5(txt + self.to_bytes(salt))
		return md5_encoded.digest()

	def encode_message(self, message, encryption_keys, crypto_func=None):
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
		if crypto_func is None:
			crypto_func = self.salted_md5

		padded_message = self.pad_odd(message)
		message_bytes = self.to_bytes(padded_message)
		encoded_message = self.feistel_symmetrical_block_cipher(message_bytes, encryption_keys, crypto_func)
		return encoded_message.hex()

	def decode_message(self, encoded_message, encryption_keys, crypto_func=None):
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
		if crypto_func is None:
			crypto_func = self.salted_md5

		bytes_encoded = bytes.fromhex(encoded_message)
		decoded_message = self.feistel_symmetrical_block_cipher(bytes_encoded, encryption_keys[::-1], crypto_func)

		try:
			decoded_message = decoded_message.decode(self.text_encoding)
		except UnicodeDecodeError:
			raise KeyError("Unable to decrypt message!")

		return self.remove_pad(decoded_message)

	def feistel_symmetrical_block_cipher(self, message, keys, crypto_func):
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
			n_right = self.rolling_xor(n_left, crypto_func(n_right_tmp, key))
			n_left = n_right_tmp

		return n_right + n_left


if __name__ == "__main__":

	message = "this is a test to check if the decoded message is the same as the original message after encoding and decryption"
	keys = ["salt", "pepper", "oregano", "cinnamon", "any text at all", "0113423434øå5634636basdaeer%tertasd_.,Æ"]

	crypto = FeistelBlockCipher()
	encoded = crypto.encode_message(message, keys)
	decoded = crypto.decode_message(encoded, keys)

	print("Original message:")
	print(message)
	print("\nEncoded message:")
	print(encoded)
	print("\nDecoded message:")
	print(decoded)
