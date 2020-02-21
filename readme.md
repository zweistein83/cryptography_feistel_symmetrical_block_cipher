## Feistel symmetrical block cipher
[https://en.wikipedia.org/wiki/Feistel_cipher](https://en.wikipedia.org/wiki/Feistel_cipher)
 
crypto = FeistelBlockCipher(padding_char="@", text_encoding="utf-8")

 - **padding_char** (optional): one character which is used for padding if the message is of odd length
 - **text_encoding** (optional): used for converting from and to bytes. Default is "utf-8".

**Encode message:**
  
encoded_message = crypto.encode_message(message, keys, crypto_func) 

- **message:** message that should be encoded as a string.
- **keys:** keys used for encryption as a list of strings. Each key should be unique.
- **crypto_func** (optional): You can pass any cryptographical function that returns bytes. Must also take 2 inputs (message, key). Default is salted md5 which uses key as salt.

**Decode message:**
 
decoded_message = crypto.decode_message(encoded, keys, crypto_func)
- **message:** message that should be encoded as a string.
- **keys:** keys used for decryption as a list of strings. This must be identical to what was used to encrypt the message.
- **crypto_func** (optional): You can pass any cryptographical function that returns bytes. Must also take 2 inputs (message, key). Default is salted md5 which uses key as salt.  Requires the same encryption algorithm as used to encrypt the message.

**Example:**
	
Encode message

    from FeistelBlockCipher import FeistelBlockCipher
    
    message="Lorem ipsum dolor sit amet."  
    keys = ["secret_key1", "secret_key2"]  
    
    crypto = FeistelBlockCipher()  
     
    encoded = crypto.encode_message(message, keys)  
    
    print("\nEncoded message:")  
    print(encoded)  
    -->Encoded message:
	-->8392cefb63d7a06763ac72c1724d29ed32d4838a216a33551468cfb4

    
Decode message:

    from FeistelBlockCipher import FeistelBlockCipher"
    
    crypto = FeistelBlockCipher() 
     
    keys = ["secret_key1", "secret_key2"] 
    encoded_message = "8392cefb63d7a06763ac72c1724d29ed32d4838a216a33551468cfb4"
    decoded = crypto.decode_message(encoded_message, keys)  
    print("\nDecoded message:")  
    print(decoded)
    -->Decoded message:
    -->Lorem ipsum dolor sit amet.
