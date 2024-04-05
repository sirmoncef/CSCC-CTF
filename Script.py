from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def decrypt_flag(iv_hex, encrypted_aes_key_hex, ciphertext_hex, private_key_pem):
    # Load private key from PEM
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
        backend=default_backend()
    )

    
    iv = bytes.fromhex(iv_hex)
    encrypted_aes_key = bytes.fromhex(encrypted_aes_key_hex)
    ciphertext = bytes.fromhex(ciphertext_hex)

    
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_flag = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_flag.decode()


iv_hex = 'c2e59f7f562a585094eca150b8a4708b'
encrypted_aes_key_hex = '2ce1dc0faa65ee339d7d918ec2771c424ba1e3b8a5513a62f03fb67cbea9a62da33d54ddb360b1e9986e0cd99ea083f4e24da300cef470964bbc77223f38c9e02c53ed29afd670446f3180d19854b28ab40655ab29bddf507cc366958d8425da23ac536a3bab5c1c8165e7a54a6cfc1f3d5bbb29c43fe7134c4f7464d081228a1c6597a1b96dcd5acd1bd0bfd3470d483e2cc09fed41e419b9f18239f3bd1ac4b3ae03aac496c3f74df5ec034ec6adc431e3d5ef3b6cd1f3024306862be507c4cdecebd912b51ee17a6014d3fed696193ee33e5d7d75fed5be14faa4ae6ea105bdbde4e1dccd34fafc02f60e743bd8a8144a9b61ca8005b52a6056cbee94aa86'
ciphertext_hex = '5645a590987525497d92880e91736275c25306d619b2fb0df21a8b8d38ea9808e5e94d9cb8fd5b5f86f9'
private_key_pem = """
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAvT+UPnPMN0dVfJk9K8x7G5RAaidOuqVmz2Lwcon0T7wMHprM
LvuIFq739RWVq3we4jyLSIbJgV2FHwMecajIM6H2W2iGobLFZV2S0E4pStepcDo0
fUxRCZvjuD5sdXdk+o54UYOKeexSq0sS4WFN5+ixsKDiVnTCYfLoqVFdbgivCVLy
Jvhck1xaTvfEFU2KwsrkaJaisG+PlkO1Api3NcofZfdBfBwZcq0rsWrNTqxi3/l8
msfjYL5aTjvX9ir/Wj8UlSjf4xopR2X75hYnExOarhWu7/wHq3q/KoJSETk4budZ
7uIB8HcB/xNu+zl6C3XB8DI6UQqpo1o3JJFOLQIDAQABAoIBAA11mSB78dk4nI7Z
Ay27REIo4A/srb++hbpYKgurXhHRqPcAQWdSAlLCrOXkXBmvIS8r6SgGVgx6Tz5u
ZVrmCx8I9NF5dKHJahqUdh2UgYFOJ0HREeybYeQSDzcKUYJlNGxRd6MsfMvBD/wY
wcX/up+0v/Z06sQFV9HJidyI6eEqY2gK44SoZ6m/og+tkuymYDo15tXmifcS+jW+
VXx2Y6pIGk2CLNMrtGkPYY6zTBsJzwajTEVvpDY/kDX4Afcic0nd7ILjISDrG8Va
gRcSiugSuRImQZIRCbN83FwY6bepsC48rQtPLiG+sBBFuqGEYqquJ/WmQ72Yc/zw
fBIrFUECgYEA+BUNxy1kzzLUrEl3WskRDCyLtCwnCy25Sk9L1WVp+zL2b4duQcVP
XmGEHDiwAAQXTBlLLUvmB5VYfxNwKE7DkfTUzFXAKv231FuXmSABxeht9H8Rk6z5
VF7tO6OkCiwhIAUUY9k6OB/P3uL0praZW5CWVZfcrLJ97lxCJf7zf/0CgYEAw0nT
R6uIqOKu5+TlmlUeEstL0YDZtkoIpAlCSF1sPfqZ4AEARm/dLQwCTiKd+kFqMJ7l
89/iz8WyuXoqbvIh7OlwvhHXisROk4JIStmnFRAxsnBNcfgBj0uIhipcj5gDge0Z
k+++4xWJizFVDWdWIGYQ+/tH6SFQEEc7miVjZfECgYAvsSR38QMbTiNSh8EZQ+Qy
GfI1jfNnk7+2SG5EtP1d3FtB76BDpqHufALAxikXp7Gu4IHyUFAFjzF3JI6AQTwZ
uB6ctbN+0E3h1kXbmyqcGGXjBfakFDHOhX1H5NqpVfh8Rl24IE+v8HWu3KS51ArB
bpdoFwzGan4JL9VLpqq7JQKBgBTYyKkZ8pi0uh8fHDOBaphvA0T2EEeZV5rLMjwv
XOKw4cQ71x+tyVqJsaVNpLeWTBOsoreJ6thrLk0GcYkuZ9i2gsaHeQ7jLdApVDZJ
TcC93dBClMHZy7DUS1qnIwJhI962xMg6C5KKNgiZ1456vYLv4lhD1sVYPQe/0uj9
nMLBAoGBAJYE6avN9gRxo6p5Ra2zR38rAKNaPD3Iyb1v+sigqooun90mnMFIk/vA
tI9X/X+Y7j/g40Itokj1LdPAqcLhK2zWx5HpaTfqTFTbzkMVJiJGZdP9WMIhBnFI
0yyQJLSpaXC0oaux7oxXBBRfcNCtpD6kFynVmsKP6aCFBN8weeWs
-----END RSA PRIVATE KEY-----
"""


decrypted_flag = decrypt_flag(iv_hex, encrypted_aes_key_hex, ciphertext_hex, private_key_pem)
print("Decrypted Flag:", decrypted_flag)


#Flag: CSCC{A3s_4nd_R34_g00d_c0mb1n4t10n_R1gHt?}
