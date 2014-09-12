from math import ceil
from time import sleep
from rawhashes import md5, sha1, pad
from simplecrypto.hashes import md5 as simplemd5
from simplecrypto.formats import hex, from_hex, to_bytes

def padding_oracle_attack(ciphertext, tester):
    """
    Discovers the plaintext from an encrypted AES-CBC message.
    Ciphertext must start with the IV and the message must be padded with PKCS#7
    Tester must be a function that takes a ciphertext and returns True if it
    has no padding errors, or False otherwise.

    Returns the plaintext message. The key is not recovered. Requires up to 256
    calls to `tester` per character in the ciphertext.
    """
    join_blocks = lambda b: b''.join(bytes(l) for l in b)
    test = lambda b: tester(join_blocks(b))

    # Breaks the ciphertext into blocks.
    blocks = []
    original_blocks = []
    plaintext_blocks = []
    n_blocks = len(ciphertext) // 16
    for i in range(n_blocks):
        blocks.append(list(ciphertext[i * 16: (i + 1) * 16]))
        original_blocks.append(list(ciphertext[i * 16: (i + 1) * 16]))
        plaintext_blocks.append([0] * 16)

    # Skips the first block because it's the IV.
    for block in reversed(range(1, n_blocks)):
        # We can safely ignore the blocks after the one we are trying to
        # decrypt.
        active_blocks = blocks[:block + 1]

        for char in reversed(range(0, 16)):
            padding_len = 16 - char

            # Change the ciphertext so the next bytes will be interpreted as
            # padding.
            for i in range(char + 1, 16):
                active_blocks[block - 1][i] = plaintext_blocks[block][i] ^ original_blocks[block - 1][i] ^ padding_len

            # Twiddles the corresponding bit of the previous block until we get
            # a valid padding, which means we can find the plaintext.
            for perturbation in range(1, 0x100):
                active_blocks[block - 1][char] = (active_blocks[block - 1][char] + 1) % 0xFF
                if test(active_blocks):
                    plaintext_blocks[block][char] = active_blocks[block - 1][char] ^ padding_len ^ original_blocks[block - 1][char]
                    break

        # Restore the block we were twiddling with.
        blocks[block - 1] = list(original_blocks[block - 1])

    # Removes the padding, ironically.
    plaintext = join_blocks(plaintext_blocks[1:])
    padding_len = plaintext[-1]
    assert padding_len > 0
    message, padding = plaintext[:-padding_len], plaintext[-padding_len:]
    assert all(p == padding_len for p in padding)
    return message

def extend(algo, data, extension, secret_length, secretdata_hash):
    """
    Extends a hashed message without knowing a part of it.
    Computes (extended_data, appended_hash) such that
    hash(secret || extended_data) == appended_hash, where `extended_data`
    starts with `data` and ends with `extension`.
    """
    data = to_bytes(data)
    extension = to_bytes(extension)
    secretdata_hash = to_bytes(secretdata_hash)

    secretdata_length = len(data) + secret_length
    padded_data = pad(data, secretdata_length, 'little' if algo == md5 else 'big')

    total_length = secret_length + len(padded_data) + len(extension)
    return padded_data + extension, algo(extension, total_length, secretdata_hash)

def extend_md5(data, extension, secret_length, secretdata_hash):
    return extend(md5, data, extension, secret_length, secretdata_hash)

def extend_sha1(data, extension, secret_length, secretdata_hash):
    return extend(sha1, data, extension, secret_length, secretdata_hash)

if __name__ == '__main__':
    secret = b'secret'
    data = b'data'
    secretdata_hash = md5(secret + data)
    appended_data, appended_hash = extend_md5(data, b'append', len(secret), secretdata_hash)
    print(appended_data)
    print(hex(appended_hash), '==', hex(md5(secret + appended_data)))

    secret = b'secret'
    data = b'data'
    secretdata_hash = sha1(secret + data)

    appended_data, appended_hash = extend_sha1(data, b'append', len(secret), secretdata_hash)
    print(appended_data)
    print(hex(appended_hash), '==', hex(sha1(secret + appended_data)))
