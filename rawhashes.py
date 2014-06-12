import math
import struct

def md5pad(message, length):
    message = bytearray(message)
    message.append(0x80)
    if length != 56:
        message.extend([0] * (56 - (length + 1) % 64))
    message += (length * 8).to_bytes(8, byteorder='little')
    return bytes(message)


# Adapted from http://rosettacode.org/wiki/MD5/Implementation#Python
def md5(message, message_length=None, state=b'\x01#Eg\x89\xab\xcd\xef\xfe\xdc\xba\x98vT2\x10'):
    """
    Computes the MD5 of a byte message, optionally starting from an existing state.
    """
    rotate_amounts = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
                      5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
                      4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
                      6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]
     
    constants = [int(abs(math.sin(i+1)) * 2**32) & 0xFFFFFFFF for i in range(64)]

    functions = 16*[lambda b, c, d: (b & c) | (~b & d)] + \
                16*[lambda b, c, d: (d & b) | (~d & c)] + \
                16*[lambda b, c, d: b ^ c ^ d] + \
                16*[lambda b, c, d: c ^ (b | ~d)]
     
    index_functions = 16*[lambda i: i] + \
                      16*[lambda i: (5*i + 1)%16] + \
                      16*[lambda i: (3*i + 5)%16] + \
                      16*[lambda i: (7*i)%16]

    def left_rotate(x, amount):
        x &= 0xFFFFFFFF
        return ((x<<amount) | (x>>(32-amount))) & 0xFFFFFFFF

    message_length = message_length or len(message)
    message = md5pad(message, message_length)
 
    hash_pieces = list(struct.unpack("<LLLL", state))
 
    for chunk_ofst in range(0, len(message), 64):
        a, b, c, d = hash_pieces
        chunk = message[chunk_ofst:chunk_ofst+64]
        for i in range(64):
            f = functions[i](b, c, d)
            g = index_functions[i](i)
            to_rotate = a + f + constants[i] + int.from_bytes(chunk[4*g:4*g+4], byteorder='little')
            new_b = (b + left_rotate(to_rotate, rotate_amounts[i])) & 0xFFFFFFFF
            a, b, c, d = d, new_b, b, c
        for i, val in enumerate([a, b, c, d]):
            hash_pieces[i] += val
            hash_pieces[i] &= 0xFFFFFFFF

    return struct.pack("<LLLL", *hash_pieces)