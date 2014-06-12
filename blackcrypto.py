from rawhashes import md5, md5pad
from simplecrypto.hashes import md5 as simplemd5
from simplecrypto.formats import hex, from_hex, to_bytes

def extend_md5(data, extension, secret_length, secretdata_hash):
	#data = to_bytes(data)
	#extension = to_bytes(extension)
	#secretdata_hash = to_bytes(secretdata_hash)

	secretdata_length = len(data) + secret_length
	padded_data = md5pad(data, secretdata_length)

	total_length = secret_length + len(padded_data) + len(extension)
	return padded_data + extension, md5(extension, total_length, secretdata_hash)

secret = b'secret'
data = b'data'
secretdata_hash = md5(secret + data)
appended_data, appended_hash = extend_md5(data, b'append', len(secret), secretdata_hash)
print(appended_data)
print(hex(appended_hash) == hex(md5(secret + appended_data)))