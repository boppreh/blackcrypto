from rawhashes import md5, sha1, pad
from simplecrypto.hashes import md5 as simplemd5
from simplecrypto.formats import hex, from_hex, to_bytes

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