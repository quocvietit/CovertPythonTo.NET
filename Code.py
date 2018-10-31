import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from lglaf import int_as_byte
plain = b''

def key_transform(old_key):
    new_key = b''
    old_key = bytearray(old_key)
    for x in range(32, 0, -1):
        c = old_key[x-1]
        new_key += int_as_byte(c - (x % 0x0C))
    return new_key


def xor_key(key, kilo_challenge):
    # Reserve key
    key_xor = b''
    pos = 0
    challenge = struct.unpack('>I', kilo_challenge)[0]
    for i in range(8):
        k = struct.unpack('<I', key[pos:pos + 4])[0]
        key_xor += struct.pack('<I', k ^ challenge)
        pos += 4
    return key_xor


def encrypt_kilo_challenge(encryption_key, kilo_challenge):
    plaintext = b''
    for k in range(0, 16):
        # Assemble 0x00 0x01 0x02 ... 0x1F byte-array
        plaintext += int_as_byte(k)
    encryption_key = key_transform(encryption_key)
    xored_key = xor_key(encryption_key, kilo_challenge)
    obj = Cipher(algorithms.AES(xored_key), modes.ECB(),
                 backend=default_backend()).encryptor()
    return obj.update(plaintext) + obj.finalize()


def crc16(data):
	"""CRC-16-CCITT computation with LSB-first and inversion."""
	crc = 0xffff
	for byte in data:
		crc ^= byte
		for bits in range(8):
			if crc & 1:
				crc = (crc >> 1) ^ 0x8408
			else:
				crc >>= 1
	return crc ^ 0xffff

def invert_dword(dword_bin):
	print dword_bin
	dword = struct.unpack("I", dword_bin)[0]
 	return struct.pack("I", dword ^ 0xffffffff)

print  [ord(i) for i in invert_dword('KILO'.encode('ascii'))]

def make_request(cmd, args=[], body=b''):
	if not isinstance(cmd, bytes):
		cmd = cmd.encode('ascii')
	assert isinstance(body, bytes), "body must be bytes"

	# Header: command, args, ... body size, header crc16, inverted command
	header = bytearray(0x20)

	def set_header(offset, val):
		if isinstance(val, int):
			val = struct.pack('<I', val)
		assert len(val) == 4, "Header field requires a DWORD, got %s %r" % \
		                      (type(val).__name__, val)
		header[offset:offset + 4] = val

	set_header(0, cmd)
	assert len(args) <= 4, "Header cannot have more than 4 arguments"
	for i, arg in enumerate(args):
		set_header(4 * (i + 1), arg)

	# 0x14: body length
	set_header(0x14, len(body))
	# 0x1c: Inverted command
	set_header(0x1c, invert_dword(cmd))
	# Header finished (with CRC placeholder), append body...
	header += body
	# finish with CRC for header and body
	set_header(0x18, crc16(header))
	return bytes(header)


key = b'qndiakxxuiemdklseqid~a~niq,zjuxl'
kilo_challenge = 'ace5b106'.decode('hex')
mode = 2

kilo_response = encrypt_kilo_challenge(key, kilo_challenge)
print len(kilo_response)


mode_bytes = struct.pack('<I', mode)
print mode_bytes
kilo_metr_request = make_request(b'KILO', args=[b'METR', b'\0\0\0\0', mode_bytes, b'\0\0\0\0'],
	                                 body=bytes(kilo_response))

print type(kilo_metr_request)
print kilo_metr_request.encode('hex')