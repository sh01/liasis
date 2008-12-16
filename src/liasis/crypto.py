#!/usr/bin/env python
#Copyright 2008 Sebastian Hagen
# This file is part of liasis.
#
# liasis is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 2 of the License, or
# (at your option) any later version.
#
# liasis is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# ARC4 implementation, derives from description on
# <http://en.wikipedia.org/wiki/ARC4>

class ARC4:
   def __init__(self, key:bytes):
      """Initialize new ARC4 instance"""
      self._S = S = bytearray(range(256))
      j = 0
      for i in range(256):
         j = (j + S[i] + key[i % len(key)]) % 256
         (S[i], S[j]) = (S[j], S[i])
      self._i = 0
      self._j = 0
   
   @classmethod
   def new(cls, *args, **kwargs):
      """Alternate constructor for API compatibility with Crypto.Cipher.ARC4"""
      return cls(*args, **kwargs)
     
   def _crypt(self, plaintext:bytes) -> bytearray:
      """{En,De}crypt binary data."""
      i = self._i
      j = self._j
      S = self._S
      
      rv = bytearray(len(plaintext))
      
      if (isinstance(plaintext, memoryview)):
         plaintext = bytes(plaintext)
      
      for k in range(len(plaintext)):
         i = (i + 1) % 256
         j = (j + S[i]) % 256
         (S[i], S[j]) = (S[j], S[i])
         rv[k] = int(plaintext[k]) ^ S[(S[i] + S[j]) % 256]
      
      self._i = i
      self._j = j
      
      return rv
    
   encrypt = decrypt = _crypt


def _selftest():
   from binascii import b2a_hex
   for (key,pt,ct) in (
      (b"secret",b"What's the airspeed of an unladen swallow?",
       b'\xba^\xb3h\xa5\xd7\xf6\xd2Z\xae\x9b\xbd\x9a\x94\x86G\xc8R\x16\xc2\xec\x95\xe4=\x1e\\\x01\x89\xb6\x0b1z\xd1\xd9l\xf4\xa7/B\xb4=\xee'),
      (b"topsecret",bytearray(b"I'm being oppressed!"),
       b'\x9cO\xc2\xb5\xfd\x065\xa3p\x86\xb4\xc6.L\xf7\xa83\\\x99\xda'),
      (b"pass", memoryview(b"Nobody expects the Spanish inquisition!"),
       b'\x0e\xaf\xd6\xabX\xde\x90\x97\xcf4\xfa\xcc\xf9\xa9\x91\xe8\xc4\xcaN\x1c\xf4\x12\x1b.<\xa5\xf8\x07=\xbc\xdfo\xa8\xe5\xe7cbo\x8e')):
      a4ct = bytes(ARC4(key).encrypt(pt))
      if (ct != a4ct):
         raise Exception("Key {0} yielded ciphertext {1}, expected {2}".format(key.decode('ascii'), a4ct, ct))
      print ('correct ciphertext: {0}'.format(b2a_hex(a4ct)))


if (__name__ == '__main__'):
   _selftest()
