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
      
      for k in range(len(plaintext)):
         i = (i + 1) % 256
         j = (j + S[i]) % 256
         (S[i], S[j]) = (S[j], S[i])
         rv[k] = int(plaintext[k]) ^ S[(S[i] + S[j]) % 256]
      
      self._i = i
      self._j = j
      
      return rv
    
   encrypt = decrypt = _crypt
   
