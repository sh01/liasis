#!/usr/bin/env python
#Copyright 2007,2008 Sebastian Hagen
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

# 'Mirror' classes for certain bt_client structures
# These are missing stateful objects that are only useful in the process that
# created them, and include methods to serialize and deserialize them. They're
# intended to be used for serializing these objects, and optionally by liasis
# clients to deserialize the data dumped by liasis and mirror the liasis 
# instance's state.

class BinaryKeysDict(dict):
   def __init__(self, *args, **kwargs):
      if (not args):
         dict.__init__(self)
         for (k,v) in kwargs.items():
            self[k] = v
         return
      
      raise ValueError("Unexpected arguments.")
   
   def __setitem__(self, k, v):
      if (isinstance(k, str)):
         k = k.encode('ascii')
      return dict.__setitem__(self, k, v)
   def __getitem__(self, k):
      if (isinstance(k, str)):
         k = k.encode('ascii')
      return dict.__getitem__(self, k)
   def items_strkeys(self):
      return ((k.decode('ascii'),v) for (k,v) in self.items())


class BitMask(bytearray):
   """Data structure representing a general-purpose bitmask"""
   def __init__(self, arg1=None, *args, bitlen, **kwargs):
      if (arg1 is None):
         # Compute length in bytes to pass to bytearray constructor
         arg1 = bitlen//8 + int((bitlen % 8) != 0)
      bytearray.__init__(self, arg1, *args, **kwargs)
      self.bitlen = bitlen
   
   def __getstate__(self):
      return (bytes(self), self.bitlen)
   
   def __setstate__(self, state):
      (b, bitlen) = state
      self.__init__(b, bitlen=bitlen)
   
   @classmethod
   def build_full(cls, length):
      """Return piecemask instance with specified length, and all bits set"""
      byte_count_full = length//8
      bit_count_mod = length % 8
      if (bit_count_mod):
         ext = bytearray(1)
         ext[0] = sum((1 << i for i in range(8-bit_count_mod,8)))
      else:
         ext = b''
      return cls(b'\xff'*byte_count_full + ext, bitlen=length)

   def bit_set(self, index, val):
      """Set bit with provided index"""
      assert (index < self.bitlen)
      byte_index = index//8
      bit_index = index % 8
      if (val):
         self[byte_index] |= (1 << (7-bit_index))
      else:
         self[byte_index] &= ~(1 << (7-bit_index))
   
   def bit_get(self, index):
      """Return bit with provided index"""
      assert (index < self.bitlen)
      byte_index = index//8
      bit_index = index % 8
      return bool((self[byte_index] >> (7-bit_index)) & 1)

   def bits_set_count(self):
      """Return count of bits marked"""
      rv = 0
      for i in self:
         while (i > 0):
            if (i % 2):
               rv += 1
            i //= 2
      return rv


class BlockMask(BitMask):
   """Data structure representing blocks of torrent held by us."""
   def __init__(self, piece_count, piece_length, piece_length_last, block_length, **kwargs):
      self.piece_count = piece_count
      self.piece_length = piece_length
      self.piece_length_last = piece_length_last
      self.block_length = block_length
      # the following is a variant of ceil((1.0*piece_length)/block_length)
      # without the risk of floating-point inaccuracy
      self.blocks_per_piece = piece_length//block_length + int((piece_length % block_length) != 0)
      self.blocks_per_piece_last = piece_length_last//block_length + int((piece_length_last % block_length) != 0)
      assert (0 < self.blocks_per_piece_last <= self.blocks_per_piece)
      length = self.blocks_per_piece * (piece_count - 1) + self.blocks_per_piece_last
      BitMask.__init__(self, bitlen=length, **kwargs)

   def piece_have_completely_get(self, piece):
      """Return whether we completely have the specified piece"""
      block_first = piece * self.blocks_per_piece
      if (piece == self.piece_count - 1):
         block_last = block_first + self.blocks_per_piece_last - 1
      else:
         block_last = block_first + self.blocks_per_piece - 1
      
      # Inefficient for pieces with many blocks. Significant further
      # optimization possible.
      for block in range(block_first, block_last+1):
         if not (self.bit_get(block)):
            return False
      return True

   def __setstate__(self, state):
      (args, kwargs) = state
      self.__init__(*args, **dict((k.decode('ascii'),v) for (k,v) in kwargs.items()))

   def __getstate__(self):
      return ((self.piece_count, self.piece_length,
         self.piece_length_last, self.block_length),
         BinaryKeysDict(arg1=bytes(self)))

   def block_have_get(self, piece, sub_index):
      """Return whether specified block is set"""
      return BitMask.bit_get(self, piece * self.blocks_per_piece + sub_index)
   
   def block_have_set(self, piece, sub_index, have):
      """Set/Unset specified block"""
      return BitMask.bit_set(self, (piece * self.blocks_per_piece + sub_index), have)
