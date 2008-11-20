#!/usr/bin/env python
#Copyright 2007 Sebastian Hagen
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

from cStringIO import StringIO

class PieceMask:
   """Data structure representing pieces of torrent held by a peer"""
   def __init__(self, length, bitfield=None):
      """Initialize piecemask instance of length <length> with <bitmask> or an all zero bitmask if not specified"""
      self.mask = StringIO()
      self.length = length
      if not (bitfield is None):
         assert (length + 7 >= len(bitfield)*8 >= length >= 1)
         self.mask.write(bitfield)
      else:
         self.mask.seek(length//8 + int((length % 8) != 0) - 1)
         self.mask.write('\x00')
      
   def __getinitargs__(self):
      return (self.length, self.mask.getvalue())
      
   def __getstate__(self):
      return None
   def __setstate__(self, state):
      if not (state is None):
         raise ValueError('argument state is %r, expected None.' % (state,))
   
   @classmethod
   def build_full(cls, length):
      """Return piecemask instance with specified length, and all bits set"""
      byte_count_full = length//8
      bit_count_mod = length % 8
      if (bit_count_mod):
         ext = chr(sum([2**i for i in range(8-bit_count_mod,8)]))
      else:
         ext = ''
      return cls(length, '\xff'*byte_count_full + ext)

   def piece_have_set(self, index, have):
      """Save that we have/don't have the piece with provided index"""
      assert (index < self.length)
      byte_index = index//8
      bit_index = index % 8
      self.mask.seek(byte_index)
      byte_val = ord(self.mask.read(1))
      if (have):
         byte_val |= (1 << (7-bit_index))
      else:
         byte_val &= ~(1 << (7-bit_index))
      self.mask.seek(-1,1)
      self.mask.write(chr(byte_val))
   
   def piece_have_get(self, index):
      """Return if we have the piece with provided index"""
      assert (index < self.length)
      byte_index = index//8
      bit_index = index % 8
      self.mask.seek(byte_index)
      byte_val = ord(self.mask.read(1))
      return bool((byte_val >> (7-bit_index)) & 1)

   def pieces_have_count(self):
      """Return count of pieces marked as present"""
      self.mask.seek(0)
      rv = 0
      while (True):
         s = self.mask.read(1)
         if (s == ''):
            break
         i = ord(s)
         while (i > 0):
            if (i % 2):
               rv += 1
            i //= 2
      return rv

   def bitfield_get(self):
      """Return complete mask as bitfield"""
      return self.mask.getvalue()

   def __repr__(self):
      return '%s(%s, bitfield=%r)' % (self.__class__.__name__, self.length, self.bitfield_get())
   
   def __str__(self):
      return '<%s len %s id %s>' % (self.__class__.__name__, self.length, id(self))


class BlockMask(PieceMask):
   """Data structure representing blocks of torrent held by us."""
   def __init__(self, piece_count, piece_length, piece_length_last, block_length, bitfield=None):
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
      PieceMask.__init__(self, length, bitfield)

   def __getinitargs__(self):
      return (self.piece_count, self.piece_length, self.piece_length_last, self.block_length, self.mask.getvalue())

   def piece_have_get(self, *args, **kwargs):
      """raise NotImplentedError
      
      overridden to protect the innocent"""
      raise NotImplementedError()

   def piece_have_set(self, *args, **kwargs):
      """raise NotImplentedError
      
      overridden to protect the innocent"""
      raise NotImplementedError()

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
         if not (PieceMask.piece_have_get(self, block)):
            return False
      return True

   def block_have_get(self, piece, sub_index):
      """Return whether specified block is set"""
      return PieceMask.piece_have_get(self, piece * self.blocks_per_piece + sub_index)
   
   def block_have_set(self, piece, sub_index, have):
      """Set/Unset specified block"""
      return PieceMask.piece_have_set(self, (piece * self.blocks_per_piece + sub_index), have)
