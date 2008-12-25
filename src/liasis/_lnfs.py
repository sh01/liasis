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

"""
LNFS ("LNFS is Not a File System") implementation.
LNFS is a simple file-format, for storing data for several torrents in a
single file / block device.
New torrents can be added at the end as long as there is space; no provisions
for efficiently deleting torrents from the set are made.
Also, the resulting data won't be readable by anything except programs
specifically supporting LNFS, which at the time of writing include liasis -
and nothing else.

As such, its usefulness is limited to some very specific scenarios; if you
don't already have something in mind you could use this for, it probably
isn't going to be useful to you at all.

To protect the innocent, no usage examples are provided for this module. If
you really need it, you should be able to figure it out.
"""

import struct
import fcntl

from .diskio import BTDiskSyncIO, BTDiskAIO

class LNFSError(Exception):
   pass

class LNFSVolume:
   DEV_HEADER = b'LNFS\x0a\x00\x0d\x00\x00\x00\x01'
   BLOCK_HEADER_FMT = b'>BQ20s'
   BLOCK_HEADER_LEN = struct.calcsize(BLOCK_HEADER_FMT)
   def __init__(self, fl):
      self.f = fl
      fcntl.lockf(fl, fcntl.LOCK_EX | fcntl.LOCK_NB)
      fl.seek(0,2)
      self.f_len = fl.tell()
      fl.seek(0)
      if (self.f_len < len(self.DEV_HEADER)):
         raise LNFSError("Filelike {0} isn't long enough to be a LNFS volume.".format(fl))
      hd = fl.read(len(self.DEV_HEADER))
      if (hd != self.DEV_HEADER):
         raise LNFSError("Filelike {0} started with {1}, which isn't a valid LNFS header.".format(fl, hd))
      
      self.torrents = {}
      offset = len(self.DEV_HEADER)
      len_left = self.f_len - offset

      while (len_left >= self.BLOCK_HEADER_LEN):
         fl.seek(offset)
         bhd = fl.read(self.BLOCK_HEADER_LEN)
         (used, blocklen, infohash) = struct.unpack(self.BLOCK_HEADER_FMT, bhd)
         if (not used):
            break
         
         len_left -= self.BLOCK_HEADER_LEN
         if (blocklen > len_left):
            raise LNFSError('Format error: block at offset {0} claims size {1}, which would exceed volume size {2}.'.format(offset, blocklen, self.f_len))
         self.torrents[infohash] = (offset, blocklen)
         offset += blocklen + self.BLOCK_HEADER_LEN
         len_left -= blocklen
      
      self.free_offset = offset
   
   def btdiskio_build(self, sa, metainfo, *args, **kwargs):
      if (metainfo.info_hash in self.torrents):
         (offset, blocklen) = self.torrents[metainfo.info_hash]
         di_args = (sa, self, offset, blocklen)
      else:
         tlen = metainfo.length_total
         if (tlen > (self.f_len - self.free_offset)):
            raise LNFSError('{0} has insufficient memory to store {1} more bytes'.format(self, tlen))
         aio = sa.aio
         bhd = struct.pack(self.BLOCK_HEADER_FMT, 1, tlen, metainfo.info_hash)
         if not (aio is None):
            aio.io((aio.REQ_CLS(aio.MODE_WRITE, bhd, self.f, self.free_offset, callback=lambda *args: None),))
         else:
            self.f.seek(self.free_offset)
            self.f.write(bhd)
         
         di_args = (sa, self, self.free_offset, tlen)
         self.torrents[metainfo.info_hash] = (self.free_offset, tlen)
         self.free_offset += tlen + self.BLOCK_HEADER_LEN
      
      if (sa.aio is None):
         return LNFSDiskSyncIO(*di_args)
      else:
         return LNFSDiskAIO(*di_args)
   
   def __repr__(self):
      return '<LNFSVolume at {0} fl {1} torrents {2} size {3} used {4}>'.format(
         id(self), self.f, len(self.torrents), self.f_len, self.free_offset)
   
   def close(self):
      self.f.close()
      self.f = None


class LNFSDiskIOBase:
   def __init__(self, sa, volume, offset, length):
      self._sa = sa
      self._volume = volume
      self._offset = offset
      self._length = length

   def _fileset_get(self, offset:int, length:int):
      if (offset < 0):
         raise ValueError('offset {0} is bogus.'.format(offset))
      if (length < 0):
         raise ValueError('length {0} is bogus'.format(length))
      if ((offset + length) > self._length):
         raise ValueError('_fileset_get({0}, {1}) called on {0} with length {1}'.format(offset, length, self, self._length))
      return (self._volume.f, self._offset+offset, length)

   def close(self):
      pass


class LNFSDiskSyncIO(LNFSDiskIOBase, BTDiskSyncIO):
   pass

class LNFSDiskAIO(LNFSDiskIOBase, BTDiskAIO):
   pass


def _selftest(volume_fn, btfn_s):
   from .benc_structures import BTMetaInfo
   from gonium.service_aggregation import ServiceAggregate
   
   sa = ServiceAggregate()
   sa.aio = None
   
   print('Opening LNFS volume ...')
   vol = LNFSVolume(open(volume_fn, 'r+b'))
   for btfn in btfn_s:
      print('Submitting data from {0!a} ...'.format(btfn))
      mi = BTMetaInfo.build_from_benc_stream(open(btfn,'rb'))
      vol.btdiskio_build(sa, mi)
   print('No problems detected.')


if (__name__ == '__main__'):
   import sys
   vfn = sys.argv[1]
   btfn_s = sys.argv[2:]
   
   _selftest(vfn, btfn_s)
