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

import logging
import os
from collections import deque, Callable

from hashlib import sha1

from .bt_exceptions import BTClientError, BTCStateError, BTFileError

_logger = logging.getLogger('BTDiskIO')
_log = _logger.log


class BTDiskIORequest:
   def __init__(self, results_pending, callback):
      self.res_count = results_pending
      self.callback = callback
      self.failed = False
   
   def _process_result(self, req):
      """Process IO read/write response"""
      self.res_count -= 1
      assert(self.res_count >= 0)
      if (self.res_count == 0):
         self.callback(self)


class BTDiskIOSync:
   """File like object for accessing the set of files targeted by one torrent"""
   
   def __init__(self, ed, metainfo, basedir, basename_use=True):
      """Initialize instance with metainfo data.
      
      All files in metainfo.files should be closed, and will be opened as part
      of initialization.
      """
      # Ensure that the user hasn't asked several instances to work
      # with the same files in parallel.
      self._ed = ed
      self.metainfo = metainfo
      self.files = metainfo.files
      self.length = sum([file.length for file in metainfo.files])
      
      if (basename_use):
         basedir_in = basedir
         basedir = os.path.normpath(os.path.join(basedir, metainfo.basename))
         if not (os.path.abspath(basedir).startswith(os.path.abspath(basedir_in))):
            raise BTClientError("Basename {0!a} retrieved from {1} by {2} isn't safe to use.".format(metainfo.basename, metainfo, self))
      self.basedir = basedir
      
      if not (os.path.exists(basedir)):
         _log(12, "Targetdirectory {0!a} doesn't exist; creating it.".format(basedir))
         os.mkdir(basedir)
      
      files_processed = []
      try:
         for btfile in self.files:
            if (btfile.get_openness()):
               raise BTCStateError('BTFile {0} is already open.'.format(btfile))
            btfile.file_open(basedir)
            files_processed.append(btfile)
      except Exception:
         # If something went wrong, don't leave processed files newly opened
         for btfile in files_processed:
            btfile.file_close()
         raise
      
      self.file_index = 0
      self.file_index_max = (len(self.files) - 1)
   
   def _fileset_get(self, offset:int, length:int):
      """Return sequence of (file, offset, length) accesses needed to implement
         subrange access on BTDiskIO"""
      f_i = 0
      rv = deque()
      while (f_i < len(self.files)):
         btfile = self.files[f_i]
         flen = btfile.length
         if (offset > 0):
            if (offset >= flen):
               offset -= flen
               f_i += 1
               continue
            flen -= offset
         
         len_rw = min(length, flen)
         rv.append((btfile.file, offset, len_rw))
         offset = 0
         length -= len_rw
         if (length == 0):
            break
         f_i += 1
      else:
         raise BTFileError('Access violates file domain.')
      return rv

   def async_write(self, req_s:(int,memoryview), callback:Callable) -> BTDiskIORequest:
      """Write data at offset."""
      req = BTDiskIORequest(1, callback)
      for (offset, buf) in req_s:
         i = 0
         buf = memoryview(buf)
         for (f, f_off, length) in self._fileset_get(offset, len(buf)):
            f.seek(f_off)
            try:
               l = f.write(memoryview(buf[i:i+length]))
            except IOError:
               _log(38, 'async_write() failed:', exc_info=True)
               req.failed = True
               break
            if (l != length):
               _log(40, "Can't happen error: failed to write to {0}(wrote {1} of {2} bytes)".format(f, l, length))
               req.failed = True
               break
            i += length
         else:
            assert(i == len(buf))
      
      self._ed.set_timer(0,req._process_result,args=(None,))
      return req
   
   def async_readinto(self, req_s:(int,memoryview), callback:Callable) -> BTDiskIORequest:
      """Read data from offset."""
      req = BTDiskIORequest(1, callback)
      for (offset, buf) in req_s:
         i = 0
         buf = memoryview(buf)
         for (f, f_off, length) in self._fileset_get(offset, len(buf)):
            f.seek(f_off)
            try:
               l = f.readinto(buf[i:i+length])
            except IOError:
               _log(38, 'async_readinto() failed:', exc_info=True)
               req.failed = True
               break
            if (l != length):
               _log(40, "Failed to read from {0}(read {1} of {2} bytes)".format(f, l, length))
               req.failed = True
               break
            i += length
         else:
            assert(i == len(buf))
      
      self._ed.set_timer(0, req._process_result, args=(None,))
      return req
   
   def close(self):
      """Close backing files"""
      for file in self.files:
         file.file_close()


def _selftest():
   import struct
   from gonium.fdm import ED_get
   from collections import namedtuple
   from .benc_structures import BTTargetFile
   CHUNKLEN = 4
   
   flen_s = [1, 11, 1025, 23456]
   flen_s[-1] += (CHUNKLEN - (sum(flen_s) % CHUNKLEN))
   
   chunkcount = sum(flen_s)//CHUNKLEN
   
   fn_data = []
   for i in range(len(flen_s)):
      fn_data.append((flen_s[i], '__liasis_dio.test.{0}.tmp'.format(i).encode('ascii')))
   
   DMI = namedtuple('DummyMetaInfo', ('files','basename'))
   
   dmi = DMI([BTTargetFile(fn,fs) for (fs,fn) in fn_data], b'.')
   
   ed = ED_get()()
   
   btdio = BTDiskIOSync(ed, dmi, b'.')
   
   def sd(*args, **kwargs):
      ed.shutdown()
   
   print('== Test: Writing data ==')
   chunks_write = [(i*CHUNKLEN, struct.pack('>L', i) + b'\x00'*(CHUNKLEN-4)) for i in range(chunkcount)]
   btdio.async_write(chunks_write, sd)
   ed.event_loop()
   
   for f in (btf.file for btf in dmi.files):
      f.seek(0)
   buf = b''
   i = 0
   
   for f in (btf.file for btf in dmi.files):
      while (True):
         buf += f.read(CHUNKLEN-len(buf))
         if (len(buf) < CHUNKLEN):
            break
         (val,) = struct.unpack('>L',buf[:4])
         if (val != i):
            raise ValueError('Chunk {0} has data {1}.'.format(i, buf))
         i += 1
         buf = b''
   
   print('== Verifying written data ==')
   print('...passed.')
   
   chunks_read = [(i*CHUNKLEN, bytearray(CHUNKLEN)) for i in range(chunkcount)]
   print('== Test: Reading data ==')
   btdio.async_readinto(chunks_read, sd)
   ed.event_loop()
   for i in range(chunkcount):
       (val,) = struct.unpack('>L', chunks_read[i][1][:4])
       if (val != i):
          raise ValueError('BTDiskIO delivered data {0} for chunk {1}.'.format(chunks_read[i][1], i))
   
   print('...passed')
   print('== cleaning up ==')
   for fnd in fn_data:
      os.remove(fnd[1])
   
   
if (__name__ == '__main__'):
   _selftest()
