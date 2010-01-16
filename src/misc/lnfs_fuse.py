#!/usr/bin/env python3
#Copyright 2010 Sebastian Hagen
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

# LNFS is not a filesystem. But for some purposes, it might be worth weakly
# pretending that is.

import os
from os.path import abspath
import errno
import stat
import fuse
from binascii import b2a_hex, a2b_hex

from liasis._lnfs import LNFSVolume
from liasis.benc_structures import BTMetaInfo

FILE_ACCMODES = os.O_RDONLY | os.O_WRONLY | os.O_RDWR | os.O_CREAT


class LNFSFile:
   def __init__(self, dev, off, length):
      self.dev = dev
      self.off = off
      self.length = length

   def read(self, off, length):
      if (off > self.length):
         return b''
      if ((off + length) > self.length):
         length = self.length - off
      
      self.dev.seek(self.off + off)
      return self.dev.read(length)


def raise_oserr(errno, msg=''):
   raise OSError(errno,msg)

class LNFSFuse(fuse.Operations):
   base_stat = {
      'st_atime':0,
      'st_mtime':0,
      'st_ctime':0,
      'st_gid':0,
      'st_uid':0,
      'st_mode':0,
      'st_size':0,
      'st_blocks':0,
      'st_blksize':1048576
   }
   
   def __init__(self, *args, **kwargs):
      super().__init__(*args, **kwargs)
      self.fs_tree = {}
      self.ih2vol = {}
   
   def add_lnfs_vol(self, vol):
      for ih in vol.torrents:
         self.ih2vol[ih] = vol
   
   def add_mi(self, metainfo):
      ih = metainfo.info_hash
      try:
         vol = self.ih2vol[ih]
      except KeyError:
         return False
      
      (offset, length) = vol.get_block_data_indices(ih)
      if (metainfo.length_total != length):
         raise ValueError('Length mismatch: %s != %s' % (length, metainfo.length_total))
      
      f_off = offset
      ih_hex = b2a_hex(ih)
      for f in metainfo.files:
         (dn, fn) = os.path.split(os.path.join(b'/', ih_hex, metainfo.basename, f.path).decode('utf-8'))
         tdir = self._get_file(dn, True)
         tdir[fn] = LNFSFile(vol.f, f_off, f.length)
         f_off += f.length
      
      return True
   
   def finish_setup(self):
      for (ih, vol) in self.ih2vol.items():
         ih_hex = b2a_hex(ih).decode('utf-8')
         if (ih_hex in self.fs_tree):
            continue
         (offset, length) = vol.get_block_data_indices(ih)
         self.fs_tree[ih_hex] = LNFSFile(vol.f, offset, length)
   
   def _get_file(self, path, makedirs=False):
      rp_c = abspath(path).split(os.path.sep)
      
      cwd = self.fs_tree
      for pc in rp_c:
         if (len(pc) == 0):
            continue
         try:
            cwd = cwd[pc]
         except KeyError:
            if (makedirs):
               cwd[pc] = {}
               cwd = cwd[pc]
            else:
               return None
      
      return cwd
   
   def getattr(self, path, fh=None):
      f = self._get_file(path)
      if (f is None):
         raise_oserr(errno.ENOENT)
      
      rv = self.base_stat.copy()
      if (isinstance(f, dict)):
         rv['st_mode'] |= stat.S_IFDIR | 0o555
         rv['nlink'] = 2
         for val in f.values():
            if (isinstance(f, dict)):
               rv['nlink'] += 1
      else:
         rv['st_size'] = f.length
         rv['st_blocks'] = (f.length + 511) // 512
         rv['st_mode'] |= stat.S_IFREG | 0o444
         rv['st_nlink'] = 1
      
      return rv
   
   def readdir(self, path, fh):
      file = self._get_file(path)
      if (file is None):
         raise_oserr(errno.ENOENT)
      
      if not (isinstance(file, dict)):
         raise_oserr(ENOTDIR)
      
      return ['.','..'] + list(file.keys())

   def open(self, path, flags):
      if (self._get_file(path) is None):
         raise_oserr(errno.ENOENT)
      
      if ((flags & FILE_ACCMODES) != os.O_RDONLY):
         raise_oserr(errno.EACCESS)
      return 0

   def read(self, path, length, offset, fh):
      f = self._get_file(path)
      if (f is None):
         raise_oserr(errno.ENOENT)
      if not (isinstance(f, LNFSFile)):
         raise_oserr(errno.EISDIR)
      
      return f.read(offset, length)


def main():
   import sys
   import logging
   import optparse
   from fcntl import LOCK_SH, LOCK_NB
   
   logging.basicConfig(format='%(asctime)s %(levelname)s %(message)s',
      stream=sys.stderr, level=logging.DEBUG)
   
   logger = logging.getLogger()
   log = logger.log
   
   op = optparse.OptionParser()
   op.add_option('--allow-other', dest='allow_other', action='store_true', default=False, help='Allow FS access for other users than the mounting one.')
   op.add_option('--fg', dest='foreground', action='store_true', default=False, help="Don't background after initialization.")
   
   (opts, args) = op.parse_args()
   
   (volfn, mountpoint, *mifns) = args
   
   lf = LNFSFuse()
   
   log(20, 'Opening and parsing LNFS volume.')
   volf = open(volfn, 'rb')
   vol = LNFSVolume(volf, LOCK_SH | LOCK_NB)
   lf.add_lnfs_vol(vol)
   log(20, 'Done.')
   
   log(20, 'Reading and parsing MI files ...')
   for fn in mifns:
      f = open(fn, 'rb')
      mi = BTMetaInfo.build_from_benc_stream(f)
      lf.add_mi(mi)
   
   log(20, 'Done.')
   
   lf.finish_setup()
   
   log(20, 'Init finished.')
   
   fuse_kwargs = {}
   if (opts.foreground):
      fuse_kwargs['foreground'] = True
   if (opts.allow_other):
      fuse_kwargs['allow_other'] = True
   
   fuse.FUSE(lf, mountpoint, **fuse_kwargs)


if (__name__ == '__main__'):
   main()
