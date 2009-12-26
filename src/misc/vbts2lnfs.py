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

# Vanilla BT storage to LNFS converter program.

import logging

from gonium.service_aggregation import ServiceAggregate

from liasis.benc_structures import BTMetaInfo
from liasis._lnfs import LNFSVolume
from liasis.diskio import btdiskio_build as btdiskio_v_build

_logger = logging.getLogger()
_log = _logger.log


def btdata_copy_nb(dst, src, length, callback, blocksize=1048576):
   """Nonblockingly copy data from one btdiskio to another"""
   blockcount = length//blocksize + bool(length % blocksize)
   wc = 0
   offset = 0
   
   def read_next():
      nonlocal offset
      bs = min(blocksize, length-offset)
      buf = bytearray(bs)
      req_new = src.async_readinto(((offset,buf),), callback=read_process)
      req_new.buf = buf
      req_new.offset = offset
      offset += bs

   def write_process(req):
      nonlocal wc
      wc += 1
      if (wc == blockcount):
         callback()
      else:
         read_next()

   def read_process(req):
      dst.async_write(((req.offset, req.buf),), callback=write_process)
   
   read_next()


def btdata_copy_b(sa, *args, **kwargs):
   btdata_copy_nb(*args, callback=sa.ed.shutdown, **kwargs)
   sa.ed.event_loop()


def _main():
   import optparse
   import sys
   from gonium import _debugging; _debugging.streamlogger_setup()
   
   op = optparse.OptionParser(usage='%prog [options] <lnfs_volume> <torrent meta file>...')
   op.add_option('-b', '--basepath', dest='basepath', default='.', metavar='PATH', help='Basepath to use for reading BT data')
   op.add_option('-r', '--reverse', default=False, action='store_true', help='Copy from LNFS to FS instead of the opposite direction')
   
   (options, args) = op.parse_args()
   basepath = options.basepath.encode()
   
   fn_vol = args[0]
   fns_bt = args[1:]
   
   sa = ServiceAggregate()
   sa.aio = None
   
   _log(20, 'Opening LNFS volume {0!a}.'.format(fn_vol))
   vol = LNFSVolume(open(fn_vol,'r+b'))
   
   for fn_bt in fns_bt:
      _log(20, 'Reading metainfo from {0!a} and opening data files.'.format(fn_bt))
      mi = BTMetaInfo.build_from_benc_stream(open(fn_bt,'rb'))
      btdiskio_v = btdiskio_v_build(sa, mi, basepath, mkdirs=options.reverse, mkfiles=options.reverse)
      btdiskio_lnfs = vol.btdiskio_build(sa, mi, basepath)
      
      _log(20, 'Copying data.')
      if (options.reverse):
         btdata_copy_b(sa, btdiskio_v, btdiskio_lnfs, mi.length_total)
      else:
         btdata_copy_b(sa, btdiskio_lnfs, btdiskio_v, mi.length_total)
      _log(20, 'Data copy finished.')
   
   _log(20, 'All done.')


if (__name__ == '__main__'):
   _main()
