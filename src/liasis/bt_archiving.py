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

"""Classes for archiving summaries of finished torrents."""

import os.path
import pickle
import binascii
import time

class BTHNullArchiver:
   """Archiving class which throws all data away immmediately"""
   def __init__(self):
      pass
   
   def bth_archive(self, bth):
      """Does nothing, successfully"""
      pass


class ArchivedBTH:
   """Class storing central attributes of a terminated BTH"""
   bth_attributes = ('metainfo', 'port', 'peer_id',
      'content_bytes_in', 'content_bytes_out', 'ts_downloading_start',
      'ts_downloading_finish', 'active', 'bytes_left', 'download_complete')
   
   def __init__(self, kwargs):
      for attr in self.bth_attributes:
         setattr(self, attr, kwargs[attr])
   
   @classmethod
   def build_from_bth(cls, bth):
      """Build and return instance initialized from bth instance"""
      items = {}
      for name in cls.bth_attributes:
         items[name] = getattr(bth, name)
      
      return cls(items)


class BTHPickleDirectoryArchiver:
   """Archiving class which archives data for each bth into a pickle file"""
   ts_factor = 1000000
   def __init__(self, basepath):
      self.basepath = basepath
   
   @classmethod
   def _ts_bytes_get(cls):
      """Return bytes representing current time"""
      return ('{0}'.format(int(time.time()*cls.ts_factor))).encode('ascii')
   
   def targetfile_open(self, bth):
      """Determine targetpath for archival file and open it"""
      mi_string = binascii.b2a_hex(bth.metainfo.info_hash)
      pf1 = os.path.join(self.basepath, mi_string)
      if (not os.path.exists(pf1)):
         os.mkdir(pf1)
      
      path = os.path.join(pf1, self._ts_bytes_get())
      while (os.path.exists(path)):
         path = os.path.join(pf1, self._ts_bytes_get())
      # There is a race-condition here; fs semantics prevent us from completely
      # avoiding it. To be on the safe side, one shouldn't allow several
      # archivers to write to the same directory in parallel.
      f = open(path, 'wb')
      return f
   
   def bth_archive(self, bth):
      """Extract important data from bth and archive it"""
      targetfile = self.targetfile_open(bth)
      abth = ArchivedBTH.build_from_bth(bth)
      pickle.dump(abth, targetfile, protocol=-1)
      targetfile.close()



