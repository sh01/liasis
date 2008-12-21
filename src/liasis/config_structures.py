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

"""Structures for persistent but non-pickled liasis state"""

import os
import time
from hashlib import md5
from socket import AF_UNIX

from .bt_archiving import BTHPickleDirectoryArchiver

def peer_id_generate():
   return (b'-LS0000-' + md5('{0}{1}'.format(os.getpid(), time.time()).encode('ascii')).digest())[:20]


class ConfigBase:
   _bytes_attributes = ()
   def config_use(self, target):
      for attr in self._bytes_attributes:
         val = getattr(self, attr)
         if (isinstance(val, (bytes, bytearray))):
            continue
         setattr(self, attr, val.encode())
      
      for key in self.attributes:
         setattr(target, key, getattr(self, key))


class DaemonConfig(ConfigBase):
   """Global Liasis config value storage class"""
   pickle_filename = b'liasis_state.pickle'


class BTMConfig(ConfigBase):
   """BTManager config value storage class"""
   control_socket_af = AF_UNIX
   control_socket_address = b'liasis_ctl.sock'
   peer_id_generator = staticmethod(peer_id_generate)


class BTCConfig(ConfigBase):
   """BTC config value storage class"""
   attributes = ('host', 'port', 'pickle_interval', 'backlog', 
      'bwm_cycle_length', 'bwm_history_length')
   
   _bytes_attributes = ('bth_archive_basepath', 'host', 'data_basepath')
   
   # default config values
   bth_archive_basepath = b'torrent_archive'
   bth_archiver_cls = BTHPickleDirectoryArchiver
   data_basepath = b'data'
   port = 10000
   host = ''
   pickle_interval = 100
   backlog = 10
   bwm_cycle_length = 1
   bwm_history_length = 1000

   def config_use(self, target):
      ConfigBase.config_use(self, target)
      target.bth_archiver = self.bth_archiver_cls(self.bth_archive_basepath)

