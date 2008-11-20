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

"""Implementation of a DHT (Distributed Hash Table) node, as specified on
<http://www.bittorrent.org/Draft_DHT_protocol.html>
THIS IS NOWHERE NEAR A POINT WHERE IT COULD POSSIBLY BEGIN TO WORK.
"""

import time

from benc_structures import py_from_benc_str, benc_str_from_py


class DHTError(StandardError):
   pass


class DHTNode:
   """Data about a single DHT Node"""
   def __init__(self, id_, ip_address, port):
      self.id = id_
      self.ip_address = ip_address
      self.port = port
      self._answering = None
      self._ts_activity = None
   
   def ts_activity_bump(self, ts=None):
      """Set last activity timestamp to current system time or specified ts"""
      if (ts is None):
         ts = time.time()
      self._ts_activity = ts
   
   def is_good(self, threshold=900):
      """Return known-goodness of this node"""
      return (self._answering and ((time.time() - self._ts_activity) >= threshold))
   
   def __repr__(self):
      return '%s%r' % (self.__class__.__name__, (self.id, self.ip_address, self.port))


class DHTNodeTable:
   """Storage for information about (at most 160*8) DHT nodes"""
   ID_LEN = 160 # in bits
   def __init__(self, id_, bucket_size_max=8):
      nodes = []
      for i in xrange(self.ID_LEN + 1):
         nodes.append([])
      self._nodes = tuple(nodes)
      self.id = id_
      self.bucket_size_max = bucket_size_max
   
   def bucket_get_id(self, id_):
      """Return bucket a node with specified id would be put into"""
      bucket_idx = math.ceil(math.log((id_ ^ self.id), 2))
      return self._nodes[bucket_idx]
   
   def node_get(self, id_):
      """Return stored node, assuming we have it."""
      for node in self.bucket_get_id(node.id):
         if (node.id == id_):
            return node
      raise KeyError(repr(id_))
   
   def node_add(self, node):
      """Add node to table"""
      bucket = self.bucket_get_id(node.id)
      if (len(bucket) >= self.bucket_size_max):
         raise DHTError('Bucket size limit %d in bucket for node %r exceeded.' % (self.bucket_size_max, node))
      
      bucket.append(node)


class DHTNodeManager:
   """Class for DHT socket management and request sending"""
   def __init__(self, id_, event_dispatcher, bind_target):
      self.id = id_
      self.node_table = DHTNodeTable(id_)
      self._ed = event_dispatcher
      self._sock = self._ed.SockDatagram(input_handler=self.sock_input_handle)
      self._sock.connection_init(bind_target=bind_target)
   
   def _sock_input_handle(self, source, data):
      """Process input from our UDP socket"""
      #FIXME!


