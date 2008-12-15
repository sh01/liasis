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


"""Collection of 'mirror' classes of certain bt_client structures

Mirror instances lack stateful objects that are only useful in the process that
created them, and include methods to serialize and deserialize them safely,
i.e. without making any assumptions about the validity of the data they're
deserialized from.

They are intended to be used for serializing these objects, and optionally
by liasis clients to deserialize the data dumped by liasis and mirror the
liasis instance's state."""

from .benc_structures import BTPeer, BTMetaInfo
from .bt_piecemasks import *

def s2b(s):
   return s.encode('ascii')


class BaseMirror:
   """Baseclass for mirrors"""
#------------------------------------------------------------------------------ builders for serializers and deserializers of common types
   @staticmethod
   def state_var_ds_instantiater_build(cls):
      def rv(cls_sub, args):
         return cls(*args)
      return rv
   
   @staticmethod
   def state_var_ds_setstate_build(cls):
      def rv(cls_sub, args):
         rv = cls.__new__(cls)
         rv.__setstate__(args)
         return rv
      return rv
   
   @staticmethod
   def state_var_ds_bfs_build(cls):
      def rv(cls_sub, v):
         return cls.build_from_state(v)
      return rv
   
   @staticmethod
   def seq_state_var_ds_bfs_build(cls):
      def rv(cls_sub, v):
         return [cls.build_from_state(e) for e in v]
      return rv
   
   @staticmethod
   def state_ds_static_build(func):
      def rv(cls, *args, **kwargs):
         return func(*args, **kwargs)
      return rv
   
#------------------------------------------------------------------------------ common serializers and deserializers
   @staticmethod
   def state_var_s_identity(v):
      return v

   @staticmethod
   def state_var_ds_identity(cls, v):
      return v

   @staticmethod
   def state_var_s_state_get(v):
      return v.state_get()
   
   @staticmethod
   def seq_state_var_s_state_get(v):
      return [e.state_get() for e in v]

   @staticmethod
   def state_var_s_getinitargs(v):
      return v.__getinitargs__()
   
   @staticmethod
   def state_var_s_getstate(v):
      return v.__getstate__()

#------------------------------------------------------------------------------ instance creation / serialization methods
   def __init__(self, **kwargs):
      for key in kwargs:
         setattr(self, key, kwargs[key])
   
   @classmethod
   def build_from_original(cls, orig):
      """Build instance from data from BTClientConnection instance"""
      init_dict = {}
      for state_var_spec in cls.state_vars:
         for attrname in state_var_spec[2]:
            init_dict[attrname] = getattr(orig, attrname)
      
      return cls(**init_dict)
      
   def state_get(self):
      """Summarize internal state using nested dicts, lists, ints and strings"""
      state = {}
      for (seri, deseri, attrnames) in self.state_vars:
         for attrname in attrnames:
            attrval = getattr(self, attrname)
            if not (attrval is None):
               state[s2b(attrname)] = seri(attrval)
      
      return state

   @classmethod
   def build_from_state(cls, state):
      """Build instance from summarized internal state"""
      state = dict((k.decode('ascii'),v) for (k,v) in state.items())
      init_dict = {}
      for (seri, deseri, attrnames) in cls.state_vars:
         for attrname in attrnames:
            if (attrname in state):
               init_dict[attrname] = deseri(cls, state[attrname])
            else:
               init_dict[attrname] = None
      
      return cls(**init_dict)
      
   @classmethod
   def state_get_from_original(cls, orig):
      """Summarize state of BTClientConnection instance using nested dicts, lists, ints and strings"""
      state = {}
      for (seri, deseri, attrnames) in cls.state_vars:
         for attrname in attrnames:
            attrval = getattr(orig, attrname)
            if not (attrval is None):
               state[s2b(attrname)] = seri(attrval)
      return state



class BTClientConnectionMirror(BaseMirror):
   """BTClientConnection mirror"""
   def __state_var_ds_bool(cls, v):
      return bool(int(v))
   def __state_var_s_bool(v):
      return int(bool(v))
   
   # state_get() output spec; controls serialization and deserialization of
   # BTClientConnection(Mirror) instances.
   state_vars = (
      #bool values, encoded as integers
      (__state_var_s_bool, __state_var_ds_bool,
      ('s_interest', 's_choked', 's_snubbed', 'p_interest',
      'p_choked', 'handshake_processed', 'handshake_sent', 'sync_done',
      'instance_init_done', 'downloading', 'uploading', 'ext_Fast',
      'mse_init', 'mse_init_done')),
      #int values
      (int, BaseMirror.state_ds_static_build(int), 
      ('buffer_input_len', 'content_bytes_in', 'content_bytes_out', 'ts_start',
      'ts_traffic_last_out', 'ts_traffic_last_in', 'ts_request_last_out', 'mse_cm',
       'peer_req_count')),
      #lists with directly valid subelements
      (list, BaseMirror.state_var_ds_identity, ('pieces_wanted', 'blocks_pending',
         'blocks_pending_out', 'pieces_suggested', 'pieces_allowed_fast')),
      # strings
      (bytes, BaseMirror.state_var_ds_identity, ('peer_id',)),
      # special cases
      (BaseMirror.state_var_s_getstate,
      BaseMirror.state_var_ds_setstate_build(BitMask), ('piecemask',)),
      (BaseMirror.state_var_s_state_get,
      BaseMirror.state_var_ds_bfs_build(BTPeer), ('btpeer',))
   )
   def __repr__(self):
      return '<{0} to {1} at {2} sent: {3} received: {4}>'.format(
            self.__class__.__name__, self.btpeer, id(self),
            self.content_bytes_out, self.content_bytes_in)


class BTorrentHandlerMirror(BaseMirror):
   """BTorrentHandler mirror"""
   def __state_var_ds_bool(cls, v):
      return bool(int(v))
   
   def __state_var_ds_metainfo(cls, v):
      return BTMetaInfo.build_from_dict(v)
   
   # state_get() output spec; controls serialization and deserialization of
   # BTorrentHandler(Mirror) instances.
   state_vars = (
      #bool values
      (int, __state_var_ds_bool,
      ('active', 'endgame_mode', 'download_complete', 'init_started',
      'init_done', 'uploading', 'peer_connection_count_target',
      'peer_connections_start_delay')),
      #int values
      (int, BaseMirror.state_ds_static_build(int),
      ('piece_count', 'pieces_have_count', 'bytes_left', 'downloader_count',
      'optimistic_unchoke_count', 'content_bytes_in', 'content_bytes_out', 
      'tier', 'tier_index')),
      # str values
      (bytes, BaseMirror.state_var_ds_identity, ('peer_id', 'trackerid')),
      # special cases
      (BaseMirror.state_var_s_getstate,
      BaseMirror.state_var_ds_setstate_build(BitMask), ('piecemask',)),
      (BaseMirror.state_var_s_getstate,
      BaseMirror.state_var_ds_setstate_build(BlockMask),
      ('blockmask', 'blockmask_req')),
      (BaseMirror.state_var_s_state_get, __state_var_ds_metainfo, 
      ('metainfo',)),
      (BaseMirror.seq_state_var_s_state_get, 
      BaseMirror.seq_state_var_ds_bfs_build(BTClientConnectionMirror), 
      ('peer_connections',)),
      (BaseMirror.seq_state_var_s_state_get,
      BaseMirror.seq_state_var_ds_bfs_build(BTPeer), ('peers_known',))
   )
   
   def target_basename_get(self):
      """Get base filename for this BTH"""
      if (self.metainfo.basename):
         return self.metainfo.basename
      if (self.metainfo.files):
         return self.metainfo.files[0].path
      return None
   
   def __repr__(self):
      return '<{0} id: {1} info_hash: {2!a} basefilename: {3!a} active: {4}' \
         'complete: {5}>'.format(self.__class__.__name__, id(self),
         self.metainfo.info_hash, self.target_basename_get(), self.active,
         self.download_complete)


class BTClientMirror(BaseMirror):
   """BTClient mirror"""
   bthm_cls = BTorrentHandlerMirror

   def dictval_state_var_s_state_get(v):
      rv = {}
      print(v)
      for key in v:
         rv[key] = v[key].state_get()
      return rv
   

   def dictval_state_var_ds_bfs_bth(cls, v):
      rv = {}
      for key in v:
         rv[key] = cls.bthm_cls.build_from_state(v[key])
      return rv
   
   state_vars = (
      (int, BaseMirror.state_ds_static_build(int), ('port',)),
      (bytes, BaseMirror.state_var_ds_identity, ('host',)),
      (BaseMirror.seq_state_var_s_state_get,
      BaseMirror.seq_state_var_ds_bfs_build(BTClientConnectionMirror),
      ('connections_uk',)),
      (dictval_state_var_s_state_get, dictval_state_var_ds_bfs_bth, ('torrents',))
   )

   def __repr__(self):
      return '<{0} listen: ({1!a},{2}) id: {3}>'.format(self.__class__.__name__, self.host, self.port, id(self))


class SIHLBTClientMirror(BTClientMirror):
   """BTClient mirror which also keeps a sorted list of info-hashes"""
   def __init__(self, *args, **kwargs):
      BTClientMirror.__init__(self, *args, **kwargs)
      self.infohash_list_update()

   def infohash_list_update(self):
      self.infohash_list = sorted(self.torrents.keys())

