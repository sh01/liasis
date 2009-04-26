#!/usr/bin/env python
#Copyright 2007,2008,2009 Sebastian Hagen
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

import os
import logging

from gonium.fdm import AsyncDataStream, AsyncSockServer
from gonium.event_multiplexing import DSEventAggregator

from .bt_client import EABTClient
from . import benc_structures
from .benc_structures import BTMetaInfo
from .bt_piecemasks import BitMask
from .cc_base import BTControlConnectionBase, BTControlConnectionError


class BTManagerError(Exception):
   pass


class BTControlConnection(BTControlConnectionBase, AsyncDataStream):
   """Liasis BT Control Connection; server side"""
   logger = logging.getLogger('BTControlConnection')
   log = logger.log
   
   RC_NONE = 0
   RC_BTCC = 1 # 2**0
   
   def __init__(self, btm, *args, **kwargs):
      AsyncDataStream.__init__(self, *args, **kwargs)
      BTControlConnectionBase.__init__(self)
      self.btm = btm
      # sequence ids
      self.snum_btc = 0
      self.snum_bthsets = 0
      self.bth_throughput_listeners = {}
      self.cleanup_running = False

#------------------------------------------------------------------------------- btm input interface
   def btc_change_note(self):
      """Assert that our btm's BT Client list has changed"""
      self.snum_out += 1
      self.snum_btc = self.snum_out
      self.msg_send(b'INVALIDCLIENTCOUNT', [])
   
   def bth_change_process(self, btc_index):
      """Assert that the set of bths managed by the specifed btc has changed"""
      btc_index = int(btc_index)
      self.snum_out += 1
      self.snum_bthsets = self.snum_out
      self.msg_send(b'INVALIDCLIENTTORRENTS', [str(btc_index).encode('ascii')])
      
#------------------------------------------------------------------------------ network input handler helper functions
   def rcr_presence_check(self, rc_risk, seq_num):
      """Check for presence of acute race condition threat"""
      if ((rc_risk & self.RC_BTCC) and (self.snum_cmp(seq_num, self.snum_btc) == 1)):
         # BTCC race condition avoidance
         return True
      return False
   
   @staticmethod
   def client_nnint_get(args, arg_idx):
      """Retrieve non-negative integer from arg list"""
      rv = int(args[arg_idx])
      if (rv < 0):
         raise ValueError("Arg with index {0} (val {1}) is invalid; should be >= 0.".format(arg_idx, rv))
      return rv
   
   @staticmethod
   def seq_None_filter(seq, replacement=-1):
      """Replace 'None' elements in sequence with replacement"""
      rv = []
      for el in seq:
         if (el is None):
            rv.append(-1)
         else:
            rv.append(el)
      return rv

#------------------------------------------------------------------------------ output helpers
   def command_fail(self, cmd, args, exc):
      """Send COMMANDFAIL message to client"""
      eargs = [str(exc)]
      if (isinstance(exc, EnvironmentError)):
         eargs.append(2)
         eargs.append(exc.errno)
      
      self.msg_send(b'COMMANDFAIL', [[[cmd] + args], eargs])

#------------------------------------------------------------------------------ network input handlers
   def input_process_BUILDBTHFROMMETAINFO(self, cmd, args):
      """Process BUILDBTHFROMMETAINFO message"""
      client_idx = self.client_nnint_get(args,0)
      btc = self.btm.bt_clients[client_idx]
      
      mi_string = args[1]
      active = bool(int(args[2]))
      try:
         mi = BTMetaInfo.build_from_benc_string(mi_string)
      except ValueError:
         raise ValueError('Benc string {0!a} is invalid'.format(mi_string))
      
      if (mi.info_hash in btc.torrents):
         self.msg_send(b'COMMANDNOOP', [cmd] + args)
         return
      try:
         # Requires disk I/O, may fail through no fault of ours
         btc.torrent_add(mi, peer_id=self.btm.peer_id_generator(),
               piecemask_validate=True,
               piecemask=BitMask.build_full(len(mi.piece_hashes)),
               active=active)
      except BaseException as exc:
         self.command_fail(cmd, args, exc)
         return
      
      self.msg_send(b'COMMANDOK', [cmd] + args)
   
   def input_process_DROPBTH(self, cmd, args):
      """Process DROPBTH message"""
      client_idx = self.client_nnint_get(args, 0)
      btc = self.btm.bt_clients[client_idx]
      mi_string = args[1]
      try:
         btc.torrent_drop(mi_string)
      except BaseException as exc:
         self.command_fail(cmd, args, exc)
         return
      
      self.msg_send(b'COMMANDOK', [cmd] + args)
      
   def input_process_GETCLIENTCOUNT(self, cmd, args):
      """Process GETCLIENTCOUNT message"""
      self.msg_send(b'CLIENTCOUNT', [len(self.btm.bt_clients)])
   
   def input_process_GETCLIENTDATA(self, cmd, args):
      """Process GETCLIENTDATA message"""
      client_idx = self.client_nnint_get(args,0)
      self.msg_send(b'CLIENTDATA', [client_idx, self.btm.bt_clients[client_idx].state_get()])
   
   def input_process_GETCLIENTTORRENTS(self, cmd, args):
      """Process GETCLIENTTORRENTS message"""
      client_idx = self.client_nnint_get(args,0)
      self.msg_send(b'CLIENTTORRENTS', [client_idx, list(self.btm.bt_clients[client_idx].torrents.keys())])
   
   def input_process_GETBTHDATA(self, cmd, args):
      """Process GETBTHDATA message"""
      client_idx = self.client_nnint_get(args,0)
      torrent_infohash = args[1]
      self.msg_send(b'BTHDATA', [client_idx, self.btm.bt_clients[client_idx].torrents[torrent_infohash]])
   
   def input_process_GETBTHTHROUGHPUT(self, cmd, args):
      """Process GETBTHTHROUGHPUT message"""
      client_idx = self.client_nnint_get(args,0)
      torrent_infohash = args[1]
      max_len = self.client_nnint_get(args,2)
      
      bth = self.btm.bt_clients[client_idx].torrents[torrent_infohash]
      
      self.msg_send(b'BTHTHROUGHPUT', [client_idx, torrent_infohash,
            bth.bandwidth_logger_in.cycle_length*1000,
            self.seq_None_filter(bth.bandwidth_logger_in[-max_len:], -1),
            bth.bandwidth_logger_out.cycle_length*1000,
            self.seq_None_filter(bth.bandwidth_logger_out[-max_len:], -1)
      ])
   
   def input_process_FORCEBTCREANNOUNCE(self, cmd, args):
      """Process FORCEBTCREANNOUNCE message"""
      client_idx = self.client_nnint_get(args, 0)
      self.btm.bt_clients[client_idx].bths_reannounce_tracker()
      self.msg_send(b'COMMANDOK', [cmd] + args)
   
   def input_process_STARTBTH(self, cmd, args):
      """Process STARTBTH message"""
      client_idx = self.client_nnint_get(args,0)
      torrent_infohash = args[1]
      client = self.btm.bt_clients[client_idx]
      
      if (client.torrent_active_get(torrent_infohash)):
         self.msg_send(b'COMMANDNOOP', [cmd] + args)
      else:
         client.torrent_start(torrent_infohash)
         self.msg_send(b'COMMANDOK', [cmd] + args)
      
   def input_process_STOPBTH(self, cmd, args):
      """Process STOPBTH message"""
      client_idx = self.client_nnint_get(args,0)
      torrent_infohash = args[1]
      client = self.btm.bt_clients[client_idx]
      if (not client.torrent_active_get(torrent_infohash)):
         self.msg_send(b'COMMANDNOOP', [cmd] + args)
      else:
         client.torrent_stop(torrent_infohash)
         self.msg_send(b'COMMANDOK', [cmd] + args)
   
   def input_process_SUBSCRIBEBTHTHROUGHPUT(self, cmd, args):
      """Process SUBSCRIBEBTHTHROUGHPUT message"""
      client_idx = self.client_nnint_get(args,0)
      client = self.btm.bt_clients[client_idx]
      
      if (client in self.bth_throughput_listeners):
         self.msg_send(b'COMMANDNOOP', [cmd] + args)
      else:
         #self.em_throughput_close_handle #FIXME: build seperate EM for this
         self.bth_throughput_listeners[client] = \
            client.em_throughput.new_listener(self.em_throughput_cycle_handle)
         self.msg_send(b'COMMANDOK', [cmd] + args)
      
   def input_process_UNSUBSCRIBEBTHTHROUGHPUT(self, cmd, args):
      """Process UNSUBSCRIBEBTHTHROUGHPUT message"""
      client_idx = self.client_nnint_get(args,0)
      client = self.btm.bt_clients[client_idx]
      
      if (client in self.bth_throughput_listeners):
         listener = self.bth_throughput_listeners.pop(client)
         listener.close()
         self.msg_send(b'COMMANDOK', [cmd] + args)
      else:
         self.msg_send(b'COMMANDNOOP', [cmd] + args)
         
#------------------------------------------------------------------------------ protocol error handlers
   def error_process_benc(self, msg_string):
      """Process reception of invalidly encoded message"""
      self.msg_send(b'BENCERROR', [msg_string])
      
   def error_process_unknowncmd(self, msg_string, msg_data):
      """Process reception of unknown command"""
      self.msg_send(b'UNKNOWNCMD', msg_data)
      
   def error_process_arg(self, msg_string, msg_data, exc=None):
      """Process reception of command with invalid arguments"""
      self.msg_send(b'ARGERROR', [msg_data, str(exc).encode('ascii')])

#------------------------------------------------------------------------------ event multiplexer event handlers
   def em_throughput_cycle_handle(self, btc, down_data, up_data):
      """Process multiplexed cycle event from bt_client"""
      # Inefficient, but that's probably ok
      self.msg_send(b'BTHTHROUGHPUTSLICE', [
         str(self.btm.btc_index(btc)).encode('ascii'), down_data, up_data])
   
   # FIXME: repair this somehow
   #def em_throughput_close_handle(self):
      #"""Process unregistering of cycle event listener from bt_client"""
      ## FIXME: need to call this differently now
      #if (self.cleanup_running):
         #return
      ## Inefficient, but that's probably ok
      #for (key, val) in self.bth_throughput_listeners.items():
         #if (val == listener):
            #del(self.bth_throughput_listeners[key])
            #self.msg_send(b'UNSUBSCRIBE', [str(self.btm.btc_index(key)).encode('ascii')])
            #break
      #else:
         #raise ValueError(b'Not tracking listener {0}.'.format(listener,))

   def close_process(self, fd):
      """Process closing of one of our fds"""
      pass

   def close(self):
      """Close connection and deregister active listeners"""
      AsyncDataStream.close(self)
      self.cleanup_running = True
      for listener in self.bth_throughput_listeners.values():
         listener.close()
      self.bth_throughput_listeners = {}
      self.cleanup_running = False
   
   # tuple contents:
   #  1. name of processing method
   #  2. race condition risk
   #  3. commands that may cause this command; None for unprovoked commands
   input_handlers = {
      b'BUILDBTHFROMMETAINFO': ('input_process_BUILDBTHFROMMETAINFO', RC_BTCC, None),
      b'DROPBTH': ('input_process_DROPBTH', RC_BTCC, None), # FIXME: add missing RC risks here
      b'GETCLIENTCOUNT': ('input_process_GETCLIENTCOUNT', RC_NONE, None),
      b'GETCLIENTDATA': ('input_process_GETCLIENTDATA', RC_BTCC, None),
      b'GETCLIENTTORRENTS': ('input_process_GETCLIENTTORRENTS', RC_BTCC, None),
      b'GETBTHDATA': ('input_process_GETBTHDATA', RC_BTCC, None),
      b'GETBTHTHROUGHPUT': ('input_process_GETBTHTHROUGHPUT', RC_BTCC, None),
      b'FORCEBTCREANNOUNCE': ('input_process_FORCEBTCREANNOUNCE', RC_BTCC, None),
      b'STARTBTH': ('input_process_STARTBTH', RC_BTCC, None),
      b'STOPBTH': ('input_process_STOPBTH', RC_BTCC, None),
      b'SUBSCRIBEBTHTHROUGHPUT':('input_process_SUBSCRIBEBTHTHROUGHPUT', RC_BTCC, None),
      b'UNSUBSCRIBEBTHTHROUGHPUT':('input_process_UNSUBSCRIBEBTHTHROUGHPUT', RC_BTCC, None)
   }


class BTManagerBase:
   def __init__(self, peer_id_generator, bt_clients=()):
      self.peer_id_generator = peer_id_generator
      self.bt_clients = list(bt_clients)
      self.event_listeners = []
      for btc in bt_clients:
         for attr in ('em_throughput', 'em_bth_add', 'em_bth_remove'):
            assert hasattr(btc, attr)
      
      for btc in bt_clients:
         self.event_listeners.append(btc.em_bth_add.new_listener(self.bth_change_process))
         self.event_listeners.append(btc.em_bth_remove.new_listener(self.bth_change_process))

      self.control_connections = list()
      
   def btc_index(self, btc):
      """Return index of specified btc"""
      # Inefficient for a non-trivial number of btcs, but that's probably ok
      return self.bt_clients.index(btc)
      
   def cc_add(self, cc):
      """Start using specified control connection"""
      if (cc in self.control_connections):
         raise BTManagerError('Already using CC {0}.'.format(cc))
      self.control_connections.append(cc)

   def btc_add(self, btc):
      """Start managing specified bt client"""
      if (btc in self.bt_clients):
         raise BTManagerError('Already managing BTC {0}.'.format(btc,))
      
      for attr in ('em_throughput', 'em_bth_add', 'em_bth_remove'):
         assert hasattr(btc, attr)
         
      self.bt_clients.append(btc)
      self.event_listeners.append(btc.em_bth_add.new_listener(self.bth_change_process))
      self.event_listeners.append(btc.em_bth_remove.new_listener(self.bth_change_process))
      for conn in self.control_connections:
         conn.btc_change_note()
   
   def bth_change_process(self, btclient, info_hash):
      """Process BTH set change event from one of our btcs"""
      btc_index = self.btc_index(btclient)
      for con in self.control_connections:
         conn.bthset_change_note(btc_index)


class StreamSockBTManager(BTManagerBase):
   logger = logging.getLogger('StreamSockBTManager')
   log = logger.log
   def __init__(self, event_dispatcher, peer_id_generator, address_family,
         address, backlog=5, bt_clients=(), **kwargs):
      BTManagerBase.__init__(self, peer_id_generator, bt_clients=bt_clients,
         **kwargs)
      self.event_dispatcher = event_dispatcher
      self.serv = AsyncSockServer(event_dispatcher, address,
         family=address_family, backlog=backlog)
      self.serv.connect_process = self.cc_new_handle
      
   def cc_new_handle(self, sock, addressinfo):
      """Initialize new control connection."""
      self.log(20, '{0} accepting new control connection on {1} from {2}.'.format(
         self, sock, addressinfo))
      BTControlConnection(self, self.event_dispatcher, sock)

