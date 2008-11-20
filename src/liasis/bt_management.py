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

import os
import logging

from gonium.fd_management import SockStreamBinary, SockServer
from gonium.event_multiplexing import DSEventAggregator, CCBEventListener

from bt_client import EABTClient, peer_id_generate
import benc_structures
from benc_structures import BTMetaInfo
from bt_piecemasks import PieceMask
from cc_base import BTControlConnectionBase, BTControlConnectionError


class BTManagerError(StandardError):
   pass


class BTControlConnection(BTControlConnectionBase, SockStreamBinary):
   """Liasis BT Control Connection; server side"""
   logger = logging.getLogger('BTControlConnection')
   log = logger.log
   
   RC_NONE = 0
   RC_BTCC = 1 # 2**0
   
   def __init__(self, *args, **kwargs):
      SockStreamBinary.__init__(self, *args, **kwargs)
      BTControlConnectionBase.__init__(self)
      # sequence ids
      self.snum_btc = 0
      self.snum_bthsets = 0
      self.btm = None
      self.bth_throughput_listeners = {}
      self.cleanup_running = False

#------------------------------------------------------------------------------- btm input interface
   def btc_change_note(self):
      """Assert that our btm's BT Client list has changed"""
      self.snum_out += 1
      self.snum_btc = self.snum_out
      self.msg_send('INVALIDCLIENTCOUNT', [])
   
   def bth_change_process(self, btc_index):
      """Assert that the set of bths managed by the specifed btc has changed"""
      btc_index = int(btc_index)
      self.snum_out += 1
      self.snum_bthsets = self.snum_out
      self.msg_send('INVALIDCLIENTTORRENTS', [str(btc_index)])
      
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
         raise ValueError("Arg with index %d (val %d) is invalid; should be >= 0." % (arg_idx, rv))
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
         raise ValueError('Benc string %r is invalid')
      
      if (mi.info_hash in btc.torrents):
         self.msg_send('COMMANDNOOP', [cmd] + args)
      else:
         btc.torrent_add(mi, peer_id=peer_id_generate(), 
               piecemask_validate=True,
               piecemask=PieceMask.build_full(len(mi.piece_hashes)),
               active=active)
         self.msg_send('COMMANDOK', [cmd] + args)
   
   def input_process_DROPBTH(self, cmd, args):
      """Process DROPBTH message"""
      client_idx = self.client_nnint_get(args, 0)
      btc = self.btm.bt_clients[client_idx]
      mi_string = args[1]
      btc.torrent_drop(mi_string)
      self.msg_send('COMMANDOK', [cmd] + args)
      
   def input_process_GETCLIENTCOUNT(self, cmd, args):
      """Process GETCLIENTCOUNT message"""
      self.msg_send('CLIENTCOUNT', [len(self.btm.bt_clients)])
   
   def input_process_GETCLIENTDATA(self, cmd, args):
      """Process GETCLIENTDATA message"""
      client_idx = self.client_nnint_get(args,0)
      self.msg_send('CLIENTDATA', [client_idx, self.btm.bt_clients[client_idx].state_get()])
   
   def input_process_GETCLIENTTORRENTS(self, cmd, args):
      """Process GETCLIENTTORRENTS message"""
      client_idx = self.client_nnint_get(args,0)
      self.msg_send('CLIENTTORRENTS', [client_idx, list(self.btm.bt_clients[client_idx].torrents.keys())])
   
   def input_process_GETBTHDATA(self, cmd, args):
      """Process GETBTHDATA message"""
      client_idx = self.client_nnint_get(args,0)
      torrent_infohash = args[1]
      
      self.msg_send('BTHDATA', [client_idx, self.btm.bt_clients[client_idx].torrents[torrent_infohash]])
   
   def input_process_GETBTHTHROUGHPUT(self, cmd, args):
      """Process GETBTHTHROUGHPUT message"""
      client_idx = self.client_nnint_get(args,0)
      torrent_infohash = args[1]
      max_len = self.client_nnint_get(args,2)
      
      bth = self.btm.bt_clients[client_idx].torrents[torrent_infohash]
      
      self.msg_send('BTHTHROUGHPUT', [client_idx, torrent_infohash,
            bth.bandwith_logger_in.cycle_length*1000,
            self.seq_None_filter(bth.bandwith_logger_in[-max_len:], -1),
            bth.bandwith_logger_out.cycle_length*1000,
            self.seq_None_filter(bth.bandwith_logger_out[-max_len:], -1)
      ])
   
   def input_process_FORCEBTCREANNOUNCE(self, cmd, args):
      """Process FORCEBTCREANNOUNCE message"""
      client_idx = self.client_nnint_get(args, 0)
      self.btm.bt_clients[client_idx].bths_reannounce_tracker()
      self.msg_send('COMMANDOK', [cmd] + args)
   
   def input_process_STARTBTH(self, cmd, args):
      """Process STARTBTH message"""
      client_idx = self.client_nnint_get(args,0)
      torrent_infohash = args[1]
      client = self.btm.bt_clients[client_idx]
      
      if (client.torrent_active_get(torrent_infohash)):
         self.msg_send('COMMANDNOOP', [cmd] + args)
      else:
         client.torrent_start(torrent_infohash)
         self.msg_send('COMMANDOK', [cmd] + args)
      
   def input_process_STOPBTH(self, cmd, args):
      """Process STOPBTH message"""
      client_idx = self.client_nnint_get(args,0)
      torrent_infohash = args[1]
      client = self.btm.bt_clients[client_idx]
      if (not client.torrent_active_get(torrent_infohash)):
         self.msg_send('COMMANDNOOP', [cmd] + args)
      else:
         client.torrent_stop(torrent_infohash)
         self.msg_send('COMMANDOK', [cmd] + args)
   
   def input_process_SUBSCRIBEBTHTHROUGHPUT(self, cmd, args):
      """Process SUBSCRIBEBTHTHROUGHPUT message"""
      client_idx = self.client_nnint_get(args,0)
      client = self.btm.bt_clients[client_idx]
      
      if (client in self.bth_throughput_listeners):
         self.msg_send('COMMANDNOOP', [cmd] + args)
      else:
         self.bth_throughput_listeners[client] = CCBEventListener(
            client.em_throughput, self.em_throughput_close_handle,
            self.em_throughput_cycle_handle)
         self.msg_send('COMMANDOK', [cmd] + args)
      
   def input_process_UNSUBSCRIBEBTHTHROUGHPUT(self, cmd, args):
      """Process UNSUBSCRIBEBTHTHROUGHPUT message"""
      client_idx = self.client_nnint_get(args,0)
      client = self.btm.bt_clients[client_idx]
      
      if (client in self.bth_throughput_listeners):
         listener = self.bth_throughput_listeners.pop(client)
         listener.clean_up()
         self.msg_send('COMMANDOK', [cmd] + args)
      else:
         self.msg_send('COMMANDNOOP', [cmd] + args)
         
#------------------------------------------------------------------------------ protocol error handlers
   def error_process_benc(self, msg_string):
      """Process reception of invalidly encoded message"""
      self.msg_send('BENCERROR', [msg_string])
      
   def error_process_unknowncmd(self, msg_string, msg_data):
      """Process reception of unknown command"""
      self.msg_send('UNKNOWNCMD', msg_data)
      
   def error_process_arg(self, msg_string, msg_data, exc=None):
      """Process reception of command with invalid arguments"""
      self.msg_send('ARGERROR', [msg_data, str(exc)])

#------------------------------------------------------------------------------ event multiplexer event handlers
   def em_throughput_cycle_handle(self, listener, btc, down_data, up_data):
      """Process multiplexed cycle event from bt_client"""
      # Inefficient, but that's probably ok
      self.msg_send('BTHTHROUGHPUTSLICE', [str(self.btm.btc_index(btc)), down_data, up_data])
      
   def em_throughput_close_handle(self, listener):
      """Process unregistering of cycle event listener from bt_client"""
      if (self.cleanup_running):
         return
      # Inefficient, but that's probably ok
      for (key, val) in self.bth_throughput_listeners.items():
         if (val == listener):
            del(self.bth_throughput_listeners[key])
            self.msg_send('UNSUBSCRIBE', [str(self.btm.btc_index(key))])
            break
      else:
         raise ValueError('Not tracking listener %r.' % (listener,))

   def close_process(self, fd):
      """Process closing of one of our fds"""
      pass

   def clean_up(self):
      """Close connection and deregister active listeners"""
      SockStreamBinary.clean_up(self)
      self.cleanup_running = True
      for listener in self.bth_throughput_listeners.values():
         listener.clean_up()
      self.bth_throughput_listeners = {}
      self.cleanup_running = False
   
   # tuple contents:
   #  1. name of processing method
   #  2. race condition risk
   #  3. commands that may cause this command; None for unprovoked commands
   input_handlers = {
      'BUILDBTHFROMMETAINFO': ('input_process_BUILDBTHFROMMETAINFO', RC_BTCC, None),
      'DROPBTH': ('input_process_DROPBTH', RC_BTCC, None), # FIXME: add missing RC risks here
      'GETCLIENTCOUNT': ('input_process_GETCLIENTCOUNT', RC_NONE, None),
      'GETCLIENTDATA': ('input_process_GETCLIENTDATA', RC_BTCC, None),
      'GETCLIENTTORRENTS': ('input_process_GETCLIENTTORRENTS', RC_BTCC, None),
      'GETBTHDATA': ('input_process_GETBTHDATA', RC_BTCC, None),
      'GETBTHTHROUGHPUT': ('input_process_GETBTHTHROUGHPUT', RC_BTCC, None),
      'FORCEBTCREANNOUNCE': ('input_process_FORCEBTCREANNOUNCE', RC_BTCC, None),
      'STARTBTH': ('input_process_STARTBTH', RC_BTCC, None),
      'STOPBTH': ('input_process_STOPBTH', RC_BTCC, None),
      'SUBSCRIBEBTHTHROUGHPUT':('input_process_SUBSCRIBEBTHTHROUGHPUT', RC_BTCC, None),
      'UNSUBSCRIBEBTHTHROUGHPUT':('input_process_UNSUBSCRIBEBTHTHROUGHPUT', RC_BTCC, None)
   }


class BTManagerBase:
   def __init__(self, bt_clients=()):
      self.bt_clients = list(bt_clients)
      self.event_listeners = []
      for btc in bt_clients:
         for attr in ('em_throughput', 'em_bth_add', 'em_bth_remove'):
            assert hasattr(btc, attr)
      
      for btc in bt_clients:
         self.event_listeners.append(btc.em_bth_add.EventListener(self.bth_change_process))
         self.event_listeners.append(btc.em_bth_remove.EventListener(self.bth_change_process))

      self.control_connections = list()
      
   def btc_index(self, btc):
      """Return index of specified btc"""
      # Inefficient for a non-trivial number of btcs, but that's probably ok
      return self.bt_clients.index(btc)
      
   def cc_add(self, cc):
      """Start using specified control connection"""
      if (cc in self.control_connections):
         raise BTManagerError('Already using CC %r.' % (cc,))
      self.control_connections.append(cc)

   def btc_add(self, btc):
      """Start managing specified bt client"""
      if (btc in self.bt_clients):
         raise BTManagerError('Already managing BTC %r.' % (btc,))
      
      for attr in ('em_throughput', 'em_bth_add', 'em_bth_remove'):
         assert hasattr(btc, attr)
         
      self.bt_clients.append(btc)
      self.event_listeners.append(btc.em_bth_add.EventListener(self.bth_change_process))
      self.event_listeners.append(btc.em_bth_remove.EventListener(self.bth_change_process))
      for conn in self.control_connections:
         conn.btc_change_note()
   
   def bth_change_process(self, listener, info_hash):
      """Process BTH set change event from one of our btcs"""
      btc_index = self.btc_index(listener.multiplexer.parent)
      for con in self.control_connections:
         conn.bthset_change_note(btc_index)


class StreamSockBTManager(BTManagerBase):
   logger = logging.getLogger('StreamSockBTManager')
   log = logger.log
   def __init__(self, event_dispatcher, address_family, bindargs, backlog=5, bt_clients=(),
            **kwargs):
      BTManagerBase.__init__(self, bt_clients=bt_clients, **kwargs)
      self.event_dispatcher = event_dispatcher
      self.serv = event_dispatcher.SockServer(bindargs=bindargs,
         address_family=address_family, connect_handler=self.cc_new_handle,
         connection_factory=BTControlConnection, backlog=backlog)
      
   def cc_new_handle(self, connection):
      """Initialize new control connection."""
      self.log(20, '%r accepting new control connection %r from %r.' % (self,
            connection, connection.address))
      connection.btm = self


