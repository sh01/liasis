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

import logging
import time

from gonium import fd_management
from gonium.fd_management import SockStreamBinary
from gonium.event_multiplexing import EventMultiplexer

from liasis.bandwith_management import RingBuffer

from benc_structures import BTMetaInfo
from cc_base import BTControlConnectionBase, BTControlConnectionError, \
BTCCStateError
from bt_client_mirror import SIHLBTClientMirror, BTorrentHandlerMirror


class Universe:
   """The set of everything; only supports the 'in' operator."""
   def __contains__(self, el):
      return True

class BTControlConnectionClient(BTControlConnectionBase):
   """Liasis BT Control Connection; client side"""
   logger = logging.getLogger('BTControlConnectionClient')
   log = logger.log
   
   btcm_cls = SIHLBTClientMirror
   bthm_cls = BTorrentHandlerMirror
   
   def __init__(self):
      BTControlConnectionBase.__init__(self)
      self.cc = None
      self.bt_clients = []
      self.up_to_date = False
     
      #------------------------------------------------------------------------------ subclass interface
      self.em_utd_change_true = EventMultiplexer(self)
      self.em_utd_change_false = EventMultiplexer(self)
      self.em_throughput_block = EventMultiplexer(self)
      self.em_throughput_slice = EventMultiplexer(self)


#------------------------------------------------------------------------------ implemented general-purpose methods
   def utd_status_update(self):
      """Process possible changes in our up-to-date status"""
      uod_current = True
      for bt_client in self.bt_clients:
         if ((bt_client is None) or (not bt_client.up_to_date)):
            uod_current = False
            break

      if (uod_current != self.up_to_date):
         self.up_to_date = uod_current
         if (uod_current):
            self.em_utd_change_true()
         else:
            self.em_utd_change_false()
   
   def msg_send(self, cmd, args):
      """Queue a single message specified by cmd and args to peer."""
      BTControlConnectionBase.msg_send(self, cmd, args)
      self.messages_pending.append([cmd] + args)

   def data_update(self):
      """Sync model of peer's state to peer"""
      self.msg_send('GETCLIENTCOUNT', [])
   
   def bth_start(self, client_idx, info_hash):
      """Start specified BTH"""
      self.msg_send('STARTBTH', [int(client_idx), str(info_hash)])
   
   def bth_stop(self, client_idx, info_hash):
      """Stop specified BTH"""
      self.msg_send('STOPBTH', [int(client_idx), str(info_hash)])
   
   def bth_drop(self, client_idx, info_hash):
      """Drop specified BTH from list of BTHs managed by specified BTC"""
      self.msg_send('DROPBTH', [int(client_idx), str(info_hash)])
   
   def btc_reannounce_force(self, client_idx):
      """Force active BTHs of specified BTC to reannounce to their trackers"""
      self.msg_send('FORCEBTCREANNOUNCE', [int(client_idx)])
   
   def bth_add_from_metainfo(self, client_idx, mi_str, active):
      """Add new BTH built from provided MI string to specified BTC"""
      # sanity check
      mi = BTMetaInfo.build_from_benc_string(mi_str)
      self.msg_send('BUILDBTHFROMMETAINFO', [int(client_idx), mi_str, int(active)])
   
   def rcr_presence_check(self, rc_risk, seq_num):
      """Save specified seq_num and return False"""
      self.snum_in = self.snum_out = seq_num
      return False
   
#------------------------------------------------------------------------------ network input handler helper functions
   @staticmethod
   def seq_None_unfilter(seq, replacement=-1):
      """Replace replacement elements in sequence with None"""
      rv = []
      for el in seq:
         if (el == replacement):
            rv.append(None)
         else:
            rv.append(el)
      return rv
   
#------------------------------------------------------------------------------ network input handlers
   def input_process_PROTOERROR(self, cmd, args):
      """Process protocol error message"""
      raise BTControlConnectionError('%r got %s line: %r' % (self, cmd, [cmd,] + list(args)))

   def input_process_BTHDATA(self, cmd, args):
      """Process BTHDATA message"""
      client_idx = int(args[0])
      client = self.bt_clients[client_idx]
      info_hash = args[1]
      bthm = self.bthm_cls.build_from_state(args[2])
      
      client.torrents[info_hash] = bthm
      client.up_to_date = (not (None in td.values()))
      client.infohash_list_update()
      self.utd_status_update()
   
   def input_process_BTHTHROUGHPUT(self, cmd, args):
      """Process BTHTHROUGHPUT message"""
      client_idx = int(args[0])
      info_hash = args[1]

      cycle_len_down = int(args[2])/1000.0
      tp_hist_down = self.seq_None_unfilter(args[3])
      cycle_len_up = int(args[4])/1000.0
      tp_hist_up = self.seq_None_unfilter(args[5])
      
      self.em_throughput_block(client_idx, info_hash, tp_hist_down, tp_hist_up)

   def input_process_BTHTHROUGHPUTSLICE(self, cmd, args):
      """Process BTHTHROUGHPUTSLICE message"""
      client_idx = int(args[0])
      down_data = args[1]
      up_data = args[2]
      self.em_throughput_slice(client_idx, down_data, up_data)

   def input_process_CLIENTCOUNT(self, cmd, args):
      """Process CLIENTCOUNT message and request full data for each client"""
      self.cc = int(args[0])
      self.bt_clients = [None]*self.cc
      for i in range(self.cc):
         self.msg_send('GETCLIENTDATA', [i,])
   
   def input_process_CLIENTDATA(self, cmd, args):
      """Process CLIENTDATA message"""
      client_idx = int(args[0])
      btcm = self.btcm_cls.build_from_state(args[1])
      btcm.up_to_date = True
      self.bt_clients[client_idx] = btcm
      self.utd_status_update()
   
   def input_process_CLIENTTORRENTS(self, cmd, args):
      """Process CLIENTTORRENTS message"""
      client_idx = int(args[0])
      client = self.bt_clients[client_idx]
      info_hashes = args[1]
      
      td = client.torrents
      for info_hash in td:
         if not (info_hash in info_hashes):
            del(td[info_hash])
      
      for info_hash in info_hashes:
         if not (info_hash in td):
            td[info_hash] = None
            self.msg_send('GETBTHDATA', [client_idx, info_hash])
      
      client.up_to_date = (not (None in td.values()))
      client.infohash_list_update()
      self.utd_status_update()
   
   def input_process_COMMANDOK(self, cmd, args):
      """Process COMMANDOK message"""
      pass

   def input_process_COMMANDNOOP(self, cmd, args):
      """Process COMMANDNOOP message"""
      pass

   def input_process_INVALIDCLIENTCOUNT(self, cmd, args):
      """Process INVALIDCLIENTCOUNT message"""
      self.cc = None
      self.msg_send('GETCLIENTCOUNT', ())
   
   def input_process_INVALIDCLIENTTORRENTS(self, cmd, args):
      """Process INVALIDCLIENTTORRENTS message"""
      client_idx = int(args[0])
      self.bt_clients[client_idx].up_to_date = False
      # FIXME: should probably note that torrent list has become stale here
      self.msg_send('GETCLIENTTORRENTS', [client_idx,])
      self.utd_status_update()
      
   def input_process_RCREJ(self, cmd, args):
      """Process RCREJ message"""
      raise BTControlConnectionError('%r got %s line: %r' % (self, cmd, [cmd,] + list(args)))

#------------------------------------------------------------------------------ protocol error handlers
   def error_process_benc(self, msg_string):
      """Process reception of invalidly encoded message"""
      raise
      
   def error_process_unknowncmd(self, msg_string, msg_data):
      """Process reception of unknown command"""
      raise
      
   def error_process_arg(self, msg_string, msg_data, exc=None):
      """Process reception of command with invalid arguments"""
      raise
   
   # input command data
   all_set = Universe()
   commandnoop_set = set(('BUILDBTHFROMMETAINFO', 'STARTBTH', 'STOPBTH',
      'SUBSCRIBEBTHTHROUGHPUT', 'UNSUBSCRIBEBTHTHROUGHPUT'))
   commandok_set = commandnoop_set.union(set(('BUILDBTHFROMMETAINFO','DROPBTH')))

   # tuple contents:
   #  1. name of processing method
   #  2. race condition risk
   #  3. commands that may cause this command; None for unprovoked commands
   input_handlers = {
       'ARGERROR': ('input_process_PROTOERROR', True, all_set),
       'BENCERROR': ('input_process_PROTOERROR', True, all_set),
       'BTHDATA': ('input_process_BTHDATA', True, ('GETBTHDATA',)),
       'BTHTHROUGHPUT': ('input_process_BTHTHROUGHPUT', True, ('GETBTHTHROUGHPUT',)),
       'BTHTHROUGHPUTSLICE': ('input_process_BTHTHROUGHPUTSLICE', True, None),
       'CLIENTCOUNT': ('input_process_CLIENTCOUNT', True, ('GETCLIENTCOUNT',)),
       'CLIENTDATA': ('input_process_CLIENTDATA', True, ('GETCLIENTDATA',)),
       'CLIENTTORRENTS': ('input_process_CLIENTTORRENTS', True, ('GETCLIENTTORRENTS',)),
       'COMMANDOK': ('input_process_COMMANDOK', True, commandok_set),
       'COMMANDNOOP': ('input_process_COMMANDNOOP', True, commandnoop_set),
       'INVALIDCLIENTCOUNT': ('input_process_INVALIDCLIENTCOUNT', True, None),
       'INVALIDCLIENTTORRENTS': ('input_process_INVALIDCLIENTTORRENTS', True, None),
       'RCREJ':('input_process_RCREJ', True, all_set),
       'UNKNOWNCMD': ('input_process_PROTOERROR', True, all_set)
   }
   
   del(all_set)
   del(commandnoop_set)
   del(commandok_set)


class ThroughputCounter:
   """BTCC-using class which strives to retain accurate throughput histories
   
   Note that while this isn't a subclass of BTCC, it does expect to be
   subclassed along with it. The non-subclass status is a reminder that this
   class does not call BTCC's __init__(), and the using subclass has to do
   so itself.
   
   This class will automatically subscribe to the throughput events of all
   bt_clients shown by the liasis server, and retrieve their histories after
   sync."""
   logger = logging.getLogger('ThroughputCountingBTCC')
   log = logger.log
   def __init__(self, history_length=16384, *args, **kwargs):
      self.history_length = history_length
      self.em_throughput_block.EventListener(self.throughput_block_log)
      self.em_throughput_slice.EventListener(self.throughput_slice_log)
      self.em_utd_change_true.EventListener(self.throughput_history_sync)
   
   def throughput_history_sync(self, listener):
      """Request throughput block."""
      assert (self.up_to_date)
      for i in range(len(self.bt_clients)):
         self.msg_send('SUBSCRIBEBTHTHROUGHPUT', [i]) # won't hurt, even if we already are subscribed
         for (infohash, bth) in self.bt_clients[i].torrents.items():
            self.msg_send('GETBTHTHROUGHPUT', [i, infohash, self.history_length])
            if not (hasattr(bth, 'bandwith_logger_in')):
               bth.bandwith_logger_in = RingBuffer(self.history_length)
               bth.bandwith_logger_out = RingBuffer(self.history_length)
   
   def throughput_block_log(self, listener, client_idx, info_hash, td_down, td_up):
      """Process received block of throughput data."""
      if (not self.up_to_date):
         self.log(30, '%r not processing throughput block data since it is not currently up to date.' % (self,))
         return
      
      td_down = td_down[-self.history_length:]
      td_up = td_up[-self.history_length:]
      
      l = len(td_down)
      if (l != len(td_up)):
         raise ValueError('td_down: %r td_up: %r' % (td_down, td_up))
      
      padding = [None]*(self.history_length - l)
      # Since we're up to date, the client and info-hash had better exist.
      bth = self.bt_clients[client_idx].torrents[info_hash]
      bli = bth.bandwith_logger_in = RingBuffer(self.history_length)
      blo = bth.bandwith_logger_out = RingBuffer(self.history_length)
      
      bli.history = td_down + padding
      blo.history = td_up + padding
      
      bli.history_index = blo.history_index = (l - 1)
   
   def throughput_slice_log(self, listener, client_idx, td_down, td_up):
      """Process received slice of throughput data."""
      if (not self.up_to_date):
         self.log(30, '%r not processing throughput slice data since it is not currently up to date.' % (self,))
         return
      
      btc = self.bt_clients[client_idx]
      
      ihl = btc.infohash_list
      l = len(td_down)
      
      if (not (l == len(td_up) == len(ihl))):
         raise ValueError('td_down: %r td_up: %r infohash_list: %r' % (td_down, td_up, ihl))
      
      bthd = btc.torrents
      
      for i in range(l):
         bth = bthd[ihl[i]]
         bth.bandwith_logger_in.slice_add(td_down[i])
         bth.bandwith_logger_out.slice_add(td_up[i])


class BTControlConnectionClientGonium(BTControlConnectionClient,
      SockStreamBinary):
   def __init__(self, *args, **kwargs):
      BTControlConnectionClient.__init__(self)
      SockStreamBinary.__init__(self, *args, **kwargs)


