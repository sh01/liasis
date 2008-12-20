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

# Central BT client classes.

import datetime
import logging
import math
import os
import random
import struct
import time
from collections import deque
from hashlib import sha1,md5
from io import BytesIO

# python-crypto
# from Crypto.Cipher import ARC4
from .crypto import ARC4

# gonium
from gonium.fdm import AsyncDataStream, AsyncSockServer
from gonium.hacks.asynchttpc import build_async_opener
from gonium.event_multiplexing import DSEventAggregator, EventMultiplexer

# local imports
from . import benc_structures
from .bt_exceptions import BTClientError, BTCStateError, BTFileError, \
   HandlerNotReadyError
from .bt_piecemasks import BitMask, BlockMask
from .benc_structures import BTPeer
from .tracker_proto_structures import tracker_request_build
from .bandwidth_management import NullBandwidthLimiter, PriorityBandwidthLimiter
from .bt_client_mirror import BTClientConnectionMirror, BTorrentHandlerMirror, BTClientMirror
from .bt_semipermanent_stats import BTStatsTracker
from .diskio import BTDiskIOSync as BTDiskIO

MAINTENANCE_INTERVAL = 100

class InsanityError(BTClientError):
   pass

class ResourceLimitError(BTClientError):
   pass

class ValidationError(InsanityError):
   pass

class UnknownTorrentError(ValidationError):
   pass

class BTProtocolError(BTClientError):
   pass

class MSEProtocolError(BTProtocolError):
   pass

class BTProtocolExtensionError(BTProtocolError):
   pass

class ChokedError(BTClientError):
   pass

class DupeError(BTClientError, ValueError):
   pass


# The following is directly derived from 
# <http://en.wikipedia.org/wiki/Exponentiation_by_squaring>.
def bmodpow(base, exp, mod):
   """Efficient binary exponentiation with modulo"""
   rv = 1
   while (exp > 0):
      if ((exp % 2) != 0):
         rv *= base
         if (rv >= mod):
            rv %= mod
         exp -= 1
      
      base *= base
      if (base >= mod):
         base %= mod
      exp //= 2
      
   return rv

def peer_id_generate():
   return (b'-LS0000-' + md5('{0}{1}'.format(os.getpid(), time.time()).encode('ascii')).digest())[:20]

class ReservedMask:
   EXT_AZUREUS_EM = 2**63
   EXT_FAST = 2**3
   EXT_DHT = 2**1
   def __init__(self, mask=0):
      self.mask = int(mask)
      
   def copy(self):
      return self.__class__(self.mask)
   
   def featuremask_get(self, feature_string):
      return getattr(self, 'EXT_{0}'.format(feature_string))
   
   def feature_get(self, feature):
      return self.mask & int(feature)
   
   def feature_set(self, feature, val):
      feature = int(feature)
      if (val):
         self.mask = self.mask & (~ feature)
      else:
         self.mask = self.mask | feature
   
   @classmethod
   def build_from_binstring(cls, binstring):
      return cls(struct.unpack('>Q', binstring)[0])
   
   def binstring_get(self):
      return struct.pack('>Q', self.mask)
   
   def __repr__(self):
      return '{0}({1!a})'.format(self.__class__.__name__, self.mask)

   def __int__(self):
      return int(self.mask)
   def __and__(self, other):
      return self.__class__(int(self) & int(other))
   def __or__(self, other):
      return self.__class__(int(self) | int(other))
   def __xor__(self, other):
      return self.__class__(int(self) ^ int(other))
   def __invert__(self):
      return self.__class__(~ self.mask)


class MSEBase:
   """Base class for Message Stream Encryption features"""
   # MSE v1.0 protocol constants
   MSE_P = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A36210000000000090563
   MSE_G = 2
   MSE_VC = b'\x00\x00\x00\x00\x00\x00\x00\x00'
   
   MSE_PRIVKEY_MIN = 2**159
   MSE_PRIVKEY_MAX = 2**160-1

   MSE_CM_PLAIN = 1
   MSE_CM_RC4 = 2
   MSE_CMS_SUPPORTED = MSE_CM_PLAIN | MSE_CM_RC4
   
   MSE_LEN_CRYPTCHUNK1 = len(MSE_VC) + 6
   
   @staticmethod
   def mse_data_hash(data):
      """Compute MSE HASH() of provided data string"""
      return sha1(data).digest()
   
   def mse_variables_clear(self):
      """Set all MSE instance attributes to None"""
      self.mse_key_priv_self = None
      self.mse_key_pub_self = None
      self.mse_key_pub_peer = None
      self.mse_S = None
      self.mse_skey = None
      self.mse_rc4_dec = None
      self.mse_rc4_enc = None
      self.mse_peer_crypto_provide = None
      self.mse_padC_len = None
      self.mse_peer_ia_len = None
      self.mse_in_data_plain = None
   
   def mse_key_self_build(self):
      """Generate self public and private MSE key"""
      self.mse_key_priv_self = random.randint(self.MSE_PRIVKEY_MIN, self.MSE_PRIVKEY_MAX)
      self.mse_key_pub_self = bmodpow(self.MSE_G, self.mse_key_priv_self, self.MSE_P)
   
   def mse_S_compute(self):
      """Set mse_S based on stored private key of self and public key of peer"""
      self.mse_S = self.mse_i2s(bmodpow(self.mse_key_pub_peer, self.mse_key_priv_self, self.MSE_P), 96)
   
   def mse_hash1_compute(self):
      """Return MSE HASH('req1', S) value"""
      return self.mse_data_hash(b'req1' + self.mse_S)
   
   def mse_rc4_init(self, initstring_dec=b'keyA', initstring_enc=b'keyB'):
      """Initialize RC4 decoder and encoder for this connection"""
      self.mse_rc4_dec = ARC4.new(self.mse_data_hash(initstring_dec + self.mse_S + self.mse_skey))
      self.mse_rc4_enc = ARC4.new(self.mse_data_hash(initstring_enc + self.mse_S + self.mse_skey))
      # The MSE spec requires us to discard 1024 bytes of ARC4 output on
      # initialization.
      self.mse_rc4_dec.decrypt(b'\x00'*1024)
      self.mse_rc4_enc.encrypt(b'\x00'*1024)
   
   @classmethod
   def pad_str_build(self):
      """Generate MSE padding string (0 to 512 bytes)"""
      pad_len = random.randint(0, 4096)
      if (pad_len != 0):
         padi = random.getrandbits(pad_len)
      else:
         padi = 0
      return self.mse_i2s(padi)
   
   @staticmethod
   def mse_i2s(i, fix_len=None):
      """Convert an arbitrarily large non-negative integer into a binary string"""
      j = i
      max_e = 0
      j //= 256
      while (j > 0):
         j //= 256
         max_e += 1
      
      l = bytearray()
      j = i
      for e in range(max_e,-1,-1):
         f = 256**e
         l.append(j // f)
         j %= f
      
      
      if not (fix_len is None):
         len_delta = (fix_len - len(l))
         if (len_delta > 0):
            l = bytes(len_delta) + bytes(l)
         if (len_delta < 0):
            raise ValueError('Encoding of {0} would result in binary string {1!a}, which is longer than {2} bytes.'.forma(i, l, fix_len))
      
      return bytes(l)
   
   @staticmethod
   def mse_s2i(s):
      """Convert an arbitrarily long binary string into an integer"""
      rv = 0
      for i in range(len(s)):
         rv *= 256
         rv += ord(s[i])
      
      return rv
   
   def mse_hash2_compute(self, skey):
      """Return MSE HASH('req2', SKEY) xor HASH('req3', S) value based on specified SKEY"""
      hv1 = self.mse_data_hash(b'req2' + skey)
      hv2 = self.mse_data_hash(b'req3' + self.mse_S)
      res = b''
      hlen = len(hv1)
      if (hlen != len(hv2)):
         raise Exception('Bogus hash results: hv1: {0!a} hv2: {1!a} from parameters skey: {2!a} and mse_S: {3!a}.'.format(hv1, hv2, skey, self.mse_S))
      
      rv = bytes(((hv1[i] ^ hv2[i]) for i in range(hlen)))
      
      return rv
   

class BTClientConnection(AsyncDataStream, MSEBase):
   """Connection to a single BT peer"""
   pstr = b'BitTorrent protocol' #ver 1.0
   pprefix = bytes((len(pstr),)) + pstr
   
   logger = logging.getLogger('BTClientConnection.l1')
   log = logger.log
   logger2 = logging.getLogger('BTClientConnection.l2')
   log2 = logger2.log
   
   # Original Bittorrent protocol v1.0
   MSG_ID_CHOKE = 0
   MSG_ID_UNCHOKE = 1
   MSG_ID_INTERESTED = 2
   MSG_ID_NOTINTERESTED = 3
   MSG_ID_HAVE = 4
   MSG_ID_BITFIELD = 5
   MSG_ID_REQUEST = 6
   MSG_ID_PIECE = 7
   MSG_ID_CANCEL = 8
   
   # Fast Extension; see <http://www.bittorrent.org/fast_extensions.html>
   MSG_ID_SUGGEST_PIECE = 13
   MSG_ID_HAVE_ALL = 14
   MSG_ID_HAVE_NONE = 15
   MSG_ID_REJECT_REQUEST = 16
   MSG_ID_ALLOWED_FAST = 17
   
   # Limit the ability of hostile peers to DOS us with ridiculous buffer
   # sizes.
   # Raise this if you need it; the default is enough enough bitfields for
   # torrents with 262144 pieces, which is over an order of magnitude larger
   # than the biggest I have been able to find.
   MSG_SIZE_LIMIT = 32769
   
   pieces_wanted_max = 25
   pieces_queuelen = 16
   pieces_queue_min = 8
   
   # note that in practice this will be extended to the next integer multiple
   # of the maintenance_perform() interval of the BTorrentHandler/BTClient
   # this connection associated with
   connection_timeout = 190
   # How long to wait for blocks until we get serious doubts as to whether they'll
   # really arrive at all. After this time, mark them as unrequested, but keep
   # the requests active. Same caution to intervals as above applies.
   block_timeout = 290
   # Maximum block request size we accept; any request for a block bigger than
   # this will result in us immediately closing the connection
   request_block_length_max = 65536
   
   bytes_request_min = 1024
   
   # maximum number of blocks queued for sending to peer
   blocks_pending_out_limit = 128
   # Minimum number of blocks to wait to be queued before starting sending
   blocks_pending_out_expect = 1
   
   def __init__(self, *args, **kwargs):
      """ Initialize BTClientConnection instance.
      
      The instantiater will need to set some variables manually if this is
      an outgoing connection.
      """
      AsyncDataStream.__init__(self, inbufsize_max=(self.MSG_SIZE_LIMIT + 4), *args, **kwargs)
      # purely for convenience
      self.btpeer = None
      
      # generic connection state
      self.reserved = ReservedMask(ReservedMask.EXT_FAST)
      self.s_interest = False
      self.s_choked = True
      self.s_snubbed = False
      self.p_interest = False
      self.p_choked = True
      self.pieces_wanted = deque()
      self.blocks_pending = set()
      self.blocks_pending_out = deque()
      self.pieces_suggested = set()
      self.pieces_allowed_fast = set()
      self.piece_max = None
      self.handshake_processed = False
      self.handshake_sent = False
      self.piecemask = None   # piece status of peer
      self.sync_done = False
      self.closing = False # currently running self.close() ?
      self.buffer_input_len = 0
      self.bandwidth_request = None
      self.flush_done_callback = None
      
      # general instance state; set this manually after instantiation for 
      # outgoing connections
      self.instance_init_done = False
      self.info_hash = None
      self.self_id = None # our peer id
      self.peer_id = None # our peer's peer id
      self.handshake_callback = None
      self.keepalive_timer = None
      self.downloading = False
      self.uploading = False
      self.content_bytes_in = 0
      self.content_bytes_out = 0
      self.ts_traffic_last_out = 0
      self.ts_traffic_last_in = 0
      self.ts_start = time.time()
      self.time_block_in_waiting = None
      self.ts_request_last_out = 0
      self.bandwidth_logger_in = None
      self.bandwidth_manager_out = None
      self.bt_buffer_output = None
      self.peer_req_count = 0 # total count of blocks requested by peer
      # extensions that are active on this connection
      self.ext_Fast = False
   
      # parents
      self.bth = None # BTorrentHandler responsible for this connection
      # Set this one after instantiation for incoming connections; it's
      # optional for outgoing ones
      self.btc = None # alternative to bth: BTClient directly responsible for this connection
      # MSE init
      self.mse_variables_clear()
      self.mse_skey = None
      self.mse_init = False
      self.mse_init_done = False
      self.mse_cm = None
      self.in_buf_plain = None
      self.data_auto_decrypt = None
      self.data_auto_encrypt = None
   
   # main class API
   @classmethod
   def peer_connect(cls, ed, address, *args, **kwargs):
      """Connect to peer"""
      self = cls.build_sock_connect(ed, address, *args, **kwargs)
      self.btpeer = BTPeer(address[0], address[1], None)
      return self
      
   def init_finish(self, bth):
      """Finish variable initialization by copying data from BTorrentHandler instance"""
      self.bth = bth
      self.self_id = bth.peer_id
      self.info_hash = bth.metainfo.info_hash
      piece_count = len(bth.metainfo.piece_hashes)
      self.piece_max = piece_count - 1
      self.piecemask = BitMask(bitlen=piece_count)
      self.bandwidth_logger_in = bth.bandwidth_logger_in
      self.bandwidth_manager_out = bth.bandwidth_manager_out
      self.instance_init_done = True

   def state_get(self):
      """Summarize internal state using nested dicts, lists, ints and strings"""
      return BTClientConnectionMirror.state_get_from_original(self)

   def maintenance_perform(self):
      """Send keepalives, check interest status, etc; should be regularly called by timer"""
      now = time.time()
      if not (self):
         return
      if (now > (self.ts_traffic_last_in + self.connection_timeout)):
         if (self.sync_done):
            self.log(20, 'Soft timeout on {0}. Disconnecting.'.format(self))
            self.close() # not fatal, so remember peer for the moment
         else:
            self.log2(22, "Hard timeout (didn't finish sync) on {0}. Disconnecting.".format(self))
            self.client_error_process()
         return
      if (((now - self.ts_traffic_last_out) > 15) and self.handshake_sent):
         self.keepalive_send()
      if (self.bth):
         self.pieces_wanted_update()
      if (self.s_interest != bool(self.pieces_wanted)):
         self.interest_send(bool(self.pieces_wanted))
      if (not (self.s_choked or self.s_snubbed) and 
          (self.blocks_pending != set()) and
          (self.time_block_in_waiting + self.block_timeout < time.time())):
         self.s_snubbed = True
         self.log2(16, 'Peer at {0} appears to have started snubbing us.'.format(self))
         first = True
         for (piece_index, block_index) in self.blocks_pending.copy():
            if (first):
               first = False
            else:
               self.block_cancel(piece_index, block_index)
            self.bth.blockmask_req.block_have_set(piece_index, block_index, False)

   def piece_have_new(self, piece_index):
      """Process notification that our BTorrentHandler has finished a piece"""
      self.have_send(piece_index)
      for (i_p,i_b) in [(i_p,i_b) for (i_p, i_b) in self.blocks_pending if (i_p == piece_index)]:
         self.block_cancel(i_p,i_b)

   def process_close(self, *args, **kwargs):
      """Close connection and disassociate ourselves from BT object tree"""
      self.log2(18, '{0} shutting down'.format(self))
      self.closing = True
      if not (self.bth is None):
         self.bth.connection_remove(self)
         self.bth.pieces_availability_adjust_mask(self.piecemask, -1)
         # forget about pending blocks
         for (piece_index, block_index) in self.blocks_pending:
            self.bth.blockmask_req.block_have_set(piece_index, block_index, False)
         self.blocks_pending = set()
         self.pieces_wanted = deque()
         
         self.bth = None
      elif not (self.btc is None):
         self.btc.connection_remove(self)
         self.btc = None
      if (self.bandwidth_request):
         self.bandwidth_request.cancel()
         self.bandwidth_request = None
      if (self.flush_done_callback):
         self.flush_done_callback()
         self.flush_done_callback = None
         
      self.closing = False

   def uploading_start(self):
      """Allow ourselves to send blocks to peer"""
      if (self.uploading):
         return
      if (self.p_choked):
         self.choke_send(False)
      self.uploading = True
      
   def uploading_stop(self, choke=True):
      """Stop sending blocks to peer"""
      if not (self.uploading):
         return
      if ((not self.p_choked) and choke):
         self.choke_send(True)
         if (self.blocks_pending_out):
            if (self.ext_Fast):
               # Without the Fast Extension, choking implicitly cancels all
               # pending blocks
               for (piece_index, start, length) in self.blocks_pending_out:
                  self.reject_request_send(piece_index, start, length)
            
            self.blocks_pending_out.clear()
      self.uploading = False
   
   def read_blocks(self, force=False):
      """Request blocks from mass storage"""
      # XXX: Think about tuning this
      bpo = self.blocks_pending_out
      if (len(bpo) < self.blocks_pending_out_expect):
         if (not force):
            return
         self.log2(30, '{0} force-reading blocks ({1} pending blocks).'.format(
            self, len(bpo)))
      
      if (sum(len(b) for b in self._outbuf) > 16384):
         return
      
      total_len = sum(e[2]+13 for e in bpo)
      if (not total_len):
         return
      
      buf = bytearray(total_len)
      
      payload_len = 0
      def bpo_iter(bpo):
         nonlocal payload_len
         i = 0
         pl = self.bth.piece_length_get()
         while (bpo):
            (pi, bs, bl) = bpo.popleft()
            buf[i:13+i] = struct.pack('>LBLL', (bl+9), self.MSG_ID_PIECE, pi, bs)
            msg_len = 13 + bl
            payload_len += bl
            yield (pl*pi + bs, memoryview(buf)[i+13:i+msg_len])
            i += msg_len
         raise StopIteration()
      
      req = self.bth.bt_disk_io.async_readinto(bpo_iter(bpo),
         self._send_block)
      bpo.clear()
      req.buf = buf
      req.payload_len = payload_len

   def _output_write(self, *args, **kwargs):
      AsyncDataStream._output_write(self, *args, **kwargs)
      if ((not self._outbuf) and self.uploading):
         self.read_blocks()

   def _send_block(self, io_req):
      """Push blocks read from hd out to network"""
      if not (self):
         return
      if (io_req.failed):
         self.log2('{0} closing because of failure of IO request {1}.'.format(
            self, io_req))
         self.close()
         return
      self.content_bytes_out += io_req.payload_len
      self.send_data_bt(io_req.buf)

   # internal methods: sending data to peer
   def send_data_bt(self, data, bw_count=True, buffering_force=False, **kwargs):
      """Send data if no data buffered at bt layer, otherwise buffer it"""
      if (self.data_auto_encrypt):
         data = self.data_auto_encrypt(data)
         
      if (self.bt_buffer_output or buffering_force):
         self.bt_buffer_output += data
      else:
         self.send_bytes((data,), **kwargs)
         self.ts_traffic_last_out = time.time()
         if (bw_count):
            self.bandwidth_manager_out.bandwidth_take(len(data))
   
   # MSE handshakes
   def mse_hss1_send(self):
      """Send MSE handshake sequence 1 / 2 to peer"""
      if (self.closing):
         return
      self.send_data_bt(self.mse_i2s(self.mse_key_pub_self) + self.pad_str_build(), bw_count=False)
   
   def mse_hss5_send(self, crypto_method, pad=None):
      """Send MSE handshake sequence 5 to peer"""
      if (self.closing):
         return
      if (pad is None):
         pad = self.pad_str_build()
      
      self.send_data_bt(self.mse_rc4_enc.encrypt(self.MSE_VC +
            struct.pack('>IH', crypto_method, len(pad)) + pad),
            bw_count = False)
   
   def mse_crypto_method_select(self):
      """Select MSE crypto method based on what we and the peer support"""
      if (self.MSE_CM_PLAIN & self.mse_peer_crypto_provide):
         return self.MSE_CM_PLAIN
      elif (self.MSE_CM_RC4 & self.mse_peer_crypto_provide):
         return self.MSE_CM_RC4
      raise MSEProtocolError('Provided crypto mask {0} of client on connection'
         '{1!a} does not contain any methods supported by us.'
         ''.format(self.mse_peer_crypto_provide, self))
   
   # BT-level handshakes
   def handshake_str_get(self):
      """Return the BT handshake string we are going to send"""
      assert (self.instance_init_done and (len(self.info_hash) == 20) and (len(self.self_id) == 20))
      return b''.join((self.pprefix, self.reserved.binstring_get(), self.info_hash, self.self_id))
   
   def handshake_send(self):
      """Send handshake to peer"""
      if (self.closing):
         return
      self.send_data_bt(self.handshake_str_get())
      self.handshake_sent = True
      
   # regular BT traffic
   def keepalive_send(self):
      """Send keepalive message to peer"""
      if (self.closing):
         return

      self.send_data_bt(b'\x00\x00\x00\x00')

   def msg_send(self, msg_id, payload, bw_count=True, buffering_force=False):
      """Send message with specified msg_id and payload to peer"""
      if (self.closing):
         return
      header = struct.pack('>LB', (len(payload) + 1), msg_id)
      self.send_data_bt(header + payload, bw_count=bw_count, buffering_force=buffering_force)
      
   def choke_send(self, choking):
      """Send CHOKE/UNCHOKE message to peer and save status"""
      choking = bool(choking)
      if (choking == self.p_choked):
         raise BTCStateError('peer choked status is already {0}.'.format(self.p_choked))
      self.log2(12, '{0} changes peer choked status to {1}.'.format(self, choking))
      
      if (choking):
         msg_id = self.MSG_ID_CHOKE
      else:
         msg_id = self.MSG_ID_UNCHOKE
         
      self.msg_send(msg_id, b'')
      self.p_choked = choking
      
   def interest_send(self, interest):
      """Send INTERESTED/NOT INTERESTED message to peer and save status"""
      interest = bool(interest)
      if (interest == self.s_interest):
         raise BTCStateError('self interest status is already {0}.'.format(self.s_interest,))
      self.log2(12, '{0} changes interest status to {1}'.format(self, interest))
      
      if (interest):
         msg_id = self.MSG_ID_INTERESTED
      else:
         msg_id = self.MSG_ID_NOTINTERESTED
      
      self.msg_send(msg_id, b'')
      self.s_interest = interest
      
   def have_send(self, piece_index):
      """Send HAVE message for piece <piece_index> to peer"""
      payload = struct.pack('>L', piece_index)
      self.msg_send(self.MSG_ID_HAVE, payload)
      
   def bitfield_send(self):
      """Send BITFIELD message to peer"""
      self.msg_send(self.MSG_ID_BITFIELD, self.bth.piecemask)
      
   def block_request(self, piece_index, block):
      """Send a REQUEST message for a specific block identified by internal indexes"""
      piece_index_max = self.bth.piece_length_get(piece_index == self.piece_max) - 1
      block_start = block * self.bth.block_length
      assert (block_start <= piece_index_max)
      block_len = min(self.bth.block_length, piece_index_max - block_start + 1)
      
      self.log2(12, 'Connection {0} requesting block p{1}, s{2}, l{3}.'.format(self, piece_index, block_start, block_len))
      
      msg_payload = struct.pack('>LLL', piece_index, block_start, block_len)
      self.msg_send(self.MSG_ID_REQUEST, msg_payload)
      if (self.bth is None):
         # BTC might have been terminated during send
         return
      
      if not (self.blocks_pending):
         self.time_block_in_waiting = time.time()
      self.blocks_pending.add((piece_index, block))
      self.bth.blockmask_req.block_have_set(piece_index, block, True)
      self.ts_request_last_out = time.time()
      
   def block_cancel(self, piece_index, block_index):
      """Send CANCEL message for specified pending block, and forget about it"""
      piece_index_max = self.bth.piece_length_get(piece_index == self.piece_max) - 1
      block_start = block_index * self.bth.block_length
      assert (block_start <= piece_index_max)
      block_len = min(self.bth.block_length, piece_index_max - block_start + 1)
      
      self.log2(12, 'Connection {0} cancelling request of block p{1}, s{2}, l{3}.'.format(self, piece_index, block_start, block_len))
      msg_payload = struct.pack('>LLL', piece_index, block_start, block_len)
      
      self.block_pending_cancel((piece_index, block_index))
      self.msg_send(self.MSG_ID_CANCEL, msg_payload)
   
   def reject_request_send(self, piece_index, block_start, block_length):
      """"Send REJECT REQUEST message for specified pending block"""
      self.log2(12, 'Connection {0} rejecting peer request of block p{1}, s{2}, l{3}.'.format(self, piece_index, block_start, block_length))
      msg_payload = struct.pack('>LLL', piece_index, block_start, block_length)
      self.msg_send(self.MSG_ID_REJECT_REQUEST, msg_payload)
      
   def pieces_wanted_update(self, pm_out=None):
      """Update sequence of pieces we are interested in"""
      pieces_wanted = self.pieces_wanted
      self.pieces_wanted = deque()
      for index in pieces_wanted:
         # Forget about pieces that don't have any further desirable blocks
         if (self.bth.query_piece_wanted(index)):
            self.pieces_wanted.append(index)
      if (not self.pieces_wanted):
         if (pm_out is None):
            pm_out = self.piecemask
         self.pieces_wanted = self.bth.pieces_wanted_get(pm_out, self.pieces_wanted_max)
         
   def blocks_request(self):
      """Heuristically request pieces from peer"""
      if (not self.bth):
         return
      if (self.s_snubbed):
         return
      if (self.s_choked):
         if ((not self.ext_Fast) or (self.pieces_allowed_fast == set())):
            return
         # Are there any allowed fast pieces we don't have already, and that
         # the peer actually has?
         # While checking for it this way is somewhat wasteful when such pieces
         # exist, for most of the download period they won't, and we can save
         # cycles in those cases.
         for piece in self.pieces_allowed_fast:
            if ((not self.bth.piecemask.bit_get(piece)) and self.piecemask.bit_get(piece)):
               break
         else:
            return
         # A: Yes, there are.
         pm_out = BitMask(bitlen=self.piecemask.bitlen)
         for piece in self.pieces_allowed_fast:
            pm_out.bit_set(self.piecemask.bit_get(piece))
         self.pieces_wanted_update(pm_out)
      else:
         self.pieces_wanted_update()

      for index in self.pieces_wanted:
         if (index == self.piece_max):
            subrange = range(self.bth.blockmask.blocks_per_piece_last)
         else:
            subrange = range(self.bth.blockmask.blocks_per_piece)
         for sub_index in subrange:
            if (len(self.blocks_pending) >= self.pieces_queuelen):
               break
            if ((not self.bth.blockmask.block_have_get(index, sub_index)) and 
                ((not self.bth.blockmask_req.block_have_get(index, sub_index)) or
                (self.bth.endgame_mode and (not 
                ((index, sub_index) in self.blocks_pending))))):
               self.block_request(index, sub_index)
               if (self.bth is None):
                  # Send attempt triggered connection close
                  break
         else:
            continue
         # inner loop was broken; break this one, as well
         break

   def block_pending_cancel(self, block):
      """Process a (piece becoming non-pending) - event"""
      self.blocks_pending.remove(block)
      if not (self.blocks_pending):
         self.time_block_in_waiting = None
         self.s_snubbed = False
      # IFFY: This might become incorrect if we ever implemented endgame-
      # style parallel requests. OTOH in that case its accuracy likely
      # won't matter anymore.
      self.bth.blockmask_req.block_have_set(block[0], block[1], False)
      
   def client_error_process(self):
      """Close connection and report to BTH that this client(?) is broken"""
      self.closing = True
      if (self.bth):
         self.bth.peer_connection_error_process(self)

      self.close()
   
   def _in_data_update(self):
      """Update in_data after having baseclass discard input"""
      return memoryview(self._inbuf[:self._index_in])
   
   def mse_setup(self, crypt, decrypt):
      if not (self.data_auto_decrypt is self.data_auto_encrypt is None):
         raise BTClientError('{0} is already using crypto.'.format(self))
      self.data_auto_encrypt = crypt
      self.data_auto_decrypt = decrypt
      self._discard_inbt_data = self._discard_inbt_data_crypt
      self._wait_n_bytes = self._wait_n_bytes_crypto
   
   def _discard_inbt_data_crypt(self, length:int):
      """Discard <length> octets of processed plaintext with MSE """
      del(self.in_buf_plain[:length])
      self.buffer_input_len = len(self.in_buf_plain)
   
   def _discard_inbt_data(self, length:int):
      """Discard <length> octets of processed plaintext without MSE"""
      self.discard_inbuf_data(length)
      self.buffer_input_len = self._index_in
      return
   
   def _wait_n_bytes(self, count:int):
      """Wait for n more bytes of input before calling process_input again without MSE"""
      self.size_need = count
      
   def _wait_n_bytes_crypto(self, count:int):
      """Wait for n more bytes of input before calling process_input again with MSE"""
      self.size_need = count - len(self.in_buf_plain)
      
   def process_input(self, in_data):
      """Deal with input to our buffers"""
      if not (self):
         # Never mind; connection is dead already.
         # XXX: Try to do something useful with possibly remaining buffered
         # PIECE messages?
         return
      
      self.ts_traffic_last_in = time.time()
      
      if not (self.data_auto_decrypt is None):
         # MSE input decryption
         self.in_buf_plain += self.data_auto_decrypt(in_data)
         self.discard_inbuf_data()
         in_data = memoryview(self.in_buf_plain)
      
      self.bandwidth_logger_in.bandwidth_take(len(in_data) - self.buffer_input_len)
      self.buffer_input_len = len(in_data)
      
      if (self.mse_init):
         # MSE handshaking code
         if (self.mse_key_pub_peer is None):
            if (self.buffer_input_len < 96):
               # insufficient data for anything
               return
            self.mse_key_pub_peer = self.mse_s2i(in_data[:96])
            self.mse_S_compute()
            self._discard_inbt_data(96)
            in_data = self._in_data_update()
            self.mse_hss1_send()
         
         if (self.mse_init == 1):
            if (self.buffer_input_len >= 20):
               hash1 = self.mse_hash1_compute()
               i = bytes(in_data).find(hash1)
               if (i < 0):
                  return
               self._discard_inbt_data(i + len(hash1))
               in_data = self._in_data_update()
               self.mse_init = 2
            else:
               return
         
         if (self.mse_init == 2):
            if (self.buffer_input_len >= 20):
               hash2_val = in_data[:20]
               try:
                  self.mse_skey = self.btc.mse_hash2_resolve(self, hash2_val)
               except UnknownTorrentError:
                  self.log(25, "Handshake validation on {0} failed; not tracking torrent with infohash fitting MSE handshake data.".format(self), exc_info=False)
                  self.mse_init = False
                  self._discard_inbt_data()
                  in_data = self._in_data_update()
                  self.close()
                  return
               self.mse_rc4_init()
               self._discard_inbt_data(20)
               in_data = self._in_data_update()
               self.mse_init = 3
            else:
               return
         
         if (self.mse_init == 3):
            if (self.buffer_input_len >= self.MSE_LEN_CRYPTCHUNK1):
               data_dec = self.mse_rc4_dec.decrypt(in_data[:self.MSE_LEN_CRYPTCHUNK1])
               if not (data_dec.startswith(self.MSE_VC)):
                  raise MSEProtocolError('Connection {0} got invalid VC value {1} from peer. Closing.'.format(self, data_dec[:len(self.MSE_VC)]))
            
               data_dec_2 = data_dec[len(self.MSE_VC):]
               (self.mse_peer_crypto_provide, self.mse_padC_len) = struct.unpack('>IH', data_dec_2)
               self._discard_inbt_data(self.MSE_LEN_CRYPTCHUNK1)
               in_data = self._in_data_update()
               self.mse_init = 4
            else:
               return
         
         if (self.mse_init == 4):
            chunk_len = self.mse_padC_len + 2
            if (self.buffer_input_len >= chunk_len):
               data_dec = self.mse_rc4_dec.decrypt(in_data[:chunk_len])
               self._discard_inbt_data(chunk_len)
               in_data = self._in_data_update()
               self.mse_peer_ia_len = struct.unpack('>H', data_dec[-2:])[0]
               if (self.mse_peer_ia_len > 0):
                  self.mse_init = 5
               else:
                  self.in_buf_plain = bytearray()
                  self.mse_init = 6
            else:
               return
         
         if (self.mse_init == 5):
            if (self.buffer_input_len >= self.mse_peer_ia_len):
               self.in_buf_plain = self.mse_rc4_dec.decrypt(in_data[:self.mse_peer_ia_len])
               self._discard_inbt_data(self.mse_peer_ia_len)
               in_data = self._in_data_update()
               self.mse_init = 6
            else:
               return
         
         if (self.mse_init == 6):
            cm = self.mse_crypto_method_select()
            self.mse_cm = cm
            self.mse_hss5_send(cm)
            self.mse_init = False
            self.mse_init_done = True
            if (cm == self.MSE_CM_PLAIN):
               # Ugly hack
               del(in_data) # Destroy view on bytearray; next op would fail otherwise
               self._index_in += len(self.in_buf_plain)
               inbuf = self._inbuf
               if (len(inbuf) < self._index_in):
                  raise Exception('MSE init stage 6: inbuf of {0} has len {1}, adjusted _index_in is {2}.'.format(self, len(inbuf),self._index_in))
               self._inbuf = bytearray(len(inbuf))
               self._inbuf[:len(self.in_buf_plain)] = self.in_buf_plain
               self._inbuf[len(self.in_buf_plain):self._index_in] = inbuf
               self.in_buf_plain = None
               
            elif (cm == self.MSE_CM_RC4):
               self.mse_setup(self.mse_rc4_enc.encrypt, self.mse_rc4_dec.decrypt)
            else:
               # can't happen
               raise ValueError('Unknown chosen crypto method {0}.'.format(cm))
            self.log2(15, '{0} finished MSE initialization. Using crypto method {1}.'.format(self, cm))
            self._process_input1()
            return
      
      # Unless the connection has just started and we haven't noticed that it
      # isn't a plain BT connection yet, we should have plaintext data to work
      # with from here.
      if not (self.handshake_processed):
         # The following sanity checks are slightly wasteful in pathological
         # cases, but should always do the Right Thing.
         pstrlen = len(self.pstr)
         pprefix = self.pprefix
         fmtstr = '>B{0}s8s20s20s'.format(pstrlen)
         header_size = struct.calcsize(fmtstr)
         if (not in_data):
            return # nothing to see here, yet.
         if (in_data[0] != self.pprefix[0:1]):
            # Not what we expect.
            if (self.mse_init_done):
               self.log(30, 'Presumed BT client at {0} started with data {1}, which is bogus. Closing connection.'.format(self.btpeer, bytes(in_data)))
               self.client_error_process()
            else:
               # Might be a MSE connection, try crypto handshake.
               self.mse_init = 1
               self.mse_key_self_build()
               self._process_input1()
            return
         if (len(in_data) < (pstrlen + 1)):
            return # nothing more to see here, yet
         if (in_data[:len(self.pprefix)] != memoryview(self.pprefix)):
            # Not what we expect, either.
            if (self.mse_init_done):
               self.log(30, 'Presumed BT client at {0} started with data {1!a}, which is bogus. Closing connection.'.format(self.btpeer, bytes(in_data)))
               self.client_error_process()
            else:
               # Might be a MSE connection, try crypto handshake.
               self.mse_init = 1
               self.mse_key_self_build()
               self._process_input1()
            return
         if (len(in_data) < header_size):
            return # Beginning is good, but handshake data not complete yet.
         
         # Beginning is good, and handshake data complete.
         (pstrlen_in, pstr_in, reserved_in_raw, info_hash_in, peer_id_in) = struct.unpack(fmtstr, in_data[:header_size])
         reserved_in = ReservedMask.build_from_binstring(reserved_in_raw)
         self.log(15, 'Got valid handshake data from peer at {0!a}: info_hash {1!a}, peer_id {2!a}, reserved {3!a}'.format(self.btpeer, info_hash_in, peer_id_in, reserved_in))
         if not (self.handshake_sent):
            # This is an incoming connection, and up to here we didn't know
            # which torrent it was associated with. Ask for outside validation
            self.peer_id = peer_id_in
            self.info_hash = info_hash_in
            try:
               self.handshake_callback(self)
            except ResourceLimitError:
               self.log(15, 'Closing {0} because of resource limit.'.format(self), exc_info=True)
               self.close()
               return
            except BTCStateError as exc:
               self.log(14, "Closing {0} because of handler readiness failure {1!a}.".format(self, str(exc)))
               self.close()
               return
            except UnknownTorrentError:
               self.log(25, 'Handshake validation on {0} failed; not tracking torrent with infohash {1!a}.'.format(self, info_hash_in), exc_info=False)
               self.close()
               return
            
            # Connection is valid.
            self.handshake_send()
            self.bitfield_send()
         else:
            # This is an outgoing connection; info_hash should have been
            # set to something sensible before, and peer_id also might have
            # been
            if (self.peer_id != peer_id_in):
               if (self.peer_id):
                  self.log(30, 'Peer at {0!a} returned peer_id {1!a}, expected {2!a}.'.format(self.btpeer, peer_id_in, peer_id))
                  self.client_error_process()
                  return
               else:
                  self.peer_id = peer_id_in
            if (self.info_hash != info_hash_in):
               self.log(30, 'Peer at {0!a} returned info_hash {1!a}, expected {2!a}.'.format(self.btpeer, info_hash_in, self.info_hash))
               self.client_error_process()
               return
            self.bitfield_send()
         
         if (self.peer_id == self.self_id):
            self.log(35, 'Peer at {0} uses same peer id {1} as we do; closing.'.format(self.btpeer, self.self_id))
            self.client_error_process()
            return
         
         self.reserved &= reserved_in
         if (self.reserved.feature_get(ReservedMask.EXT_FAST)):
            self.log2(15, 'Peer at {0} supports Fast Extension; activating it.'.format(self.btpeer))
            self.ext_Fast = True
         
         self.handshake_processed = True
         if (not self):
            return
         cont = bool(in_data[header_size:])
         del(in_data)
         self._discard_inbt_data(header_size)
         if (cont):
            self._process_input1()
         return
      
      # regular protocol mode
      in_data_len = len(in_data)
      in_data_sio = BytesIO(in_data)
      msg_len = 0
      while (self._fw):
         index = in_data_sio.tell()
         if ((in_data_len - index) < 4):
            break
         msg_len = struct.unpack('>L', in_data_sio.read(4))[0]
         if (msg_len > self.MSG_SIZE_LIMIT):
            self.log(30, '{0} got message with excessive length {1}. Closing connection and discarding client. Message was: {2!a}'.format(self, msg_len, in_data_sio.read(4 + msg_len)))
            self.client_error_process()
            return
         
         if ((in_data_len - index) < (msg_len + 4)):
            in_data_sio.seek(index)
            break
         
         # Message has been buffered completely
         if (msg_len == 0):
            # keepalive msg
            continue
         msg_id = struct.unpack('>B', in_data_sio.read(1))[0]
         try:
            input_handler = self.input_handlers[msg_id]
         except KeyError:
            in_data_sio.seek(index)
            self.log(30, 'Peer {0!a} sent message with bogus msg_id {1}. Closing connection and discarding client. Message was: {2!a}'.format(self.btpeer, msg_id, bytes(in_data[index:index+4+msg_len])))
            self.client_error_process()
            return
         
         try:
            input_handler(self, in_data_sio, msg_len-1)
         except (BTClientError, ValueError, struct.error, AssertionError) as exc:
            self.log(30, 'Exception {0!a} on connection peer {1!a}. Buffered data {2!a}. Closing connection and discarding peer. Exception:'.format(str(exc), self.btpeer, bytes(in_data)), exc_info=isinstance(exc, (AssertionError, BTClientError)))
            self.client_error_process()
            return
         
         if not (self.sync_done):
            self.log(18, 'Sync on conn {0} finished.'.format(self))
            self.maintenance_perform() # set interest status
            self.sync_done = True
         # don't make any assumptions about where the handler has seeked to
         in_data_sio.seek(index + 4 + msg_len)
         msg_len = 0
      
      if ((not self) or (in_data_sio.tell() == 0)):
         return
      del(in_data)
      self._discard_inbt_data(in_data_sio.tell())
      self._wait_n_bytes(msg_len + 4)
      if (self.uploading):
         self.read_blocks()
      
   #BT Protocol v1.0 message handlers
   def input_process_choke(self, data_sio, payload_len):
      """Process CHOKE message"""
      if (payload_len != 0):
         raise BTProtocolError('Value {0} for payload_len invalid; expected 0.'.format(payload_len))
      self.log2(12, '{0} got choked by peer'.format(self))
      self.s_choked = True
      if not (self.ext_Fast):
         for block in self.blocks_pending.copy():
            self.block_pending_cancel(block)
         
   def input_process_unchoke(self, data_sio, payload_len):
      """Process UNCHOKE message"""
      if (payload_len != 0):
         raise BTProtocolError('Value {0} for payload_len invalid; expected 0.'.format(payload_len))
      self.log2(12, '{0} got unchoked by peer'.format(self))
      self.s_choked = False
      if (self.downloading and self.bth):
         self.blocks_request()

   def input_process_interested(self, data_sio, payload_len):
      """Process INTERESTED message"""
      if (payload_len != 0):
         raise BTProtocolError('Value {0} for payload_len invalid; expected 0.'.format(payload_len))
      self.log2(12, '{0} notes interest by peer'.format(self))
      self.p_interest = True

   def input_process_notinterested(self, data_sio, payload_len):
      """Process NOT INTERESTED message"""
      if (payload_len != 0):
         raise BTProtocolError('Value {0} for payload_len invalid; expected 0.'.format(payload_len))
      self.log2(12, '{0} notes disinterest by peer'.format(self))
      self.bth.downloaders_update(discard_optimistic_unchokes=False)
      self.p_interest = False
      
   def input_process_have(self, data_sio, payload_len):
      """Process HAVE message"""
      if (payload_len != 4):
         raise BTProtocolError('Value {0} for payload_len invalid; expected 4.'.format(payload_len))
      piece_index = struct.unpack('>L', data_sio.read(payload_len))[0]
      self.piecemask.bit_set(piece_index, True)
      self.bth.piece_availability_adjust(piece_index, + 1)
      
      if not (self.s_interest):
         # This may have made the peer more interesting to us
         self.maintenance_perform()
   
   def input_process_bitfield(self, data_sio, payload_len):
      """Process BITFIELD message"""
      if (self.sync_done):
         raise BTProtocolError('Got BITFIELD message after first message.')
      
      if (payload_len != len(self.piecemask)):
         raise BTProtocolError('Got BITFIELD message with bogus payload length {0}; expected {1}.'.format(payload_len, len(self.piecemask)))

      self.log(15, 'Updating bitfield on {0!a} after BITFIELD message.'.format(self))
      self.piecemask = BitMask(data_sio.read(payload_len), bitlen=self.piecemask.bitlen)
      self.bth.pieces_availability_adjust_mask(self.piecemask, +1)
   
   def input_process_request(self, data_sio, payload_len):
      """Process REQUEST message"""
      self.peer_req_count += 1
      block_data = (piece_index, block_start, block_length) = struct.unpack('>LLL', data_sio.read(payload_len))
      self.log2(12, 'Connection {0} got request for block p{1}, s{2}, l{3}'.format(self, piece_index, block_start, block_length))
      # Iffy: Without the Fast Extension, should we queue blocks while the peer is being choked?
      if (self.p_choked and self.ext_Fast):
         # When using the Fast Extension, we can just reject the request.
         self.reject_request_send(*block_data)
         return
      
      if not (self.bth.piecemask.bit_get(piece_index)):
         raise BTProtocolError('Connection {0} got request for block p{1}, s{2}, l{3}, the piece of which we do not have completed.'.format(self, piece_index, block_start, block_length))
      
      if (block_length > self.request_block_length_max):
         raise BTProtocolError('Connection {0} got request for block p{1}, s{2}, l{3}, the length of which is greater than our maximum block length {4}.'.format(self, piece_index, block_start, block_length, self.request_block_length_max))
      
      self.blocks_pending_out.append(block_data)
      if (len(self.blocks_pending_out) > self.blocks_pending_out_limit):
         raise BTProtocolError('Connection {0} has queued {1} outgoing blocks, which exceeds our limit of {2}. Block list: {3!a}'.format(self, len(self.blocks_pending_out), self.blocks_pending_out_limit, self.blocks_pending_out))
      
      if (not (self.p_choked or (self.bth is None))):
         self.bth.block_request_process(self)
   
   def input_process_piece(self, data_sio, payload_len):
      """Process PIECE message"""
      if not (payload_len >= 8):
         raise BTProtocolError('Value {0} for payload_len invalid; expected it to be >= 8.'.format(payload_len))
         
      (piece_index, start) = struct.unpack('>LL', data_sio.read(8))
      block_length = payload_len - 8
      self.log2(12, 'Connection {0} got block p{1}, s{2}, l{3}'.format(self, piece_index, start, block_length))
      
      block_index = start//self.bth.block_length
      block_tuple = (piece_index, block_index)
      
      if not (block_tuple in self.blocks_pending):
         if (self.ext_Fast):
            raise BTProtocolError('Connection {0} got block p{1}, s{2}, l{3}, which I do not remember requesting.'.format(self, piece_index, start, block_length))
         else:
            # This can result from a race condition inherent in the Bittorrent
            # Protocol v1.0 without the Fast Extension. Specifically, when
            # receiving a choke, we assume that all outstanding block requests
            # have been implicitly cancelled, but if the choke was sent, *and*
            # an unchoke also is sent by the peer before our (last) requests
            # are actually processed, they'll "still" be active after the
            # choke-unchoke sequence.
            # This may sound far-fetched, but unfortunately it isn't; at least
            # one client actually does perform chokes immediately followed by
            # unchokes, and the desync resulting from not taking the race
            # condition into account has been observed in practice.
            self.log2(19, 'Connection {0} got block p{1}, s{2}, l{3}, which I do not remember requesting. Discarding data.'.format(self, piece_index, start, block_length))
            self.s_snubbed = False
      else:
         self.block_pending_cancel(block_tuple)
         self.time_block_in_waiting = time.time()
         snubbed_previous = self.s_snubbed
         self.s_snubbed = False
         self.bth.block_process(self, piece_index, start, block_length, data_sio, duplicate_ignore=snubbed_previous)
         self.content_bytes_in += block_length

      if (len(self.blocks_pending) < self.pieces_queue_min):
         self.blocks_request()
      
   def input_process_cancel(self, data_sio, payload_len):
      """Process CANCEL message"""
      block_tuple = (piece_index, start, length) = struct.unpack('>LLL', data_sio.read(payload_len))
      self.log2(12, 'Connection {0} got request cancel for block p{1}, s{2}, l{3}'.format(self, piece_index, start, length))
      try:
         self.blocks_pending_out.remove(block_tuple)
      except ValueError:
         # This can happen as a result of a race condition; i.e. we start
         # sending the block/rejecting the request/choking the peer and the
         # other client cancels it before receiving our response.
         self.log2(19, 'Connection {0} got request cancel for non-outstanding block p{1}, s{2}, l{3}.'.format(self, piece_index, start, length))
   
   # BT Protocol Extension 'Fast Extension' message handlers
   def input_process_suggest_piece(self, data_sio, payload_len):
      """Process SUGGEST PIECE message"""
      piece_index = struct.unpack('>L', data.sio.read(payload_len))[0]
      if not (self.bth.piecemask.bit_get(piece_index)):
         self.pieces_suggested.add(piece_index)
      
   def input_process_have_all(self, data_sio, payload_len):
      """Process (Fast Extensions) HAVE ALL message"""
      if not (self.ext_Fast):
         raise BTProtocolExtensionError('Got HAVE ALL message on connection without Fast extensions')
      if (payload_len != 0):
         raise BTProtocolError('Value {0} for payload_len invalid; expected 0.'.format(payload_len))
      self.piecemask = BitMask.build_full(len(self.bth.metainfo.piece_hashes))
      
   def input_process_have_none(self, data_sio, payload_len):
      """Process (Fast Extensions) HAVE NONE message"""
      if not (self.ext_Fast):
         raise BTProtocolExtensionError('Got HAVE NONE message on connection without Fast extensions')
      if (payload_len != 0):
         raise BTProtocolError('Value {0} for payload_len invalid; expected 0.'.format(payload_len))
      assert (payload_len == 0)
      # The  Fast Extension spec is quite clear on that one of HAVE ALL,
      # HAVE NONE, BITFIELD MUST be sent at the start of the connection if
      # the extension is in use, but it doesn't specify that we have to close
      # the connection if we don't get one of the messages.
      # We'll default to an empty bitfield if we don't get anything, just as
      # with protocol ver 1.0
      
   def input_process_reject_request(self, data_sio, payload_len):
      """Process (Fast Extensions) REJECT REQUEST message"""
      if not (self.ext_Fast):
         raise BTProtocolExtensionError('Got REJECT REQUEST message on connection without Fast extensions')
      (piece_index, start, length) = struct.unpack('>LLL', data_sio.read(payload_len))
      
      if ((block_index % self.bth.block_length) != 0):
         raise BTProtocolError('Got bogus REJECT REQUEST message for p{0}, s{1}, l{2}: block start is no integer multiple of our block_length {3}.'.format(piece_index, start, length, self.bth.block_length))
      
      block_index = start//self.bth.block_length
      block_tuple = (piece_index, block_index)
      
      if not (block_tuple in self.blocks_pending):
         raise BTProtocolError("Got REJECT REQUEST message for block p{0}, s{1}, l{2}, which I don't remember requesting.".format(piece_index, start, length))

      self.log2(14, '{0} processing valid REJECT REQUEST message for block p{1}, s{2}, l{3}.'.format(self, piece_index, start, length))
      self.block_pending_cancel(block_tuple)
      
   def input_process_allowed_fast(self, data_sio, payload_len):
      """Process (Fast Extensions) ALLOWED FAST message"""
      if not (self.ext_Fast):
         raise BTProtocolExtensionError('Got ALLOWED FAST message on connection without Fast extensions')
      
      piece_index = struct.unpack('>L', data_sio.read(payload_len))
      if not (piece_index < self.piecemask.bitlen):
         raise BTProtocolError('Got ALLOWED FAST message for bogus piece {0}.'.format(piece_index))
      
      self.log2(12, '{0} processing valid ALLOWED FAST message for piece {1}.'.format(self, piece_index))
      self.pieces_allowed_fast.add(piece_index)
   
   # standard python operator overloading
   def __repr__(self):
      return '<{0} to {1} at {2} sent: {3} received: {4}>'.format(
            self.__class__.__name__, self.btpeer, id(self),
            self.content_bytes_out, self.content_bytes_in)
   
   def traffic_delta_cmp(self, other):
      diff_self = self.content_bytes_in #- self.content_bytes_out
      diff_other = other.content_bytes_in #- other.content_bytes_out
      if (diff_self != diff_other):
         if (diff_self < diff_other):
            return 1
         return -1
      return 0
   
   def __eq__(self, other):
      return (self is other)
   def __ne__(self, other):
      return not (self is other)
   def __lt__(self, other):
      td = self.traffic_delta_cmp(other)
      return ((td == -1) or ((td == 0) and (id(self) < id(other))))
   def __le__(self, other):
      td = self.traffic_delta_cmp(other)
      return ((td == -1) or ((td == 0) and (id(self) <= id(other))))
   def __gt__(self, other):
      td = self.traffic_delta_cmp(other)
      return ((td == 1) or ((td == 0) and (id(self) > id(other))))
   def __gt__(self, other):
      td = self.traffic_delta_cmp(other)
      return ((td == 1) or ((td == 0) and (id(self) >= id(other))))

   def __hash__(self):
      return hash(id(self))
   
   input_handlers = {
      MSG_ID_CHOKE:input_process_choke,
      MSG_ID_UNCHOKE:input_process_unchoke,
      MSG_ID_INTERESTED:input_process_interested,
      MSG_ID_NOTINTERESTED:input_process_notinterested,
      MSG_ID_HAVE:input_process_have,
      MSG_ID_BITFIELD:input_process_bitfield,
      MSG_ID_REQUEST:input_process_request,
      MSG_ID_PIECE:input_process_piece,
      MSG_ID_CANCEL:input_process_cancel,
      MSG_ID_SUGGEST_PIECE:input_process_suggest_piece,
      MSG_ID_HAVE_ALL:input_process_have_all,
      MSG_ID_HAVE_NONE:input_process_have_none,
      MSG_ID_REJECT_REQUEST:input_process_reject_request,
      MSG_ID_ALLOWED_FAST:input_process_allowed_fast
   }


class BTorrentHandler:
   """Manage downloading/seeding a single BT file"""
   block_length = 16*1024
   logger = logging.getLogger('BTorrentHandler')
   log = logger.log
   maintenance_interval = MAINTENANCE_INTERVAL
   # Timeslice in seconds we are allowed to block for. This is actually rather
   # fuzzy; we will only defer further processing if at least this amount of
   # time has passed since being called when we explicitly check for it.
   # If in doubt, set it slightly lower than you are willing to wait.
   block_time = 0.05
   
   optimistic_unchoke_rate = 0.2
   
   # defaults for bandwidth limiter instantiation, if not provided by user
   bwm_cycle_length = 1
   bwm_history_length = 1000
   # peer connection limits for a single torrent
   peer_connection_count_target = 45 # Don't open any more than this
   peer_connection_count_limit = 60 # Don't accept any more than this
   
   # time to wait until next announce on tracker error.
   announce_retry_interval = 100
   # time to wait after successful announce if the tracker doesn't provide
   # a suggestion
   announce_default_interval = 1800
   # Minimum announce interval; overrides any suggestion by tracker
   announce_min_interval = 50
   
   init_names = ('metainfo', 'peer_id', 'interval_override',
      'peer_connection_count_target', 'peer_connections_start_delay',
      'basename_use', 'piecemask', 'piecemask_validate', 'bli_cls', 'bmo_cls', 
      'content_bytes_in', 'content_bytes_out', 'ts_downloading_start',
      'ts_downloading_finish', 'active', 'bytes_left', 'download_complete',
      'announce_key')
   
   timer_attributes = ('timer_announce', 'timer_maintenance', 
      'timer_peer_connections_start', 'timer_init')
   
   def __init__(self, **kwargs):
      self.init_args = kwargs.copy()
      self.init(**kwargs)
   
   def init(self, metainfo, peer_id, interval_override=None,
                peer_connection_count_target=50,
                peer_connections_start_delay=300, basename_use=True,
                piecemask=None, piecemask_validate=True,
                bli_cls=NullBandwidthLimiter, bmo_cls=NullBandwidthLimiter,
                downloader_count=4, content_bytes_out=0, content_bytes_in=0,
                ts_downloading_start=None, ts_downloading_finish=None,
                active=False, bytes_left=None, download_complete=False,
                announce_key=None, port=None):
      
      self.event_dispatcher = None
      if (announce_key is None):
         announce_key = sha1('{0}{1}{2}'.format(time.time(), os.getpid(), random.random()).encode('ascii')).digest()
      self.announce_key = announce_key

      self.active = active # are we currently trying to transfer data?
      self.metainfo = metainfo
      self.port = None
      self.peer_id = peer_id
      self.interval_override = interval_override
      self.peer_connection_count_target = peer_connection_count_target
      self.peer_connections_start_delay = peer_connections_start_delay
      self.basename_use = basename_use
      self.piecemask = piecemask
      self.piecemask_validate = piecemask_validate
      self.pieces_have_count = 0
      
      self.endgame_mode = False
      self.download_complete = download_complete
      self.ts_downloading_start = (None or datetime.datetime.now())
      self.ts_downloading_finish = ts_downloading_finish
      self.bt_disk_io = None
      self.peer_connections = set()
      self.peers_known = set()
      self.bytes_left = bytes_left
      self.trackerid = None
      self.tr = None
      self.tier = 0
      self.tier_index = 0
      self.tracker_valid = False
      
      for name in self.timer_attributes:
         setattr(self, name, None)
      
      self.piece_count = len(self.metainfo.piece_hashes)
      self.init_started = False
      self.init_done = False
      self.uploading = True
      self.downloader_count = downloader_count
      self.optimistic_unchoke_count = int(math.ceil(downloader_count*self.optimistic_unchoke_rate))
      self.downloaders = []
      self.downloaders_index = 0
      self.senders = set()
      # generic traffic statistics; note that these only refer to finished connections
      self.content_bytes_in = content_bytes_in
      self.content_bytes_out = content_bytes_out

      # For pieces we don't have entirely yet, this saves which of their blocks
      # we have. For pieces we *do* already have completed, the mask field
      # value is undefined
      self.blockmask = BlockMask(self.piece_count, self.piece_length_get(False), self.piece_length_get(True), self.block_length)
      # Undefined for blocks we already have. For blocks we don't, saves
      # whether we are expecting to be sent that block by a peer
      self.blockmask_req = BlockMask(self.piece_count, self.piece_length_get(False), self.piece_length_get(True), self.block_length)
      
      self.pieces_availability = [0]*self.piece_count
      self.pieces_preference = ()
      self.bli_cls = bli_cls
      self.bmo_cls = bmo_cls
      self.bandwidth_logger_in = self.bandwidth_logger_out = \
         self.bandwidth_manager_out = None

      
   def data_transfers_start(self):
      """Start transferring data"""
      if (self.active):
         raise BTCStateError('{0} is already active.'.format(self))
      
      self.active = True
      if ((not self.timer_announce) and self.init_done):
         self.client_announce_tracker()
   
   def data_transfers_stop(self):
      """Stop transferring data and close all active connections"""
      if (not self.active):
         raise BTCStateError('{0} is already inactive.'.format(self))
      self.active = False
      self.client_announce_tracker(event='stopped', event_force=True)
      for conn in self.peer_connections.copy():
         conn.close()
      
   def state_get(self):
      """Summarize internal state using nested dicts, lists, ints and strings"""
      return BTorrentHandlerMirror.state_get_from_original(self)
      rv = {}
      
   def io_start(self, event_dispatcher, basepath, port):
      """Start IO init sequence: open files on disk, and start piecemask
         validation (if any)"""
      assert not (self.init_started)
      assert not (self.init_done)
      self.init_started = True
      self.event_dispatcher = event_dispatcher
      self.port = port
      
      self.bt_disk_io = BTDiskIO(self.event_dispatcher, self.metainfo, basepath,
         basename_use=self.basename_use)
      if (self.piecemask):
         assert(self.piecemask.bitlen) == len(self.metainfo.piece_hashes)
      else:
         self.piecemask = BitMask(bitlen=self.piece_count)

      self.bandwidth_logger_in = self.bli_cls(self.event_dispatcher,
         cycle_length=self.bwm_cycle_length,
         history_length=self.bwm_history_length)
      self.bandwidth_logger_out = self.bandwidth_manager_out = \
         self.bmo_cls(self.event_dispatcher, cycle_length=self.bwm_cycle_length,
         history_length=self.bwm_history_length)
      
      if (self.piecemask_validate):
         self.piecemask_validation_perform()
      else:
         self.pieces_have_count = self.piecemask.bits_set_count()
         self.download_complete = (self.pieces_have_count == self.piece_count)
         self.io_init_finish()
   
   def io_init_finish(self):
      """Finish IO initialization sequence.
         Should be called after piecemask validation (if any) is completed"""
      if (self.active):
         self.client_announce_tracker()
      self.persistence_timers_set()
      self.init_done = True
   
   def bl_close(self):
      """Stop and forget bandwidth loggers and managers"""
      for bl in (self.bandwidth_logger_in, self.bandwidth_logger_out, self.bandwidth_manager_out):
         if (bl is None):
            continue
         bl.close()
      self.bandwidth_logger_in = None
      self.bandwidth_logger_out = None
      self.bandwidth_manager_out = None

   def timers_clear(self):
      """Stop timers associated with this instance and clear timer attributes"""
      for name in self.timer_attributes:
         timer = getattr(self, name)
         if not (timer is None):
            timer.cancel()
         setattr(self, name, None)
      
   def io_stop(self):
      """Abort running timers and close files on disk on an inactive bth"""
      if (self.active):
         raise BTCStateError('{0} is currently active'.format(self))
      
      self.init_done = False
      self.bt_disk_io.close()
      self.bt_disk_io = None
      self.timers_clear()
      
      self.bl_close()
   
   def __getstate__(self):
      rv = {}
      for name in self.init_names:
         if (hasattr(self, name)):
            rv[name] = getattr(self, name)
      return rv
   
   def __setstate__(self, state):
      kwargs = state
      self.__init__(**kwargs)
   
   def piecemask_validation_perform(self, req=None):
      """Check whether allegedly present data hashes to the correct value"""
      piece_len = self.piece_length_get(False)
      if (req is None):
         self.bytes_left = self.metainfo.length_total
         self.log(22, '{0} is starting validation of previously downloaded data.'.format(self))
         blen = 1048576
         blen -= (blen % piece_len)
         if (not blen):
            blen = piece_len
         
         buf = bytearray(min(blen, self.metainfo.length_total))
         req = self.bt_disk_io.async_readinto(((0,buf),), self.piecemask_validation_perform)
         req.buf = buf
         req.blen = blen
         req.index = 0
         return
      
      buf = memoryview(req.buf)
      i = req.index
      o = 0
      while (len(buf) > o):
         m = buf[o:o+piece_len]
         if (self.piecemask.bit_get(i)):
            h = sha1(m).digest()
            if (self.metainfo.piece_hashes[i] != h):
               # We don't explicitly check for failed reads; the somewhat nicer
               # log messages aren't worth the additional complexity.
               self.log(25, 'Piece {0} of {1} was supposed to be present, but hd'
                   'content (if present) hashed to {2!a}, while expected hash was'
                   '{3!a}.'.format(i, self, h, self.metainfo.piece_hashes[i]))
            else:
               self.pieces_have_count += 1
         o += len(m)
         i += 1
      
      self.bytes_left -= len(buf)
      
      if (self.bytes_left <= 0):
         self.log(22, '{0} has finished validation of previously downloaded data.'.format(self))
         if ((self.piecemask.bitlen > 0) and self.piecemask.bit_get(i - 1)):
            # Last piece was valid. Correct self.bytes_left back up
            self.bytes_left += (self.metainfo.piece_length - self.piece_length_get(True))
         assert (self.bytes_left >= 0)
         
         self.io_init_finish()
         self.download_complete = (self.pieces_have_count == self.piece_count)
         return
      
      buf = bytearray(min(req.blen, self.bytes_left))
      
      req_new = self.bt_disk_io.async_readinto(((piece_len*i,buf),), self.piecemask_validation_perform)
      req_new.buf = buf
      req_new.blen = req.blen
      req_new.index = i
      
   def piece_length_get(self, piece_last=False):
      """Return piece_length (in bytes) for this torrent"""
      if (piece_last):
         return (self.metainfo.length_total - ((self.piece_count - 1)*self.metainfo.piece_length))
      return self.metainfo.piece_length
   
   def query_piece_wanted(self, index):
      """Return whether piece <index> has any blocks that are neither already downloaded nor currently pending"""
      if (self.piecemask.bit_get(index)):
         return False
      
      if (index == (self.piece_count - 1)):
         subrange = range(self.blockmask.blocks_per_piece_last)
      else:
         subrange = range(self.blockmask.blocks_per_piece)
      
      for sub_index in subrange:
         if ((not self.blockmask.block_have_get(index, sub_index)) and 
             ((not self.blockmask_req.block_have_get(index, sub_index))
             or self.endgame_mode)):
            return True
      return False
   
   def pieces_availability_adjust_mask(self, piecemask, adjustment):
      """Add <adjustment> to the availability metric of every piece in <piecemask>"""
      assert (piecemask.bitlen == self.piecemask.bitlen)
      if (self.download_complete):
         # Who cares?
         return
      for i in range(len(piecemask)):
         byteval = piecemask[i]
         for j in range(7,-1,-1):
            k = i*8 + j
            if (byteval & (1 << k)):
               self.pieces_availability[k] += adjustment

   def piece_availability_adjust(self, index, adjustment=1):
      """Add <adjustment> to the availability of piece with index <index>"""
      self.pieces_availability[index] += adjustment
      
   def pieces_preference_update(self):
      """Update cached piece preference when downloading new pieces"""
      # FIXME: using strict availability as a metric is suboptimal in certain
      # respects. There should probably be a significant bias for
      # finishing mostly complete files.
      
      pieces_classes = {}
      for index in range(len(self.pieces_availability)):
         if (self.piecemask.bit_get(index)):
            continue
         
         availability = self.pieces_availability[index]
         if not (availability in pieces_classes):
            pieces_classes[availability] = []
         pieces_classes[availability].append(index)
      
      for val in pieces_classes.values():
         random.shuffle(val)
      
      keys = sorted(pieces_classes.keys())
      result = []
      for key in keys:
         result.extend(pieces_classes[key])
      self.pieces_preference = result
   
   def pieces_wanted_get(self, piecemask, count):
      """Return (at most <count>) pieces we want that are part of <piecemask>"""
      if (self.download_complete):
         # For performance reasons, don't do the whole routine
         return deque()
      
      self.pieces_preference_update() # FIXME: this should probably not be called every time; it's somewhat expensive

      pieces_found = 0
      pieces = deque()
      for index in self.pieces_preference:
         if (self.query_piece_wanted(index) and 
            piecemask.bit_get(index)):
            pieces_found += 1
            pieces.append(index)
            if (pieces_found >= count):
               break
      return pieces
   
   def block_process(self, conn, piece_index, start, length, stream, duplicate_ignore=False):
      """Save a received block of data
         piece_index: piece of torrent
         start: byte index of start of block inside of piece
         length: length of block in bytes
         stream: file-like object containing block, and seeked to its beginning"""
      
      if ((start % self.block_length) != 0):
         raise BTProtocolError("Got block: p{0}, s{1}, l{2}; the start index isn't an integer multiple of block length {3}.".format(piece_index, start, length, self.block_length))
      
      piece_length = self.piece_length_get(piece_index == (self.piece_count - 1))
      
      if not ((length == self.block_length) or (((piece_length - start) == length) and (length < self.block_length))):
         raise BTProtocolError("Got block: p{0}, s{1}, l{2}; our standard block length is {3}, piece length is {4}. The length of the received block is bogus.".format(piece_index, start, length, self.block_length, piece_length))
      
      block_index = start//self.block_length
      
      if (self.blockmask.block_have_get(piece_index, block_index)):
         if (self.endgame_mode or duplicate_ignore):
            return False
         else:
            raise BTClientError("I already have piece {0}, block {1} for connection {2}, and am not in endgame mode.".format(piece_index, block_index, self))
      
      req = self.bt_disk_io.async_write(((piece_index*self.piece_length_get() + start,
         stream.read(length)),), self._block_write_process)
      req.bth_piece = piece_index
      req.bth_block = block_index
      req.bth_length = length
      
   def _block_write_process(self, req):
      """Process write finish"""
      piece_index = req.bth_piece
      block_index = req.bth_block
      block_length = req.bth_length
      if (self.blockmask.block_have_get(piece_index, block_index)):
         # Writing race condition
         self.log(30, '{0} not writing p{1} s{2} l{3} because we already have'
            'it.'.format(self, piece_index, start, block_length))
         return
      
      self.blockmask.block_have_set(piece_index, block_index, True)
      
      if (self.blockmask.piece_have_completely_get(piece_index)):
         # This is the last block of this piece we were missing. Do hash verification.
         buf = bytearray(self.piece_length_get(piece_index == (self.piece_count - 1)))
         req_new = self.bt_disk_io.async_read(((piece_index*self.piece_length_get(),
            buf),), self._piece_verify)
         req_new.buf = buf
         req_neq.bth_index = piece_index
   
   def _piece_verify(self, req):
      """Verify hash of potentially completed piece"""
      piece_index = req.bth_index
      
      mi_piece_hash = self.metainfo.piece_hashes[piece_index]
      di_piece_hash = sha1(req.buf).digest()
      
      if (di_piece_hash != mi_piece_hash):
         # Unfortunately we don't know which block(s) were bad, so we can't
         # do client banning based on this.
         self.log(35, 'Piece {0} of torrent {1} invalid; got data with hash {2!a}, expected {3!a}. Discarding data.'.format(piece_index, self, di_piece_hash, mi_piece_hash))
         
         if (piece_index == (self.piece_count - 1)):
            subrange = range(self.blockmask.blocks_per_piece_last)
         else:
            subrange = range(self.blockmask.blocks_per_piece)
         
         for block_index in subrange:
            self.blockmask.block_have_set(piece_index, block_index, False)
         return
      
      self.log(14, 'Finished piece {0} of torrent {1}. Hash {2!a} confirmed.'.format(piece_index, self, mi_piece_hash))
      self.piecemask.bit_set(piece_index, True)
      self.pieces_have_count += 1
      self.bytes_left -= piece_length
      assert (self.bytes_left >= 0)
      for conn in self.peer_connections.copy():
         conn.piece_have_new(piece_index)
      
      if (self.pieces_have_count == self.piecemask.bitlen):
         self.log(28, 'Completed torrent {0}; {1} bytes in {2} pieces.'.format(self, self.metainfo.length_total, self.piecemask.bitlen))
         self.download_complete = True
         self.ts_downloading_finish = datetime.datetime.now()
         for conn in self.peer_connections.copy():
            conn.downloading = False


   def block_request_process(self, conn):
      """Process block request on one of our connections"""
      if (conn.p_choked):
         raise BTCStateError('{0!a} received block request while peer is being choked.'.format(conn))
      if (not conn.p_interest):
         self.log(30, '{0} is requesting blocks without having declared interest. Ignoring.'.format(conn))
         return
      if (not conn.uploading):
         self.downloaders_update(discard_optimistic_unchokes=False)


   def downloaders_update(self, discard_optimistic_unchokes=True):
      """Update list of connections we are sending content blocks out over"""
      if not ((self.uploading) or (self.downloader_count < 1)):
         return
      peer_connections_all = [conn for conn in self.peer_connections]
      peer_connections_all.sort()
      peer_connections = [conn for conn in peer_connections_all if conn.p_interest]
      senders = []
      
      rate_downloader_count = self.downloader_count - self.optimistic_unchoke_count
      
      if (peer_connections == []):
         senders = peer_connections_all
      else:
         if (len(peer_connections) > rate_downloader_count):
            ref_peer = peer_connections[rate_downloader_count-1]
         else:
            ref_peer = peer_connections[-1]
         
         for conn in peer_connections_all:
            if (conn.traffic_delta_cmp(ref_peer) >= 0):
               break
            senders.append(conn)
      
      if (len(peer_connections) <= self.downloader_count):
         downloaders = peer_connections
      else:
         downloaders = peer_connections[:rate_downloader_count]
         peer_connections = peer_connections[rate_downloader_count:]
         
         if not (discard_optimistic_unchokes):
            # Append currently optimistically unchoked connections to new
            # downloader list
            for conn in self.downloaders[-self.optimistic_unchoke_count:]:
               if ((conn in self.peer_connections) and (conn.p_interest)):
                  peer_connections.append(conn)
         
         while ((peer_connections != []) and (len(downloaders) < self.downloader_count)):
            index = random.randint(0, len(peer_connections) - 1)
            downloaders.append(peer_connections.pop(index))
      
      for conn in self.downloaders:
         if not (conn in downloaders):
            self.log(20, 'Calling uploading_stop() on {0}.'.format(conn))
            conn.uploading_stop(not (conn in senders))
      
      for conn in downloaders:
         if not (conn in self.downloaders):
            conn.uploading_start()

      # Tell non-interested high-upload peers that we'd be willing to send them stuff
      for conn in senders:
         if (conn.p_choked):
            conn.choke_send(False)
      
      for conn in self.senders:
         if ((not conn in senders) and (not conn in downloaders)):
            conn.uploading = True
            conn.uploading_stop(True)

      self.senders = senders
      self.downloaders = downloaders
      
      downloader_count = len(downloaders)
      
      # Count of downloaders may have fallen
      if (downloader_count > 0):
         self.downloaders_index %= downloader_count
      else:
         self.downloaders_index = 0
   
   def timer_announce_set(self, interval):
      """Set timer for a new announce request in <interval>"""
      if (self.timer_announce):
         try:
            self.timer_announce.cancel()
         except ValueError:
            pass
      self.timer_announce = self.event_dispatcher.set_timer(interval, self.client_announce_tracker, parent=self)
   
   def persistence_timers_set(self):
      """Set persistent timers used by this instance"""
      if (self.timer_peer_connections_start):
         self.timer_peer_connections_start.cancel()
      self.timer_peer_connections_start = self.event_dispatcher.set_timer(self.peer_connections_start_delay, self.peer_connections_start, parent=self, persist=True)
      if (self.timer_maintenance):
         self.timer_maintenance.cancel()
      self.timer_maintenance = self.event_dispatcher.set_timer(self.maintenance_interval, self.maintenance_perform, parent=self, persist=True, align=True)
      
   def maintenance_perform(self):
      """Perform various maintenance tasks"""
      if (self.piecemask.bitlen - self.pieces_have_count < 10):
         self.endgame_mode = True
      
      for conn in self.peer_connections.copy():
         conn.maintenance_perform()
      
      self.downloaders_update()
      for conn in self.downloaders:
         conn.read_blocks(force=True)
      
   def peer_connections_start(self):
      """Connect to more peers if we don't have sufficient connections yet."""
      if (not self.active):
         return
      
      self.log(15, 'BTH {0} is starting connect sequence.'.format(self))
      peers_connected_count = len(self.peer_connections)
      peers_available_count = len(self.peers_known)
      
      peers_wanted_count = self.peer_connection_count_target - peers_connected_count
      if (peers_wanted_count <= 0):
         return
      
      peers_connected = set([conn.btpeer for conn in self.peer_connections])
      peers_targeted = list(self.peers_known - peers_connected)
      random.shuffle(peers_targeted)
      
      peers_wanted_count = min(peers_wanted_count, len(peers_targeted))
      
      for i in range(peers_wanted_count):
         if (len(self.peer_connections) >= self.peer_connection_count_target):
            break
         peer = peers_targeted[i]
         self.log(15, 'BTH {0} is opening connection to peer {1!a}.'.format(self, peer))
         conn = BTClientConnection.peer_connect(self.event_dispatcher,peer.address_get())
         conn.info_hash = self.metainfo.info_hash
         conn.bandwidth_logger_in = self.bandwidth_logger_in
         self.connection_add(conn)
         conn.handshake_send()
      
   def peer_connection_error_process(self, connection):
      """Process a serious error from a peer we connected (or tried to) to."""
      if (connection.btpeer in self.peers_known):
         self.log(12, 'Removing peer {0!a} from known list of bth {1} as a result of error condition.'.format(connection.btpeer, self))
         self.peers_known.remove(connection.btpeer)
      
   def tracker_conn_response_process(self, tr, data):
      """Process data from successful announce"""
      self.tr = None
      self.timer_announce = None
      an_urls_tier = self.metainfo.announce_urls[self.tier]
      an_url = an_urls_tier[self.tier_index]
      # announce target reordering
      self.log(10, 'TrackerRequest {0} from {1!a} got response; reordering announce urls.'.format(tr,an_url))
      an_urls_tier.remove(an_url)
      an_urls_tier.insert(0, an_url)
      self.tier_index = 0
      self.tracker_valid = True
      
      self.log(10, 'Processing response {0!a}.'.format(data))
      if (b'min interval' in data):
         delay_min = int(data[b'min interval'])
      else:
         delay_min = 0
      
      if (b'tracker id' in data):
         self.trackerid = data[b'tracker id']
      
      for peer in data[b'peers']:
         self.peers_known.add(peer)
      
      if (self.interval_override):
         interval = max(self.interval_override, delay_min)
      elif (b'interval' in data):
         interval = int(data[b'interval'])
         if (interval < self.announce_min_interval):
            self.log(30, 'TrackerRequest {0} from {1!a} got announce interval {2}; bumping it to {3}.'.format(tr, an_url, interval, self.announce_min_interval))
            interval = self.announce_min_interval
      else:
         interval = self.announce_default_interval
      
      if (self.active):
         self.timer_announce_set(interval)
         
         if (not self.peer_connections):
            self.peer_connections_start()
      
   def tracker_conn_error_process(self, tr):
      """Process an error occuring during announce procedure"""
      self.tr = None
      self.timer_announce = None
      if (self.tracker_valid):
         # Tracker used to be reachable, but not anymore.
         # Start at beginning of tier-structure.
         self.tracker_valid = False
         self.tier = 0
         self.tier_index = 0

      an_urls = self.metainfo.announce_urls
      if (len(an_urls[self.tier]) > (self.tier_index + 1)):
         # Should we discard the trackerid here as well?
         # The specs aren't particularly clear about this.
         self.tier_index += 1
      elif (len(an_urls) > (self.tier + 1)):
         self.trackerid = None
         self.tier += 1
         self.tier_index = 0
      else:
         self.tier = 0
         self.tier_index = 0
      
      self.log(25, 'TrackerRequest {0} failed.'.format(tr))
      if (self.active):
         self.timer_announce_set(self.announce_retry_interval)
      
   def announce_url_get(self):
      """Get announce url of currently preferred tracker"""
      return self.metainfo.announce_urls[self.tier][self.tier_index]
      
   def client_announce_tracker(self, event=None, event_force=False):
      """Announce ourselves to currently preferred tracker"""
      if (self.tr):
         self.tr.close()
      
      if (self.timer_announce):
         try:
            self.timer_announce.cancel()
         except ValueError:
            pass
         self.timer_announce = None
      elif (not event_force):
         event = b'started'
      
      self.tr = tracker_request_build(self.announce_url_get(), self.metainfo.info_hash,
            self.peer_id, self.port, self.content_bytes_out,
            self.content_bytes_in, self.bytes_left, trackerid=self.trackerid,
            compact=True, key=self.announce_key, event=event)
      self.tr.request_send(self.event_dispatcher,
         self.tracker_conn_response_process, self.tracker_conn_error_process)

   def connection_add(self, conn):
      """Add an open client connection to this handler."""
      if (conn.info_hash != self.metainfo.info_hash):
         raise InsanityError('Connection passed to {0!a}.connection_add() has info_hash {1!a}, expected {2!a}.'.format(self, conn.info_hash, self.metainfo.info_hash))
      if not (self.init_done):
         raise HandlerNotReadyError('{0} has not finished initialization.'.format(self))
      if (len(self.peer_connections) >= self.peer_connection_count_limit):
         raise ResourceLimitError('{0} is already managing {1} connections; my limit is {2}.'.format(self, len(self.peer_connections), self.peer_connection_count_limit))
      if (not self.active):
         raise BTCStateError('{0} is not active.'.format(self))
      
      self.peer_connections.add(conn)
      conn.downloading = (self.init_done and (not self.download_complete))
      conn.init_finish(self)
      
   def connection_remove(self, conn):
      """Forget about a tracked connection"""
      self.log(20, 'Removing conn {0}.'.format(conn))
      self.peer_connections.remove(conn)
      self.content_bytes_in += conn.content_bytes_in
      self.content_bytes_out += conn.content_bytes_out
      if (conn in self.senders):
         self.senders.remove(conn)
      if (conn in self.downloaders):
         self.downloaders.remove(conn)
         if (self.downloaders):
            self.downloaders_index %= len(self.downloaders)
         else:
            self.downloaders_index = 0
         self.downloaders_update(discard_optimistic_unchokes=False)
      
   def close(self):
      if (self.active):
         self.data_transfers_stop()
      self.io_stop()

   def target_basename_get(self):
      """Get base filename for this BTH"""
      if (self.metainfo.basename):
         return self.metainfo.basename
      if (self.metainfo.files):
         return self.metainfo.files[0].path
      return None

   def __repr__(self):
      return '<{0} id: {1} info_hash: {2!a} basefilename: {3!a} active: {4} ' \
         'complete: {5}>'.format(self.__class__.__name__, id(self),
         self.metainfo.info_hash, self.target_basename_get(), self.active,
         self.download_complete)


class BTClient:
   """Manage a Bt client socket, and dispatch identified connections on tracked torrents to specific torrent classes"""
   peer_id = peer_id_generate()
   logger = logging.getLogger('BTClient')
   log = logger.log
   maintenance_interval = MAINTENANCE_INTERVAL
   def __init__(self, bth_archiver=None, *args):
      self.event_dispatcher = None
      self.torrents = {}
      self.torrent_infohashes = []
      self.connections_uk = set()
      self.server = None
      self.pickler = None
      self.el_pickle_shutdown = None
      self.timer_pickle = None
      self.timer_maintenance = None
      self.bandwidth_logger_in = None
      self.em_bth_add = EventMultiplexer(self)
      self.em_bth_remove = EventMultiplexer(self)
      self.bt_stats_tracker = BTStatsTracker()
      self.basepath = None
      
      # config dummy values
      self.port = None
      self.host = None
      self.pickle_interval = None
      self.backlog = None
      self.bwm_cycle_length = None
      self.bwm_history_length = None
      self.bth_archiver = bth_archiver
   
   def torrent_infohashes_update(self):
      """Update list of torrent infohashes"""
      self.torrent_infohashes = sorted(self.torrents.keys())
   
   def state_get(self):
      """Summarize internal state using nested dicts, lists, ints and strings"""
      return BTClientMirror.state_get_from_original(self)
   
   def connections_start(self, event_dispatcher, btc_config):
      """Open server socket and call io_start() on all inactive BTHs"""
      assert (self.server is None)
      btc_config.config_use(self)
      
      self.data_basepath = btc_config.data_basepath
      self.event_dispatcher = event_dispatcher
      self.bandwidth_logger_in = NullBandwidthLimiter(self.event_dispatcher,
         cycle_length=self.bwm_cycle_length, 
         history_length=self.bwm_history_length)
      
      self.server = AsyncSockServer(self.event_dispatcher,
         (self.host, self.port), backlog=self.backlog)
      self.server.connect_process = self.client_connection_handle
      
      self.timer_maintenace = self.event_dispatcher.set_timer(
         self.maintenance_interval, self.maintenance_perform, parent=self,
         persist=True)
      
      for bth in self.torrents.values():
         if not (bth.init_started):
            bth.io_start(self.event_dispatcher, self.data_basepath, self.port)
   
   def bths_reannounce_tracker(self):
      """Tell each active BTH managed by this instance to send an announce to their tracker"""
      for bth in self.torrents.values():
         if (bth.active and bth.init_done):
            bth.client_announce_tracker()
   
   def pickling_shedule(self, pickler):
      """Start pickling to stream at regular intervals and program shutdown"""
      self.pickler = pickler
      if not (self.el_pickle_shutdown):
         self.el_pickle_shutdown = self.event_dispatcher.em_shutdown.new_listener(self.pickle_perform)
      if (self.timer_pickle):
         self.timer_pickle.cancel()
      self.timer_pickle = self.event_dispatcher.set_timer(self.pickle_interval, self.pickle_perform, parent=self, persist=True)
   
   def maintenance_perform(self):
      """Call maintenance_perform() on unknown connections"""
      for conn in self.connections_uk.copy():
         conn.maintenance_perform()
   
   def connection_remove(self, conn):
      """Process closing of a uk connection."""
      self.connections_uk.remove(conn)
   
   def client_connection_handle(self, sock, addrinfo):
      """Handle newly accepted connection on server socket"""
      self.log(15, 'BTClient {0} accepting connection from {1}.'.format(self, addrinfo))
      conn = BTClientConnection(self.event_dispatcher, sock)
      conn.handshake_callback = self.client_connection_handle_handshake
      conn.btpeer = BTPeer(addrinfo[0], addrinfo[1], None)
      conn.bandwidth_logger_in = self.bandwidth_logger_in
      conn.btc = self
      self.connections_uk.add(conn)

   def client_connection_handle_handshake(self, conn):
      """Handle handshake from connection not yet associated with torrent"""
      if (conn.info_hash) in self.torrents:
         self.connections_uk.remove(conn)
         conn.btc = None
         self.torrents[conn.info_hash].connection_add(conn)

      else:
         raise UnknownTorrentError("Not tracking any torrents with info_hash {0!a}.".format(conn.info_hash))

   def torrent_add(self, metainfo, active=True, *bth_args, **bth_kwargs):
      """Instantiate BTorrentHandler and register and return created BTH"""
      if (metainfo.info_hash) in self.torrents:
         raise DupeError("I'm already tracking torrent {0} with same info_hash {1!a} as in specified metainfo.".format(self, metainfo.info_hash))
      bth = BTorrentHandler(metainfo=metainfo, port=self.port, active=active, *bth_args, **bth_kwargs)
      self.torrents[metainfo.info_hash] = bth
      self.torrent_infohashes_update()
      self.em_bth_add(self, metainfo.info_hash)
      if not (self.event_dispatcher is None):
         bth.io_start(self.event_dispatcher, self.data_basepath, self.port)
      
      return bth

   def torrent_drop(self, info_hash):
      """Drop and return BTH with specified info_hash"""
      if not (info_hash in self.torrents):
         raise ValueError('Not tracking torrent with info_hash {0!a}.'.format(info_hash))
      bth = self.torrents[info_hash]
      bth.close()
      self.bth_archiver.bth_archive(bth)
      self.bt_stats_tracker.bth_process(bth)
      del(self.torrents[info_hash])
      self.torrent_infohashes_update()
      return bth

   def torrent_start(self, info_hash):
      """Stop transferring data for specified torrent and close active connections"""
      self.torrents[info_hash].data_transfers_start()
      
   def torrent_stop(self, info_hash):
      """Register to tracker of specified torrent and start transferring data"""
      self.torrents[info_hash].data_transfers_stop()

   def torrent_active_get(self, info_hash):
      """Return whether specified BTH is active"""
      return bool(self.torrents[info_hash].active)

   def mse_hash2_resolve(self, conn, hash2_val):
      """Determine which of our info hashes, if any, are usable skeys for specified connection and MSE hash2 value"""
      # The protocol doesn't leave us much choice here. Do an exhaustive search
      # over all of our torrents. This is unnecessarily wasteful of cpu-time,
      # but the only way to efficiently avoid it would be to use a separate 
      # listening socket for each of our active torrents.
      for info_hash in self.torrents.keys():
         if (conn.mse_hash2_compute(info_hash) == hash2_val):
            self.log(14, 'Successfully associated connection {0!a} with info_hash {1!a} based on MSE hashes.'.format(conn, info_hash))
            return info_hash
      
      raise UnknownTorrentError("Didn't find valid skey for hash2 value {0!a} on BT connection {1!a}.".format(hash2_val, conn))

   def pickle_perform(self):
      """Seek picklestream to position 0, and dump a serialization of this
         instance to it"""
      for bth in self.torrents.values():
         if (bth.piecemask_validate and bth.init_done):
            bth.piecemask_validate = False #FIXME: should be done cleanly by the time liasis enters production
      
      self.pickler(self)

   def __getstate__(self):
      return {'torrents': self.torrents, 'bt_stats_tracker': self.bt_stats_tracker}
   
   def __setstate__(self, state):
      self.__init__()
      self.torrents = state['torrents']
      self.bt_stats_tracker = state['bt_stats_tracker']
      self.torrent_infohashes_update()

   def __repr__(self):
      return '<{0} listen: ({1!a},{2}) id: {3}>'.format(self.__class__.__name__, self.host, self.port, id(self))

   def close(self):
      self.event_dispatcher = None
      if (self.server):
         self.server.close()
      self.server = None
      for conn in self.connections_uk:
         conn.close()
      self.connections_uk = set()
      
      for bth in self.torrents.values():
         bth.close()
      self.torrents = {}
      self.torrent_infohashes_update()
      
      for timer in (self.timer_pickle, self.timer_maintenance):
         timer.cancel()
      
      self.el_pickle_shutdown.close()
      self.el_pickle_shutdown = None
      self.timer_pickle = None
      self.timer_maintenance = None
      
      self.em_bth_add.close()
      self.em_bth_remove.close()


class EABTClient(BTClient):
   """BT Client which aggregates events from managed BTHs
   
   The throughput-data for each BTH managed by this client will be sent as
   events through self.em_throughput at the end of each cycle.
   call arguments: (listener,) btc, downstream_data, upstream_data
   """
   def __init__(self, *args, **kwargs):
      BTClient.__init__(self, *args, **kwargs)
      self.__em_throughput = DSEventAggregator(0, parent=self)
      self.__em_throughput_listener = self.__em_throughput.new_listener(
         self.em_throughput_cycle_handle)
      self.em_throughput = EventMultiplexer(self)
   
   def __setstate__(self, *args, **kwargs):
      BTClient.__setstate__(self, *args, **kwargs)

   def em_throughput_cycle_handle(self):
      """Handle throughput event from self.__em_throughput"""
      if (self.em_throughput.listeners == []):
         # Nobody cares, let's save some cycles
         return
      
      downstream_data = []
      upstream_data = []
      
      for infohash in self.torrent_infohashes:
         bth = self.torrents[infohash]
         downstream_data.append(bth.bandwidth_logger_in[-1])
         upstream_data.append(bth.bandwidth_logger_out[-1])
      
      self.em_throughput(self, downstream_data, upstream_data)

   def connections_start(self, *args, **kwargs):
      """Open server socket and call io_start() on all inactive BTHs"""
      BTClient.connections_start(self, *args, **kwargs)
      self.__em_throughput.n = 0
      reg = self.__em_throughput.multiplexer_register
      for bth in self.torrents.values():
         reg(bth.bandwidth_logger_in.em_cycle)
         reg(bth.bandwidth_logger_out.em_cycle)
         self.__em_throughput.n += 2

   def torrent_add(self, *args, **kwargs):
      """Instantiate BTorrentHandler and register and return created BTH"""
      bth = BTClient.torrent_add(self, *args, **kwargs)
      
      self.__em_throughput.multiplexer_register(bth.bandwidth_logger_in.em_cycle)
      self.__em_throughput.multiplexer_register(bth.bandwidth_logger_out.em_cycle)
      self.__em_throughput.n += 2
      return bth
   
   def torrent_drop(self, info_hash, *args, **kwargs):
      """Remove BTH with specified info_hash"""
      bth = self.torrents[info_hash]
      #bli_ec = bth.bandwidth_logger_in.em_cycle
      #blo_ec = bth.bandwidth_logger_out.em_cycle
      
      BTClient.torrent_drop(self, info_hash, *args, **kwargs)
      
      self.__em_throughput.n -= 2
      #self.__em_throughput.multiplexer_unregister(bli_ec) # unneeded, done automatically on torrent close through close of multiplexers
      #self.__em_throughput.multiplexer_unregister(blo_ec) # ditto
      
   
   def close(self):
      self.em_throughput.close()
      self.__em_throughput.close()
      BTClient.close(self)

