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


# BT structures for talking to trackers, based on information from
# <http://www.bittorrent.org/protocol.html> and
# <http://wiki.theory.org/BitTorrentSpecification>

# FIXME: add options to limit allowed address families for this?

import logging
import http.client
import random
import socket
import struct
import urllib.request
from urllib.parse import quote

from gonium.hacks.asynchttpc import build_async_opener
from gonium.fdm import AsyncDataStream, AsyncPacketSock

from .benc_structures import py_from_benc_str, BTPeer
from .url_parsing import HTTPLikeURL


class TrackerRequestError(Exception):
   pass

class TrackerResponseError(Exception):
   pass


class TrackerRequest:
   logger = logging.getLogger('TrackerRequest')
   log = logger.log
   fields = ('info_hash', 'peer_id', 'port', 'uploaded', 'downloaded', 'left', 'compact', 'event', 'ip', 'numwant', 'trackerid', 'key')
   def __init__(self, announce_url, info_hash, peer_id, port, uploaded, downloaded, left, compact=True, event=None, ip=None, numwant=None, trackerid=None, key=None):
      if (isinstance(event,str)):
         # UDPTrackerRequest requires this to be bytes
         event = event.encode('ascii')
      for field in self.fields:
         setattr(self, field, locals()[field])
      self.announce_url = announce_url
      
   def address_get(self, default_port=None):
      """Determine (host, port) tuple."""
      url = HTTPLikeURL.build_from_urlstring(self.announce_url)
      port = url.port
      if (url.port is None):
         port = default_port
      
      return (url.host, port)


class HTTPTrackerRequest(TrackerRequest):
   proto = b'http'
   def __init__(self, *args, **kwargs):
      TrackerRequest.__init__(self, *args, **kwargs)
      self.connection = None
      self.od = build_async_opener()
      self.result_callback = None
      self.error_callback = None
      self.clean_up_active = False
      self.data = None
   
   def req_url_get(self):
      rlist = []
      for field in self.fields:
         val = getattr(self, field)
         if (val is None):
            continue
         if (isinstance(val,bool)):
            val = int(val)
         if not (isinstance(val, (bytes, bytearray, str))):
            val = str(val)
         
         rlist.append('='.join((field, quote(val, safe=b''))))
      
      return '?'.join((self.announce_url.decode('ascii'), '&'.join(rlist)))

   def request_build(self):
      # There's at least one tracker which doesn't seem to like
      # Python-urllib-2.4 UA strings. Besides, this is more informative.
      ul_req = urllib.request.Request(self.req_url_get(), None, {'User-Agent':'Liasis'})
      (got_exc, hcd) = self.od.open(ul_req, responses=())
      
      if not (got_exc):
         raise TrackerRequestError("http.client hack failed.")
      
      return hcd.req_string

   def conn_input_handle(self, data):
      self.data = data

   def conn_close_handle(self):
      """Handle closing of fd from our http connection: process data and pass result to callback"""
      if (self.clean_up_active):
         # Nothing to see here. Result is almost certainly incomplete
         return
      response_http = self.data
      if (response_http is None):
         self.log(30, 'Tracker request to {0!a} failed; received no data.'.format(self.announce_url), exc_info=False)
         self.error_callback(self)
         return
      try:
         (got_exc, urlo) = self.od.open(self.req_url_get(), responses=(bytes(response_http),))
         
         if (got_exc):
            raise TrackerResponseError('HTTP parsing failed; got followup request: {0!a}'.format(urlo,))
         
         response_text = urlo.read()
         response_data = py_from_benc_str(response_text)
         
         if (b'failure reason' in response_data):
            fr = response_data[b'failure reason']
            self.log(30, 'Got failure reason {0!a} from tracker {1!a}.'.format(fr, self.announce_url))
            raise TrackerResponseError('Tracker {0!a} returned failure reason {1!a}. Complete response data: {2!a}'.format(self.announce_url, fr, response_data))
         if (b'warning message' in response_data):
            wm = response_data[b'warning message']
            self.log(30, 'Got warning message {0!a} from tracker {1!a}.'.format(fr, self.announce_url))
         
         # FIXME: According to wiki.theory.org, 'peer id' entries from the tuples
         # can also be hostnames. This hasn't been observed in practice, but we
         # should catch it here and do some kind of asynchronous lookup if they are.
         response_data[b'peers'] = BTPeer.seq_build(response_data[b'peers'])
      except (Exception, http.client.HTTPException) as exc:
         self.error_callback(self)
         self.log(30, 'Tracker request to {0!a} failed. Resultstring: {1!a}. Error: {2!a} ({3!a})'.format(self.announce_url, bytes(response_http), exc, str(exc)), exc_info=False)
      else:
         self.result_callback(self, response_data)
         self.connection = None
         self.close()
   
   def request_send(self, event_dispatcher, result_callback, error_callback):
      """Open connection to announce url, open and send request"""
      if not (self.connection is None):
         raise TrackerRequestError("Request {0!a} is still pending.".format(self.connection))
      
      try:
         request_string = self.request_build()
      except urllib.request.URLError:
         self.log(30, 'Error building request for {0!a}:'.format(self.req_url_get()), exc_info=True)
         error_callback(self)
         return
      
      try:
         self.connection = AsyncDataStream.build_sock_connect(event_dispatcher,
            self.address_get(default_port=80))
      except socket.error:
         self.connection = None
         self.result_callback = None
         self.error_callback = None
         error_callback(self)
         return
      
      self.connection.process_input = self.conn_input_handle
      self.connection.process_close = self.conn_close_handle
      self.result_callback = result_callback
      self.error_callback = error_callback
      
      self.connection.send_bytes((request_string,))

   def close(self):
      self.clean_up_active = True
      if (self.connection):
         self.connection.close()
      self.connection = None
      self.callback_handler = None
      self.clean_up_active = False


# Implementation of protocol described on
# <http://home.mchsi.com/~bitbuddy/wsb/udp_tracker_protocol.html>
# Unfortunately, this protocol seems to be limited to ipv4.
# Fortunately, it doesn't appear to be widely used.
class UDPTrackerRequest(TrackerRequest):
   proto = b'udp'
   pm_in_init = '>llq'
   pm_in_announce = '>lllll'
   CONNECTION_ID_DEFAULT = 0x41727101980
   ACTION_CONNECT = 0
   ACTION_ANNOUNCE = 1
   ACTION_SCRAPE = 2
   ACTION_ERROR = 3
   EXT_AUTH = 1
   
   TIMEOUT = 50
   
   EVENT_MAP = {
      None:0,
      b'completed':1,
      b'started':2,
      b'stopped':3
   }
   
   def __init__(self, *args, **kwargs):
      TrackerRequest.__init__(self, *args, **kwargs)
      self.sock = None
      self.timeout_timer = None
      self.close()
   
   @staticmethod
   def tid_generate():
      """Return a random 32bit signed integer"""
      return random.randint(-1*2**31,2**31-1)
   
   def frame_build_init(self, tid=None):
      """Build and return frame for initiating session to tracker"""
      if (tid is None):
         tid = self.transaction_id
      return struct.pack('>qll', self.CONNECTION_ID_DEFAULT,
         self.ACTION_CONNECT, tid)
   
   def numwant_get(self):
      if (self.numwant is None):
         return -1
      return self.numwant
   
   def frame_build_announce(self, tid=None, ip_address=0, extensions=0):
      """Build and return announce frame"""
      if (tid is None):
         tid = self.transaction_id
      
      key = self.key
      if (key is None):
         key = ''
      key = key[-4:]
      return struct.pack('>qll20s20sqqqlL4slHH', self.connection_id,
         self.ACTION_ANNOUNCE, tid, self.info_hash, self.peer_id,
         self.downloaded, self.left, self.uploaded, self.EVENT_MAP[self.event],
         ip_address, key, self.numwant_get(), self.port, extensions)
    
   @staticmethod
   def frame_parsebody_init(data):
      """Parse init response fragment (packet minus initial 8 bytes) and return contents"""
      if (len(data) != 8):
         raise ValueError('Data {0!a} invalid; expected exactly 8 bytes.'.format(data,))
      return struct.unpack('>q', data)[0]
   
   def frame_parsebody_announce(self, data):
      """Parse announce response body (packet minus initial 8 bytes) and return contents"""
      if (len(data) < 12):
         raise ValueError('Data {0!a} invalid; expected at least 12 bytes.'.format(data,))
      if (((len(data) - 12) % 6) != 0):
         raise ValueError('Data {0!a} invalid; length {1} does not satisfy (((l - 12) % 6) == 0) condition.'.format(data, len(data)))
      
      (interval, seeders, leechers) = struct.unpack('>lll', data[:12])
      peers = BTPeer.seq_build(data[12:])
      
      peers_filtered = []
      for peer in peers:
         if ((int(peer.ip) == 0) or (peer.port == 0)):
            self.log(30, '{0} for invalid BTPeer data {1!a}. Discarding.'.format(self, peer))
            continue
         peers_filtered.append(peer)
      
      peers = peers_filtered
      
      # Build response data manually, since it doesn't exist at protocol level
      response_data = {
         b'peers': peers,
         b'interval':interval,
         b'complete':seeders,
         b'incomplete':leechers
         }
      return response_data
   
   def timeout_handle(self):
      """Handle session timeout."""
      self.log(30, '{0!a} (tracker {1!a}) timeouted in state {2!a}.'.format(self, self.announce_url, self.state))
      self.timeout_timer = None
      self.error_callback(TrackerResponseError('Session to tracker {0!a} timeouted in state {1!a}.'.format(self.announce_url, self.state)))
      self.close()
       
   def frame_process_init(self, data):
      """Process init response"""
      if (self.state != 0):
         raise TrackerResponseError('{0!a}.frame_process_init({1!a}) got called while state == {2!a}.'.format(self, data, self.state))
      self.connection_id = self.frame_parsebody_init(data)
      self.transaction_id = self.tid_generate()
      self.state = 1
      try:
         self.frame_send(self.frame_build_announce())
      except socket.error as exc:
         self.log(30, 'Unable to contact tracker {0}: UDP sendto() failed with \'{1}\'. Faking timeout.'.format(self.address_get(),exc))
         self._timeout_fake()
         return
      
   def frame_process_announce(self, data):
      """Process announce response"""
      if (self.state != 1):
         raise TrackerResponseError('{0!a}.frame_process_announce({1!a}) got called while state == {2!a}.'.format(self, data, self.state))
       
      response_data = self.frame_parsebody_announce(data)
      self.result_callback(self, response_data)
      self.close()
    
   def frame_process_error(self, data):
      """Process error response"""
      self.log(30, '{0!a} got error {1!a} from tracker.'.format(self, data))
      self.error_callback(TrackerResponseError('Tracker {0!a} returned failure reason {1!a}.'.format(self.announce_url, data)))
      self.close()
    
   FRAME_HANDLERS = {
      ACTION_CONNECT:frame_process_init,
      ACTION_ANNOUNCE:frame_process_announce,
      ACTION_ERROR:frame_process_error
   }
    
   def frame_process(self, data, source):
      """Process UDP frame received from tracker"""
      if (source != self.tracker_address):
         # Not what we're expecting.
         self.log(30, '{0!a} got unexpected udp frame {1!a} from {2!a}. Discarding.'.format(self, data, source))
         return
       
      if (len(data) < 8):
         raise ValueError('data {0!a} invalid; expected at least 8 bytes.'.format(data,))
      
      (action, tid) = struct.unpack('>ll', data[:8])
       
      if (tid != self.transaction_id):
         # Not what we're expecting.
         self.log(30, '{0!a} got unexpected tid {1!a}; expected {2!a}. Discarding frame.'.format(self, tid, self.transaction_id))
         return

      if (action in self.FRAME_HANDLERS):
         try:
            self.FRAME_HANDLERS[action](self, data[8:])
         except (TrackerResponseError, ValueError) as exc:
            self.log(30, '{0!a} failed to parse udp frame. Discarding frame. Traceback:'.format(self), exc_info=True)
      else:
         self.log(30, '{0!a} got frame with unknown action {1!a}. Discarding frame.'.format(self, action))
    
   def frame_send(self, data):
      """Send frame to tracker"""
      self.sock.send_bytes((data,), self.tracker_address)
   
   def _timeout_fake(self):
      if not (self.timeout_timer is None):
         self.timeout_timer.cancel()
      self.timeout_timer = self.ed.set_timer(0, self.timeout_handle)
   
   def request_send(self, event_dispatcher, result_callback, error_callback):
      """Initiate announce sequence"""
      if not (self.state is None):
         raise TrackerRequestError("Request {0!a} is still pending.".format(self.sock))
      
      self.result_callback = result_callback
      self.error_callback = error_callback
      
      self.ed = event_dispatcher
      
      try:
         tracker_addrinfo = random.choice(socket.getaddrinfo(*self.address_get()))
      except socket.error as exc:
         self.log(35, "Connection to tracker {0} failed; found no valid records. Faking timeout.".format(self.address_get()))
         self._timeout_fake()
         return
      
      tracker_AF = tracker_addrinfo[0]
      rsock = socket.socket(tracker_AF, socket.SOCK_DGRAM)
      
      self.sock = AsyncPacketSock(event_dispatcher, rsock)
      self.sock.process_input = self.frame_process
      self.sock.process_close = (lambda *args: None)
       
      self.transaction_id = self.tid_generate()
      self.state = 0
      self.tracker_address = tracker_addrinfo[4][:2]
      
      try:
         self.frame_send(self.frame_build_init())
      except socket.error as exc:
         # Ugly hack, but modeling explicitly reported send failure different
         # from a timeout isn't worth the hassle.
         self.log(30, 'Unable to contact tracker {0}: UDP sendto() failed with \'{1}\'. Faking timeout.'.format(self.address_get(),exc))
         self._timeout_fake()
         return
      self.timeout_timer = event_dispatcher.set_timer(self.TIMEOUT, self.timeout_handle)
    
   def close(self):
      """Close socket, if opened, and reset state variables"""
      self.ed = None
      if (self.sock):
         self.sock.close()
         self.sock = None
      if not (self.timeout_timer is None):
         self.timeout_timer.cancel()
         self.timeout_timer = None
      self.connection_id = None
      self.state = None
      self.transaction_id = None
      self.tracker_address = None
      self.result_callback = None
      self.error_callback = None


_request_types = {}
for cls in (HTTPTrackerRequest,UDPTrackerRequest):
   _request_types[cls.proto] = cls
del(cls)


def tracker_request_build(announce_url, *args, **kwargs):
   proto = HTTPLikeURL.build_from_urlstring(announce_url).proto
   try:
      cls = _request_types[proto]
   except KeyError:
      raise ValueError('Unknown proto {0!a} in announce URL {1!a}.'.format(proto, announce_url))
   
   return cls(announce_url, *args, **kwargs)

