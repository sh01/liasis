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


# BT structures for talking to trackers, based on information from
# <http://www.bittorrent.org/protocol.html> and
# <http://wiki.theory.org/BitTorrentSpecification>

import logging
import httplib
import urllib
import urllib2
import socket
import struct
import random

from gonium import http_hacks
from benc_structures import py_from_benc_str, BTPeer
from url_parsing import HTTPLikeURL


class TrackerRequestError(StandardError):
   pass

class TrackerResponseError(StandardError):
   pass


class TrackerRequest:
   logger = logging.getLogger('TrackerRequest')
   log = logger.log
   fields = ('info_hash', 'peer_id', 'port', 'uploaded', 'downloaded', 'left', 'compact', 'event', 'ip', 'numwant', 'trackerid', 'key')
   def __init__(self, announce_url, info_hash, peer_id, port, uploaded, downloaded, left, compact=True, event=None, ip=None, numwant=None, trackerid=None, key=None):
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
   proto = 'http'
   def __init__(self, *args, **kwargs):
      TrackerRequest.__init__(self, *args, **kwargs)
      self.connection = None
      self.result_callback = None
      self.error_callback = None
      self.clean_up_active = False
   
   def req_url_get(self):
      rlist = []
      for field in self.fields:
         val = getattr(self, field)
         if (val is None):
            continue
         if (isinstance(val,bool)):
            val = int(val)
         rlist.append('%s=%s' % (field, urllib.quote(str(val), safe='')))
      
      return '%s?%s' % (self.announce_url, '&'.join(rlist))

   def request_build(self):
      # There's at least one tracker which doesn't seem to like
      # Python-urllib-2.4 UA strings. Besides, this is more informative.
      ul_req = urllib2.Request(self.req_url_get(), None, {'User-Agent':'Liasis'})
      (got_exc, hcd) = http_hacks.HTTPConnection.call_wrap(urllib2.urlopen, (ul_req,), {}, ())
      
      if not (got_exc):
         raise TrackerRequestError("Httplib hack failed.")
      
      return hcd.req_string

   def conn_input_handle(self):
      pass

   def conn_close_handle(self, fd):
      """Handle closing of fd from our http connection: process data and pass result to callback"""
      if (self.clean_up_active):
         # Nothing to see here. Result is almost certainly incomplete
         return
      try:
         response_http = self.connection.buffers_input[fd]
         (got_exc, urlo) = http_hacks.HTTPConnection.call_wrap(urllib2.urlopen, (self.announce_url,), {}, (response_http,))
         
         if (got_exc):
            raise TrackerResponseError('HTTP parsing failed; got followup request: %r' % (urlo,))
         
         response_text = urlo.read()
         response_data = py_from_benc_str(response_text)
         
         if ('failure reason' in response_data):
            fr = response_data['failure reason']
            self.log(30, 'Got failure reason %r from tracker %r.' % (fr, self.announce_url))
            raise TrackerResponseError('Tracker %r returned failure reason %r. Complete response data: %r' % (self.announce_url, fr, response_data))
         if ('warning message' in response_data):
            wm = response_data['warning message']
            self.log(30, 'Got warning message %r from tracker %r.' % (fr, self.announce_url))
         
         # FIXME: According to wiki.theory.org, 'peer id' entries from the tuples
         # can also be hostnames. This hasn't been observed in practice, but we
         # should catch it here and do some kind of asynchronous lookup if they are.
         response_data['peers'] = BTPeer.seq_build(response_data['peers'])
      except (StandardError, httplib.HTTPException), exc:
         self.error_callback(self)
         self.log(30, 'Tracker request to %r failed. Resultstring: %r. Error: %r (%r)' % (self.announce_url, response_http, exc, str(exc)), exc_info=False)
      else:
         self.result_callback(self, response_data)
         self.clean_up()
   
   def request_send(self, event_dispatcher, result_callback, error_callback):
      """Open connection to announce url, open and send request"""
      if not (self.connection is None):
         raise TrackerRequestError("Request %r is still pending." % self.connection)
      
      self.connection = event_dispatcher.SockStreamBinary()
      self.connection.input_handler = self.conn_input_handle
      self.connection.close_handler = self.conn_close_handle
      self.result_callback = result_callback
      self.error_callback = error_callback
      
      try:
         request_string = self.request_build()
      except urllib2.URLError:
         self.log(30, 'Error building request for %r:' % (self.req_url_get(),), exc_info=True)
         error_callback(self)
         return
      
      try:
         self.connection.connection_init(self.address_get(default_port=80))
      except socket.error:
         self.connection = None
         self.result_callback = None
         self.error_callback = None
         error_callback(self)
      else:
         self.connection.send_data(request_string)

   def clean_up(self):
      self.clean_up_active = True
      if (self.connection):
         self.connection.clean_up()
      self.connection = None
      self.callback_handler = None
      self.clean_up_active = False


# Implementation of protocol described on
# <http://home.mchsi.com/~bitbuddy/wsb/udp_tracker_protocol.html>
# Unfortunately, this protocol seems to be limited to ipv4.
# Fortunately, it doesn't appear to be widely used.
class UDPTrackerRequest(TrackerRequest):
   proto = 'udp'
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
      'completed':1,
      'started':2,
      'stopped':3
   }
   
   def __init__(self, *args, **kwargs):
      TrackerRequest.__init__(self, *args, **kwargs)
      self.sock = None
      self.timeout_timer = None
      self.clean_up()
   
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
         raise ValueError('Data %r invalid; expected exactly 8 bytes.' % (data,))
      return struct.unpack('>q', data)[0]
    
   @staticmethod
   def frame_parsebody_announce(data):
      """Parse announce response body (packet minus initial 8 bytes) and return contents"""
      if (len(data) < 12):
         raise ValueError('Data %r invalid; expected at least 12 bytes.' % (data,))
      if (((len(data) - 12) % 6) != 0):
         raise ValueError('Data %r invalid; length %d does not satisfy (((l - 12) % 6) == 0) condition.' % (data, len(data)))
      
      (interval, seeders, leechers) = struct.unpack('>lll', data[:12])
      peers = BTPeer.seq_build(data[12:])
       
      for peer in peers:
         if ((int(peer.ip) == 0) or (peer.port == 0)):
            raise ValueError('Invalid BTPeer data %r.' % (peer,))
       
      # Build response data manually, since it doesn't exist at protocol level
      response_data = {
         'peers': peers,
         'interval':interval,
         'complete':seeders,
         'incomplete':leechers
         }
      return response_data
   
   def timeout_handle(self):
      """Handle session timeout."""
      self.log(30, '%r (tracker %r) timeouted in state %r.' % (self, self.announce_url, self.state))
      self.timeout_timer = None
      self.error_callback(TrackerResponseError('Session to tracker %r timeouted in state %r.' % (self.announce_url, self.state)))
      self.clean_up()
       
   def frame_process_init(self, data):
      """Process init response"""
      if (self.state != 0):
         raise TrackerResponseError('%r.frame_process_init(%r) got called while state == %r.' % (self, data, self.state))
      self.connection_id = self.frame_parsebody_init(data)
      self.transaction_id = self.tid_generate()
      self.state = 1
      self.frame_send(self.frame_build_announce())
       
   def frame_process_announce(self, data):
      """Process announce response"""
      if (self.state != 1):
         raise TrackerResponseError('%r.frame_process_announce(%r) got called while state == %r.' % (self, data, self.state))
       
      response_data = self.frame_parsebody_announce(data)
      self.result_callback(self, response_data)
      self.clean_up()
    
   def frame_process_error(self, data):
      """Process error response"""
      self.log(30, '%r got error %r from tracker.' % (self, data))
      self.error_callback(TrackerResponseError('Tracker %r returned failure reason %r.' % (self.announce_url, data)))
      self.clean_up()
    
   FRAME_HANDLERS = {
      ACTION_CONNECT:frame_process_init,
      ACTION_ANNOUNCE:frame_process_announce,
      ACTION_ERROR:frame_process_error
   }
    
   def frame_process(self, source, data):
      """Process UDP frame received from tracker"""
      if (source != self.tracker_address):
         # Not what we're expecting.
         self.log(30, '%r got unexpected udp frame %r from %r. Discarding.' % (self, data, source))
         return
       
      if (len(data) < 8):
         raise ValueError('data %r invalid; expected at least 8 bytes.' % (data,))
      
      (action, tid) = struct.unpack('>ll', data[:8])
       
      if (tid != self.transaction_id):
         # Not what we're expecting.
         self.log(30, '%r got unexpected tid %r; expected %r. Discarding frame.' % (self, tid, self.transaction_id))
         return

      if (action in self.FRAME_HANDLERS):
         self.FRAME_HANDLERS[action](self, data[8:])
      else:
         self.log(30, '%r for frame with unknown action %r. Discarding frame.' % (self, action))
    
   def frame_send(self, data):
      """Send frame to tracker"""
      self.sock.send_data(data, self.tracker_address)
    
   def request_send(self, event_dispatcher, result_callback, error_callback):
      """Initiate announce sequence"""
      if not (self.state is None):
         raise TrackerRequestError("Request %r is still pending." % self.sock)
      
      self.result_callback = result_callback
      self.error_callback = error_callback
      
      self.sock = event_dispatcher.SockDatagram(input_handler=self.frame_process)
      self.sock.connection_init()
       
      self.transaction_id = self.tid_generate()
      self.state = 0
      self.tracker_address = (random.choice(socket.getaddrinfo(*self.address_get()))[4])
       
      self.frame_send(self.frame_build_init())
      
      self.timeout_timer = event_dispatcher.Timer(self.TIMEOUT, self.timeout_handle)
    
   def clean_up(self):
      """Close socket, if opened, and reset state variables"""
      if not (self.sock is None):
         self.sock.clean_up()
         self.sock = None
      if not (self.timeout_timer is None):
         self.timeout_timer.stop()
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
      raise ValueError('Unknown proto %r in announce URL %r.' % (proto, announce_url))
   
   return cls(announce_url, *args, **kwargs)

