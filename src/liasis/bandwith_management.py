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

"""Liasis gonium bandwith limiting and counting structures."""

from gonium.event_multiplexing import EventMultiplexer

class BandwithError(Exception):
   pass

class BandwithRequest:
   """Outstanding request for bandwith."""
   def __init__(self, bytes, bytes_min, callback, parent, priority):
      self.bytes = bytes
      self.bytes_min = bytes_min
      self.callback = callback
      self.priority = priority
      self.parent = parent
      self.request_ts = time.time()
   
   def __eq__(self, other):
      return self.__cmp__(other) == 0
   def __ne__(self, other):
      return self.__cmp__(other) != 0
   def __lt__(self, other):
      return self.__cmp__(other) == -1
   def __le__(self, other):
      return self.__cmp__(other) <= 0
   def __gt__(self, other):
      return self.__cmp__(other) == 1
   def __ge__(self, other):
      return self.__cmp__(other) >= 0
   
   def __cmp__(self, other):
      if (self.priority != other.priority):
         if (self.priority < other.priority):
            return 1
         else:
            return -1
      
      if (self.request_ts != other.request_ts):
         if (self.request_ts < other.request_ts):
            return -1
         return 1
      # the rest of this is unlikely to be used in practice
      if (self.bytes != other.bytes):
         if (self.bytes < other.bytes):
            return -1
         return 1
      
      if (self.bytes_min != other.bytes_min):
         if (self.bytes_min < other.bytes_min):
            return -1
         return 1

      if (self.callback < other.callback):
         return -1
      if (self.callback > other.callback):
         return 1
      
      if (self is other):
         return 0
      raise Exception('{0!a} and {1!a} are incomparable'.format(self, other))

   def __hash__(self):
      return id(self)

   def callback_call(self, *args, **kwargs):
      self.callback(bandwith_request=self, *args, **kwargs)

   def register(self):
      self.parent.requests_active.append(self)
      
   def unregister(self):
      self.parent.requests_active.remove(self)
      
   cancel = unregister

   def __repr__(self):
      '{0}({1!a},{2!a},{3!a},{4!a})'.format(self.__class__.__name__, self.bytes, self.bytes_min, self.callback, self.priority)


class RingBuffer(object):
   """Ring Buffer used for bandwith logging"""
   def __init__(self, history_length=1000, history_values_initial=None):
      self.history = [history_values_initial]*history_length
      self.history_index = 0
      self.history_length = history_length
   
   def slice_add(self, val):
      """Advance index and set resulting slot to specified value"""
      self.history_index = (self.history_index + 1) % self.history_length
      self.history[self.history_index] = val
   
   def __len__(self):
      return self.history_length
   
   def __getitem__(self, key):
      history_linear = self.history[self.history_index + 1:] + self.history[:self.history_index + 1]
      return history_linear.__getitem__(key)


class BandwithLoggerBase(RingBuffer):
   """Basis for bandwith logging functionality; won't work by itself, only
      useful as a baseclass
      
   Event multiplexers:
   em_cycle:
      triggers: At beginning of each new cycle (slice)
   em_close:
      triggers: At instance clean_up
   """
   bandwith_loggers = set()
   def __init__(self_bl, event_dispatcher, cycle_length, *args, **kwargs):
      RingBuffer.__init__(self_bl, *args, **kwargs)
      
      # FIXME: we really don't need to mess with runtime-generated classes
      # to get the functionality we need here ... clean this up someday.
      class PriorityBandwithLimiter_BandwithRequest(BandwithRequest):
         parent = self_bl
      
         def callback_call(self, bytes_granted, *args, **kwargs):
            self.callback(bandwith_request=self, bytes_granted=bytes_granted, *args, **kwargs)

      # event multiplexers
      self_bl.em_cycle = EventMultiplexer(self_bl)
      self_bl.em_close = EventMultiplexer(self_bl)

      # long-term data
      self_bl.request_cls = PriorityBandwithLimiter_BandwithRequest
      self_bl.event_dispatcher = event_dispatcher
      self_bl.cycle_length = cycle_length
      self_bl.cycle_begin() # test whether this was overidden correctly
      self_bl.cycle_timer = self_bl.event_dispatcher.set_timer(cycle_length,
         self_bl.cycle_begin, parent=self_bl, persist=True, align=True)
      self_bl.bandwith_loggers.add(self_bl) # why are we doing this, again?

   def bandwith_request(self, *args, **kwargs):
      EventMultiplexer
      raise NotImplementedError("Request processing should be done by subclasses")
   
   def cycle_begin(self):
      """Begin new counting / limiting slice.
      
      This version merely triggers the EventMultiplexer; counting / limiting
      should be implemented by subclasses."""
      self.em_cycle()

   def close(self):
      if (self.cycle_timer):
         self.cycle_timer.cancel()
         self.cycle_timer = None
      if (self in self.bandwith_loggers):
         self.bandwith_loggers.remove(self)
      
      self.em_close()
      self.em_cycle.close()
      self.em_close.close()


class NullBandwithLimiter(BandwithLoggerBase):
   """Basic logging functionality combined with no bandwith limiting."""
   def __init__(self, event_dispatcher, cycle_length, *args, **kwargs):
      self.bytes_used = 0
      super(NullBandwithLimiter, self).__init__(
         event_dispatcher=event_dispatcher, cycle_length=cycle_length, *args,
         **kwargs)
      
   def bandwith_request(self, bytes, bytes_min, callback, *args, **kwargs):
      """Always grants <bytes>, immediately."""
      self.bytes_used += bytes
      return bytes
   
   def bandwith_take(self, bytes, *args, **kwargs):
      """Notes that application has used <bytes> bytes of bandwith without request"""
      self.bytes_used += bytes
   
   def cycle_begin(self):
      self.history_index = (self.history_index + 1) % self.history_length
      self.history[self.history_index] = self.bytes_used
      self.bytes_used = 0
      BandwithLoggerBase.cycle_begin(self)


class PriorityBandwithLimiter(BandwithLoggerBase):
   """Bandwith limiter which will assign at most <byte_slice> bytes of traffic,
      once per cycle_length. Unused bandwith in a cycle is not carried over
      into subsequent cycles.
      Bandwith is assigned based on request priority, with higher priorities
      being served first.
   """
   def __init__(self, event_dispatcher, byte_slice, cycle_length, *args, **kwargs):
      """Initialize bandwith limiter with given byte slice and cycle length"""
      # long-term data
      self.requests_active = []
      self.byte_slice = byte_slice
      
      # short-term data
      self.byte_reserve = byte_slice # this may become negative through bandwith_take()
      
      # only initialize baseclass now that calling self.cycle_begin() is safe
      super(PriorityBandwithLimiter, self).__init__(event_dispatcher,
         cycle_length=cycle_length, *args, **kwargs)
   
   def bandwith_request(self, bytes, bytes_min, callback, parent=None, priority=0):
      """Request <bytes> of traffic in chunks >= <bytes_min>, except for the
         last one. If immediately granted, simply returns the amount.
         Otherwise, if bool(callback) is True, a self.request_cls will be
         instantiated with the passed parameters, registered and returned."""
      assert (bytes >= bytes_min > 0)
      if (bytes_min > self.byte_slice):
         raise BandwithError("bytes_min {0} is greater than byte_slice {1}; request would never be granted".format(bytes_min, self.byte_slice))
         
      if (bytes_min <= self.byte_reserve):
         grant = min(self.byte_reserve, bytes_min)
         self.byte_reserve -= bytes_min
         return grant

      if (callable(callback)):
         rv = self.request_cls(bytes=bytes, bytes_min=bytes_min, parent=parent, priority=priority)
         self.requests_active.append(rv)
         return rv
   
   def bandwith_take(self, bytes, parent=None):
      """Notes that application has used <bytes> bytes of bandwith without request"""
      self.bytes_reserve -= bytes
   
   def cycle_begin(self):
      """Begin a new cycle; deals out remaining bandwith and resets byte_reserve"""
      self.requests_active.sort()
      # We can't iterate over the list directly, since it may be modified by
      # bandwith_request() calls from the callbacks; however, we also have to
      # remember such modifications for the next cycle.
      requests_active_tuple = tuple(self.requests_active)
      del(self.requests_active[:])

      byte_reserve = self.byte_reserve

      for request in tuple(self.requests_active):
         if (byte_reserve <= 0):
            # We won't reduce it below zero directly, but calls to
            # bandwith_take() from the callbacks might
            break
         
         if (request.bytes_min > byte_reserve):
            continue
         if (request.bytes > byte_reserve):
            grant = byte_reserve
            byte_reserve = 0
            request_done = False
            request.bytes -= grant
            if (request.bytes < request.bytes_min):
               request.bytes_min = request.bytes
            self.requests_active.append(request)
         else:
            grant = request.bytes
            byte_reseve -= grant
            request_done = True
         
         request.callback_call(bytes_granted=grant, request_done=request_done)
      
      self.history_index = (self.history_index + 1) % self.history_length
      self.history[self.history_index] = (self.byte_slice - byte_reserve)
      
      self.byte_reserve = self.byte_slice
      
      BandwithLoggerBase.cycle_begin(self)
