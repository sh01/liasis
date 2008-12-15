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


import struct
from io import BytesIO

from .benc_structures import py_from_benc_str, benc_str_from_py


class BTControlConnectionError(Exception):
   pass

class BTCCStateError(BTControlConnectionError):
   pass

class BTControlConnectionBase:
   """Base class for liasis BT control connections"""
   SNUM_MAX = 2**32 - 1
   SNUM_UB = (SNUM_MAX + 1)/2
   
   MSGLEN_MAX = 2**32 - 1

   def __init__(self):
      self.snum_in = 0
      self.snum_out = 0
      self.messages_pending = []
   
   @classmethod
   def snum_cmp(cls, snum_1, snum_2):
      """Compare two sequence numbers"""
      delta = (snum_2 - snum_1)
      if (delta == 0):
         return 0
      if (0 < delta <= cls.SNUM_UB):
         # snum_2 bigger
         return -1
      # snum_1 bigger
      return 1
   
   def msg_send(self, cmd, args):
      """Queue a single message specified by cmd and args to peer."""
      self.msgstr_send(benc_str_from_py([cmd,] + list(args)))
   
   def msgstr_send(self, data):
      """Queue single message specified by string to peer."""
      if (not self):
         return
      data_len = len(data)
      if (len(data) > self.MSGLEN_MAX):
         raise BTControlConnectionError('Specified message {0!a} of length {1} is longer than maximum message length {2}.'.format(data, len(data), self.MSGLEN_MAX))

      header = struct.pack('>II', data_len, self.snum_out)
      self.send_bytes((header + data,))
   
   def rcr_presence_check(self, rc_risk, seq_num):
      """Check for presence of acute race condition threat; should be implemented by subclasses that need it"""
      raise NotImplementedError('rcr_presence_check should be implemented by subclass')
   
   def process_close(self):
      """Process connection close"""
      pass
   
   def process_input(self, in_data):
      """Process input received from peer"""
      in_data_sio = BytesIO(in_data)
      in_data_len = len(in_data)
      
      while (True):
         index = in_data_sio.tell()
         if ((in_data_len - index) < 8):
            break
         
         header_str = in_data_sio.read(8)
         (data_len, seq_num) = struct.unpack('>II', header_str)
         if ((in_data_len - index) < data_len):
            # Message incomplete
            in_data_sio.seek(-8,1)
            break
         
         data = in_data_sio.read(data_len)
         
         self.snum_in = seq_num
         if (len(data) == 0):
            continue
         
         # decode data and call specific data handler
         try:
            msg_data = py_from_benc_str(data)
         except ValueError:
            self.error_process_benc(data)
            self.log(30, 'Protocol benc error on {0!a}, line {1}:'.format(self, data), exc_info=True)
            continue
         
         cmd = msg_data[0]
         if not (cmd in self.input_handlers):
            self.error_process_unknowncmd(data, msg_data)
            self.log(30, 'Protocol command error on {0!a}, line {1}.'.format(self, data))
            continue
         
         (input_handler_name, rc_risks, acked_list) = self.input_handlers[cmd]
         if (rc_risks and self.rcr_presence_check(rc_risks, seq_num)):
            self.msg_send('RCREJ', msg_data)
            continue
         
         if (not (acked_list is None)):
            if (self.messages_pending[0][0] in acked_list):
               del(self.messages_pending[0])
            else:
               raise BTControlConnectionError("{0!a} got non-spurious command line {1}, which doesn't fit pending messages {2!a}.".format(self, msg_data, self.messages_pending))
         
         input_handler = getattr(self, input_handler_name)
         try:
            input_handler(cmd, msg_data[1:])
         except (IndexError, TypeError, ValueError, KeyError) as exc:
            self.error_process_arg(data, msg_data, exc)
            self.log(30, 'Protocol args error on {0}, line {1!a}:'.format(self, data), exc_info=True)
         except:
            # Fatal; caller will try to close connection. Don't try to process
            # anymore of the buffered input.
            self.discard_inbuf_data()
            raise
      
      self.discard_inbuf_data(in_data_sio.tell())

   # protocol error handlers
   def error_process_benc(self, msg_string):
      """Process reception of invalidly encoded message; should be implemented by subclasses"""
      raise NotImplementedError('error_process_benc should be implemented by subclasses')
      
   def error_process_unknowncmd(self, msg_string, msg_data):
      """Process reception of unknown command; should be implemented by subclasses"""
      raise NotImplementedError('error_process_unknowncmd should be implemented by subclasses')
      
   def error_process_arg(self, msg_string, msg_data, exc=None):
      """Process reception of command with invalid arguments; should be implemented by subclasses"""
      raise NotImplementedError('error_process_arg should be implemented by subclasses')

   # tuple contents:
   #  1. name of processing method
   #  2. race condition risk
   #  3. commands that may cause this command; None for unprovoked commands
   input_handlers = None # override this in subclass
