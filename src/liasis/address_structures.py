#!/usr/bin/python
#Copyright 2004, 2005, 2006 Sebastian Hagen
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

import socket
from socket import inet_pton, inet_ntop, AF_INET, AF_INET6
import struct


def ip_make(ip_data):
   if (isinstance(ip_data, ip_address_base)):
      return ip_data
   if (isinstance(ip_data, (int, long))):
      try:
         return ip_address_v4(ip_data)
      except ValueError:
         try:
            return ip_address_v6(ip_data)
         except ValueError:
            pass
   elif (isinstance(ip_data, basestring)):
      try:
         return ip_address_v4.fromstring(ip_data)
      except socket.error:
         try:
            return ip_address_v6.fromstring(ip_data)
         except socket.error:
            pass
   else:
      raise TypeError('Invalid type %r for argument ip_data of value %r (expected numeric or string type).' % (type(ip_data), ip_data))
   
   raise ValueError('Unable to convert argument %r to a v4 or v6 ip address.' % (ip_data,))


class ip_address_base(object):
   __slots__ = ['ip']
   
   def __init__(self, ip_int):
      if (ip_int < self.ip_minimum):
         raise ValueError('Value %r for argument ip_int is smaller than %s.' % (ip_int, self.ip_minimum))
      elif (ip_int > self.ip_maximum):
         raise ValueError('Value %r for argument ip_int is greater than %s.' % (ip_int, self.ip_maximum))
      self.ip = ip_int
   
   def fromstring(target_class, ip_string):
      self = target_class.__new__(target_class)
      self.ip = target_class.ipintfromstring(ip_string)
      return self
   fromstring = classmethod(fromstring)
      
   def __hash__(self):
      return hash(self.ip)
      
   
   def __add__(self, other):
      return self.__class__(int(self)+int(other))
      
   def __sub__(self, other):
      return self.__class__(int(self)-int(other))
      
   def __or__(self, other):
      return self.__class__(int(self) | int(other))
      
   def __xor__(self, other):
      return self.__class__(int(self) ^ int(other))
      
   def __and__(self, other):
      return self.__class__(int(self) & int(other))
      
   __radd__ = __add__
   __rsub__ = __sub__
   __ror__ = __or__
   __rxor__ = __xor__
   __rand__ = __and__
      
   def __not__(self):
      return self.__class__(~int(self))
      
   def __lshift__(self, other):
      return self.__class__(int(self) << other)
   
   def __rshift__(self, other):
      return self.__class__(int(self) >> other)
      
   def __nonzero__(self):
      return bool(self.ip)
      
   def __cmp__(self, other):
      (self, other) = (int(self), int(other))
      if (self < other):
         return -1
      elif (other < self):
         return 1
      else:
         return 0
  
   def __list__(self):
      elements = []
      integer = self.ip
      for i in range(self.subelements):
         elements.append(self.format % (integer % self.factor))
         integer //= self.factor
      
      elements.reverse()
      return elements
     
   def __tuple__(self):
      return tuple(self.__list__())
      
   def __str__(self):
      return self.separator.join(self.__list__())
      
   def __repr__(self):
      return '%s.fromstring(%r)' % (self.__class__.__name__, self.__str__())
   
   def __int__(self):
      return self.ip
   
   def __long__(self):
      return long(self.ip)
   
   def __getstate__(self):
      return (self.ip,)

   def __setstate__(self, state):
      self.ip = state[0]
   
class ip_address_v4(ip_address_base):
   separator = '.'
   factor = 256
   format = '%d'
   subelements = 4
   ip_minimum = 0
   ip_maximum = factor**subelements -1
   
   def ipintfromstring(ip_string):
      return struct.unpack('>L', inet_pton(AF_INET, ip_string))[0]
      #if not (isinstance(ip_string, basestring)):
      #   raise TypeError('Argument ip_string should be of string type (got %r which is of type %r).' % (ip_string, type(ip_string)))
      #ip_string_split = ip_string.split('.')
      #if (len(ip_string_split) != 4):
      #   raise ValueError('Argument %r for ip_string does not contain 4 dot-separated substrings.' % (ip_string,))
      
      #ip_string_split = map(int,ip_string_split)
      #ip_string_split.reverse()
      #
      #factor = 1
      #ip = 0
      #for element in ip_string_split:
      #   if (element >= 256):
      #      raise ValueError('Value %d of ip-element of ip %r is bigger than 65536.' % (element, ip_string))
         
      #   ip += element * factor
      #   factor *= self.factor
      #return ip
   ipintfromstring = staticmethod(ipintfromstring)
   
   def __str__(self):
      return inet_ntop(AF_INET,struct.pack('>L', self.ip))

      
class ip_address_v6(ip_address_base):
   separator = ':'
   factor = 65536
   format = '%X'
   subelements = 8
   ip_minimum = 0
   ip_maximum = factor**subelements - 1
   
   def ipintfromstring(target_class, ip_string):
      (int1, int2) = struct.unpack('>QQ', inet_pton(AF_INET6, ip_string))
      return int1*18446744073709551616L + int2		#18446744073709551616L == 2**(8*8) ; one more than maximum value of unsigned long long
      
      #if not (isinstance(ip_string, basestring)):
      #   raise TypeError('Argument ip_string should be of string type (got %r which is of type %r).' % (ip_string, type(ip_string)))
   
      #ip_string_split = ip_string.split(':')
      
      #if ('' in ip_string_split):
      #   abbreviated = True
      #else:
      #   abbreviated = False

      #if (ip_string_split.count('') >= 2):
      #   if (ip_string_split[0] == ''):
      #      ip_string_split[0] = '0'
      #   if (ip_string_split[-1] == ''):
      #      ip_string_split[-1] = '0'
            
      #if (ip_string_split.count('') > 1):
      #   raise ValueError('Value %r for argument ip_string contains either a sequence of more than three colons, or/and several two-colon sequences.' % (ip_string,))
      
      #elif (len(ip_string_split) > target_class.subelements):
      #   raise ValueError('Value %r for argument ip_string contains more than %d colon-separated substrings.' % (ip_string, target_class.subelements))
      
      #elif ((len(ip_string_split) < target_class.subelements) and (not abbreviated)):
      #   raise ValueError('Value %r for argument ip_string contains less than %d colon-separated substrings, and no :: sequence.' % (ip_string, target_class.subelements))

      #if (abbreviated):
      #   abbreviation_index = ip_string_split.index('')
      #   ip_string_split = [int(element, 16) for element in ip_string_split[:abbreviation_index] + ['0',]*(9-len(ip_string_split)) + ip_string_split[abbreviation_index+1:]]

      #ip_string_split.reverse()
      #ip = 0
      #factor = 1
      #for element in ip_string_split:
      #   if (element >= 65536):
      #      raise ValueError('Value %d of ip-element of ip %r is bigger than 65536.' % (element, ip_string))
         
      #   ip += element * factor
      #   factor *= target_class.factor
      #return ip 
   ipintfromstring = classmethod(ipintfromstring)
   def __str__(self):
      return inet_ntop(AF_INET6, struct.pack('>QQ', self.ip//18446744073709551616L, self.ip & 18446744073709551615L))
   
   
