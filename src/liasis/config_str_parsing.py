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

import socket

def socket_args_parse(af_str:bytes, addr_str:bytes):
   af = getattr(socket, af_str)
   if (af == socket.AF_UNIX):
      if (addr_str.count(b'\x00') > 0):
         raise ValueError('{0!a} is not a valid filename'.format(addr_str))
      return (af, (addr_str,))
   
   if (af == socket.AF_INET):
      (addr, port_str) = addr_str.split(b':')
      if (not port_str.isdigit()):
         raise ValueError()
      port = int(port_str)
      return (af, (addr, port))
   
   if (af == socket.AF_INET6):
      port_index = addr_str.rindex(b':')
      port_str = addr_str[port_index+1:]
      
      host_str = addr_str[:port_index]
      if (not (host_str.startswith(b'[') and (host_str.endswith(b']')))):
         host = host_str
      else:
         host = host_str[1:-1]
         
      if (not port_str.isdigit()):
         raise ValueError('Port str {0!a} is invalid.'.format(port_str))
      
      port = int(port_str[1:])
      return (af, (host, port))
   
   return ValueError('Unknown address family {0!a} ({1!a}).'.format(af_str, af))

