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


class HTTPLikeURL:
   def __init__(self, proto, host, port, path):
      self.proto = proto
      self.host = host
      self.port = port
      self.path = path
   
   @classmethod
   def build_from_urlstring(cls, urlstring):
      (proto, text) = urlstring.split('://', 1)
      text_split = text.split('/',1)
      hostport = text_split[0]
      if (len(text_split) == 1):
         path = ''
      else:
         path = text_split[1]
      
      if (hostport.startswith('[') and (hostport.count('[') ==  hostport.count(']') == 1)):
         # direct ipv6 address specification
         (host, text) = hostport.split(']')
         host = host[1:]
         if (text != ''):
            if not (text.startswith(':')):
               raise ValueError('Invalid url %r; expected port in data after ipv6 address in host field.' % (urlstring,))
            port = int(text[1:],10)
         else:
            port = None
      else:
         text_split = hostport.split(':',1)
         host = text_split[0]
         if (len(text_split) == 1):
            port = None
         else:
            port = int(text_split[1],10)
      
      return cls(proto, host, port, path)
   
   def __repr__(self):
      return '%s(**%s)' % (self.__class__.__name__, self.__dict__)

