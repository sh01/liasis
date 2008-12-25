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


# Some basic BT data structures, based on information from
# <http://www.bittorrent.org/protocol.html> and
# <http://wiki.theory.org/BitTorrentSpecification>

import struct
import random
import datetime
import os.path
import fcntl
import binascii
from collections import Sequence,deque
from hashlib import sha1
from io import BytesIO

from gonium.ip_address import ip_address_build

from .bt_exceptions import BTClientError


def py_from_benc_stream(stream):
   """Read and return one entity from a stream containing bencoded data"""
   next_byte = stream.read(1)
   if (next_byte.isdigit()):
      # string
      digit_str = b''
      while (next_byte.isdigit()):
         digit_str += next_byte
         next_byte = stream.read(1)
      if (next_byte != b':'):
         raise ValueError('string length followed by {0!a}, expected b":".'.format(next_byte,))
      else:
         str_len = int(digit_str)
         rv = stream.read(str_len)
         assert (len(rv) == str_len)
         return rv
   
   if (next_byte == b'i'):
      # integer
      digit_str = b''
      next_byte = stream.read(1)
      if (next_byte == b'-'):
         digit_str += next_byte
         next_byte = stream.read(1)

      while (next_byte.isdigit()):
         digit_str += next_byte
         next_byte = stream.read(1)
      if (next_byte != b'e'):
         raise ValueError('integer digit sequence followed by {0!a}, expected "e".'.format(next_byte,))
      if (digit_str.startswith(b'-0')):
         raise ValueError('integer digitstring {0!a} is invalid'.format(digit_str,))
      if (digit_str.startswith(b'0') and (len(digit_str) != 1)):
         raise ValueError('integer digitstring {0!a} starts with 0 and has length > 0'.format(digit_str,))
      
      if (digit_str == b''):
         # Edge case. The official spec doesn't state that this is invalid.
         return 0
      return int(digit_str)
   
   if (next_byte == b'l'):
      # list
      rv = []
      next_byte = stream.read(1)
      while (next_byte != b'e'):
         stream.seek(-1,1)
         rv.append(py_from_benc_stream(stream))
         next_byte = stream.read(1)
      return rv
      
   if (next_byte == b'd'):
      # dictionary
      rv = {}
      next_byte = stream.read(1)
      while (next_byte != b'e'):
         stream.seek(-1,1)
         key = py_from_benc_stream(stream)
         value = py_from_benc_stream(stream)
         rv[key] = value
         next_byte = stream.read(1)
      return rv

   raise ValueError('Unable to interpret initial chunk byte {0!a}.'.format(next_byte,))


def py_from_benc_str(string):
   """Read and return one entity from a string containing bencoded data"""
   return py_from_benc_stream(BytesIO(string))


def benc_str_from_py(obj):
   """Encode a python dict/list/str/int structure in a bencoded string"""
   if (isinstance(obj, (bytes, bytearray))):
      return '{0}:'.format(len(obj)).encode('ascii') + obj
   if (isinstance(obj, int)):
      return 'i{0}e'.format(obj).encode('ascii')
   if (isinstance(obj, (list,tuple,deque))):
      return b'l' + b''.join((benc_str_from_py(e) for e in obj)) + b'e'
   if (isinstance(obj, dict)):
      keys = sorted(obj.keys())
      return b'd' + b''.join(((benc_str_from_py(key) + benc_str_from_py(obj[key])) for key in keys)) + b'e'
   
   raise TypeError('Unable to encode object {0!a} of type {1}.'.format(obj,type(obj)))


class BTPeer:
   def __init__(self, ip, port, peer_id):
      self.ip = ip_address_build(ip)
      self.port = port
      self.peer_id = peer_id
      
   @classmethod
   def build_from_str(cls, string):
      (iplong, port) = struct.unpack('>IH', string)
      return cls(iplong, port, None)
   
   def state_get(self):
      """Summarize internal state using nested dicts, lists, ints and strings"""
      state = {
         b'ip': int(self.ip),
         b'port': self.port,
      }
      if not (self.peer_id is None):
         state[b'peer id'] = self.peer_id
      
      return state
   
   @classmethod
   def build_from_dict(cls, dict):
      if (b'peer id' in dict):
         peer_id = dict[b'peer id']
      else:
         peer_id = None
      return cls(ip = dict[b'ip'], port = dict[b'port'], 
         peer_id = peer_id)
   
   build_from_state = build_from_dict
   
   def __hash__(self):
      return hash((self.ip, self.port))
   
   def __eq__(self, other):
      if ((self.ip == other.ip) and (self.port == other.port)):
         return True
      return False
   
   def __neq__(self, other):
      return (not (self == other))
   
   @classmethod
   def seq_build(cls, seq):
      rv = []
      if (isinstance(seq,(bytes,bytearray,memoryview))):
         assert ((len(seq) % 6) == 0)
         rv = tuple([cls.build_from_str(seq[i:i+6]) for i in range(0,len(seq),6)])
      elif (isinstance(seq, list) or isinstance(seq, tuple)):
         rv = tuple([cls.build_from_dict(dict) for dict in seq])
      else:
         raise TypeError('Unable to process argument {0!a} of type {1};'
            'expected string or list/tuple.'.format(seq, type(seq)))

      return rv
   
   def address_get(self):
      return (self.ip, self.port)
   
   def __repr__(self):
      return '{0}{1!a}'.format(self.__class__.__name__, (self.ip, self.port, self.peer_id))
   
   def __str__(self):
      return '{0}{1!a}'.format(self.__class__.__name__, (str(self.ip), self.port, self.peer_id))


class BTMetaInfo:
   """Bt Metainfo file structure"""
   fields = ('announce_urls', 'piece_length', 'piece_hashes', 'files',
      'info_hash', 'basename', 'length_total', 'creation_ts', 'dict_init',
      'creator', 'comment')
   hash_helper = sha1
   
   btmeta_known_fields_global = set(('announce-list', 'announce', 'creation date', 'created by', 'comment', 'info'))
   btmeta_known_fields_info = set(('piece length', 'pieces', 'length', 'name', 'path', 'md5sum', 'files'))

   hr_line_fmt_str = '{0:20} {1}'
   hr_line_fmt_repr = '{0:20} {1!a}'
   def __init__(self, announce_urls, piece_length, piece_hashes, files,
         info_hash, basename, length_total, dict_init, creation_ts=None,
         creator=None, comment=None, announce_urls_shuffle=True):
      for field in self.fields:
         setattr(self, field, locals()[field])
      
      if (announce_urls_shuffle):
         for tier in announce_urls:
            random.shuffle(tier)
   
   @classmethod
   def str_hash(cls, string):
      return cls.hash_helper(string).digest()
   
   def state_get(self):
      """Summarize internal state using nested dicts, lists, ints and strings"""
      return self.dict_init
   
   @classmethod
   def build_from_dict(cls, dict, *args, **kwargs):
      """Create instance based on dict from benc data"""
      if (b'announce-list' in dict):
         announce_urls = dict[b'announce-list']
      else:
         announce_urls = [[dict[b'announce']]]
      if (b'creation date' in dict):
         creation_ts = datetime.datetime.fromtimestamp(dict[b'creation date'])
      else:
         creation_ts = None
      if (b'created by' in dict):
         creator = dict[b'created by']
      else:
         creator = None
      if (b'comment' in dict):
         comment = dict[b'comment']
      else:
         comment = None
      
      info = dict[b'info']
      
      piece_length = info[b'piece length']
      pieces_str_length = len(info[b'pieces'])
      pieces_str = info[b'pieces']
      if ((pieces_str_length % 20) != 0):
         raise ValueError('info->pieces length {0!a} is not a multiple of 20'.format(pieces_str_length,))
      piece_hashes = [pieces_str[i:i+20] for i in range(0,pieces_str_length,20)]
      
      if (b'length' in info):
         files = [BTTargetFile.build_from_dict(info, file_single=True)]
         basename = b''
      else:
         files = [BTTargetFile.build_from_dict(d, file_single=False) for d in info[b'files']]
         basename = info[b'name']
      
      length_total = sum([btfile.length for btfile in files])
      if not (piece_length*(len(piece_hashes)-1) < length_total <= piece_length*len(piece_hashes)):
         raise ValueError('BTMetaInfo sanity check failed: {0} pieces,'
            'piece_length {1}, sum of file lengths {2}.'.format(
            len(piece_hashes), piece_length, length_total))
      
      info_hash = cls.str_hash(benc_str_from_py(info))
      
      return cls(announce_urls=announce_urls, piece_length=piece_length, 
         piece_hashes=piece_hashes, files=files, info_hash=info_hash, 
         basename=basename, length_total=length_total,
         creation_ts=creation_ts, creator=creator, comment=comment, 
         dict_init = dict, *args, **kwargs)
      
   def trackers_get(self):
      return self.trackers
   
   @classmethod
   def build_from_benc_stream(cls, stream, *args, **kwargs):
      """Read one bencoded entity from stream, and try to build instance from it"""
      return cls.build_from_dict(py_from_benc_stream(stream), *args, **kwargs)

   @classmethod
   def build_from_benc_string(cls, string, *args, **kwargs):
      """Read first bencoded entity from string, and try to build instance from it"""
      return cls.build_from_dict(py_from_benc_str(string), *args, **kwargs)
   
   def __repr__(self):
      return '{0}({1})'.format(self.__class__.__name__, ', '.join(('{0}={1!a}'.format(field, getattr(self,field)) for field in self.fields)))

   def hr_format_lines(self):
      rv = []
      rv.append(self.hr_line_fmt_str.format('announce urls:', ' '.join((' '.join(ascii(u) for u in l) for l in self.announce_urls))))
      rv.append(self.hr_line_fmt_str.format('filenames:', ''))
      rv.append('\n'.join([' '*3 + repr(x.path) for x in self.files]))
      for (legend, name) in (
         ('piece length', 'piece_length'),
         ('total length', 'length_total'),
         ('creator', 'creator'),
         ('basename', 'basename')
         ):
         rv.append(self.hr_line_fmt_str.format(legend + ':', getattr(self, name)))
      
      for (legend, name) in (('comment', 'comment'),):
         rv.append(self.hr_line_fmt_repr.format(legend + ':', getattr(self, name)))
      
      rv.append(self.hr_line_fmt_str.format('info hash:', binascii.b2a_hex(self.info_hash)))
      try:
         cts = self.creation_ts
      except AttributeError:
         pass
      else:
         rv.append(self.hr_line_fmt_str.format('creation TS:', cts.isoformat()))
      
      rv.append(self.hr_line_fmt_str.format('piece count:', len(self.piece_hashes)))
      
      uk_fields_global = [f for f in self.dict_init if not (f in self.btmeta_known_fields_global)]
      uk_fields_info = [f for f in self.dict_init[b'info'] if not (f in self.btmeta_known_fields_info)]
      
      rv.append(self.hr_line_fmt_str.format('unknown fields:', uk_fields_global))
      rv.append(self.hr_line_fmt_str.format('unknown info fields:', uk_fields_info))
      
      return rv

class BTTargetFile:
   def __init__(self, path, length, md5sum=None):
      self.path = path
      self.length = length
      self.md5sum = md5sum
      self.file = None
   
   def __getstate__(self):
      rv = self.__dict__.copy()
      del(rv['file'])
      return rv
   
   def __setstate__(self, state):
      self.__dict__ = state
      self.file = None
   
   @classmethod
   def build_from_dict(cls, dict, file_single=False):
      if (file_single):
         path = dict[b'name']
      else:
         path = os.path.join(*dict[b'path'])
      
      if (b'md5sum' in dict):
         md5sum = dict[b'md5sum']
      else:
         md5sum = None
      if (len(path) < 1):
         raise ValueError('Dict {0!a} creates invalid path with file_single={1}.'.format(dict, file_single))
      
      return cls(path=path, length=dict[b'length'], md5sum=md5sum)
   
   def get_openness(self):
      return not (self.file is None)
   
   def file_open(self, basedir, bufsize=4096, mkdirs=True, mkfiles=True,
         lock_op=fcntl.LOCK_EX | fcntl.LOCK_NB):
      assert (self.file is None)
      path = os.path.normpath(os.path.join(basedir, self.path))
      ap = os.path.abspath(path)
      if not (ap.startswith(os.path.abspath(basedir))):
         raise BTClientError("Filepath {0!a} of {1} isn't safe to open.".format(path, self))
      
      pathdir = os.path.dirname(ap)
      if (not os.path.exists(pathdir)):
         os.makedirs(pathdir)
      if ((not mkfiles) or (os.path.exists(path))):
         # Note that there is a fundamental race condition here: if this file
         # is created by an external event before we do it, we'll truncate it.
         # OTOH, if there is any other process modifying the file in parallel
         # to us, the result likely won't be good even if things don't go wrong
         # on opening it.
         mode = 'r+b'
      else:
         mode = 'w+b'

      self.file = open(ap, mode, bufsize)
      self.file.seek(self.length-1)
      if (not self.file.peek(0)):
         self.file.write(b'\x00')
      self.file.seek(0)
      fcntl.lockf(self.file.fileno(), lock_op)
   
   def file_close(self):
      if not (self.file is None):
         fcntl.lockf(self.file.fileno(), fcntl.LOCK_UN)
         self.file.close()
         self.file = None
   
   def __repr__(self):
      return '{0}{1}'.format(self.__class__.__name__, (self.path, self.length, self.md5sum))
   

if (__name__ == '__main__'):
   import sys
   tf_name = sys.argv[1]
   tf = open(tf_name, 'rb')
   mi = BTMetaInfo.build_from_benc_stream(tf)

   print('\n'.join(mi.hr_format_lines()))

