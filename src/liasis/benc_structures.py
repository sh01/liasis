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


# Some basic BT data structures, based on information from
# <http://www.bittorrent.org/protocol.html> and
# <http://wiki.theory.org/BitTorrentSpecification>

import struct
import sha
import random
import cStringIO
import datetime
import os.path
import fcntl
import binascii

from bt_exceptions import BTClientError

import address_structures


def py_from_benc_stream(stream):
   """Read and return one entity from a stream containing bencoded data"""
   next_byte = stream.read(1)
   if (next_byte.isdigit()):
      # string
      digit_str = ''
      while (next_byte.isdigit()):
         digit_str += next_byte
         next_byte = stream.read(1)
      if (next_byte != ':'):
         raise ValueError('string length followed by %r, expected ":".' % (next_byte,))
      else:
         str_len = int(digit_str)
         rv = stream.read(str_len)
         assert (len(rv) == str_len)
         return rv
   
   if (next_byte == 'i'):
      # integer
      digit_str = ''
      next_byte = stream.read(1)
      if (next_byte == '-'):
         digit_str += next_byte
         next_byte = stream.read(1)

      while (next_byte.isdigit()):
         digit_str += next_byte
         next_byte = stream.read(1)
      if (next_byte != 'e'):
         raise ValueError('integer digit sequence followed by %r, expected "e".' % (next_byte,))
      if (digit_str.startswith('-0')):
         raise ValueError('integer digitstring %r is invalid' % (digit_str,))
      if (digit_str.startswith('0') and (len(digit_str) != 1)):
         raise ValueError('integer digitstring %r starts with 0 and has length > 0' % (digit_str,))
      
      if (digit_str == ''):
         # Edge case. The official spec doesn't state that this is invalid.
         return 0
      return int(digit_str)
   
   if (next_byte == 'l'):
      # list
      rv = []
      next_byte = stream.read(1)
      while (next_byte != 'e'):
         stream.seek(-1,1)
         rv.append(py_from_benc_stream(stream))
         next_byte = stream.read(1)
      return rv
      
   if (next_byte == 'd'):
      # dictionary
      rv = {}
      next_byte = stream.read(1)
      while (next_byte != 'e'):
         stream.seek(-1,1)
         key = py_from_benc_stream(stream)
         value = py_from_benc_stream(stream)
         rv[key] = value
         next_byte = stream.read(1)
      return rv

   raise ValueError('Unable to interpret initial chunk byte %r.' % (next_byte,))


def py_from_benc_str(string):
   """Read and return one entity from a string containing bencoded data"""
   return py_from_benc_stream(cStringIO.StringIO(string))


def benc_str_from_py(obj):
   """Encode a python dict/list/str/int structure in a bencoded string"""
   if (isinstance(obj, basestring)):
      return '%d:%s' % (len(obj), obj)
   if (isinstance(obj, int) or isinstance(obj,long)):
      return 'i%de' % (obj,)
   if (isinstance(obj, list) or isinstance(obj, tuple)):
      return 'l%se' % (''.join([benc_str_from_py(e) for e in obj]),)
   if (isinstance(obj, dict)):
      keys = obj.keys()
      keys.sort()
      return 'd%se' % ''.join(['%s%s' % (benc_str_from_py(key), benc_str_from_py(obj[key])) for key in keys])


class BTPeer:
   def __init__(self, ip, port, peer_id):
      self.ip = address_structures.ip_make(ip)
      self.port = port
      self.peer_id = peer_id
      
   @classmethod
   def build_from_str(cls, string):
      (iplong, port) = struct.unpack('>IH', string)
      return cls(iplong, port, None)
   
   def state_get(self):
      """Summarize internal state using nested dicts, lists, ints and strings"""
      state = {
         'ip': long(self.ip),
         'port': self.port,
      }
      if not (self.peer_id is None):
         state['peer id'] = self.peer_id
      
      return state
   
   @classmethod
   def build_from_dict(cls, dict):
      if ('peer id' in dict):
         peer_id = dict['peer id']
      else:
         peer_id = None
      return cls(ip = dict['ip'], port = dict['port'], 
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
      if (isinstance(seq,basestring)):
         assert ((len(seq) % 6) == 0)
         rv = tuple([cls.build_from_str(seq[i:i+6]) for i in range(0,len(seq),6)])
      elif (isinstance(seq, list) or isinstance(seq, tuple)):
         rv = tuple([cls.build_from_dict(dict) for dict in seq])
      else:
         raise TypeError('Unable to process argument %r of type %r; expected string or list/tuple.' % (seq, type(seq)))

      return rv
   
   def address_get(self):
      return (self.ip, self.port)
   
   def __repr__(self):
      return '%s%r' % (self.__class__.__name__, (self.ip, self.port, self.peer_id))
   
   def __str__(self):
      return '%s%r' % (self.__class__.__name__, (str(self.ip), self.port, self.peer_id))


class BTMetaInfo:
   """Bt Metainfo file structure"""
   fields = ('announce_urls', 'piece_length', 'piece_hashes', 'files',
      'info_hash', 'basename', 'length_total', 'creation_ts', 'dict_init',
      'creator', 'comment')
   hash_helper = sha.sha
   
   btmeta_known_fields_global = set(('announce-list', 'announce', 'creation date', 'created by', 'comment', 'info'))
   btmeta_known_fields_info = set(('piece length', 'pieces', 'length', 'name', 'path', 'md5sum', 'length', 'files'))

   hr_line_fmt_str = '%20s %s'
   hr_line_fmt_repr = '%20s %r'
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
      if ('announce-list' in dict):
         announce_urls = dict['announce-list']
      else:
         announce_urls = [[dict['announce']]]
      if ('creation date' in dict):
         creation_ts = datetime.datetime.fromtimestamp(dict['creation date'])
      else:
         creation_ts = None
      if ('created by' in dict):
         creator = dict['created by']
      else:
         creator = None
      if ('comment' in dict):
         comment = dict['comment']
      else:
         comment = None
      
      info = dict['info']
      
      piece_length = info['piece length']
      pieces_str_length = len(info['pieces'])
      pieces_str = info['pieces']
      if ((pieces_str_length % 20) != 0):
         raise ValueError('info->pieces length %d is not a multiple of 20' % (pieces_str_length,))
      piece_hashes = [pieces_str[i:i+20] for i in range(0,pieces_str_length,20)]
      
      if ('length' in info):
         files = [BTTargetFile.build_from_dict(info, file_single=True)]
         basename = ''
      else:
         files = [BTTargetFile.build_from_dict(d, file_single=False) for d in info['files']]
         basename = info['name']
      
      length_total = sum([btfile.length for btfile in files])
      
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
      return '%s(%s)' % (self.__class__.__name__, ', '.join(['%s=%r' % (field, getattr(self,field)) for field in self.fields]))

   def hr_format_lines(self):
      rv = []
      rv.append(self.hr_line_fmt_str % ('announce urls:', ' '.join([' '.join(sublist) for sublist in self.announce_urls])))
      rv.append(self.hr_line_fmt_str % ('filenames:', ''))
      rv.append('\n'.join([' '*3 + repr(x.path) for x in self.files]))
      for (legend, name) in (
         ('piece length', 'piece_length'),
         ('total length', 'length_total'),
         ('creator', 'creator'),
         ('basename', 'basename')
         ):
         rv.append(self.hr_line_fmt_str % (legend + ':', getattr(self, name)))
      
      for (legend, name) in (('comment', 'comment'),):
         rv.append(self.hr_line_fmt_repr % (legend + ':', getattr(self, name)))
      
      rv.append(self.hr_line_fmt_str % ('info hash:', binascii.b2a_hex(self.info_hash)))
      try:
         cts = self.creation_ts
      except AttributeError:
         pass
      else:
         rv.append(self.hr_line_fmt_str % ('creation TS:', cts.isoformat()))
      
      rv.append(self.hr_line_fmt_str % ('piece count:', len(self.piece_hashes)))
      
      uk_fields_global = [f for f in self.dict_init if not (f in self.btmeta_known_fields_global)]
      uk_fields_info = [f for f in self.dict_init['info'] if not (f in self.btmeta_known_fields_info)]
      
      rv.append(self.hr_line_fmt_str % ('unknown fields:', uk_fields_global))
      rv.append(self.hr_line_fmt_str % ('unknown info fields:', uk_fields_info))
      
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
         path = dict['name']
      else:
         path = os.path.join(*dict['path'])
      
      if ('md5sum' in dict):
         md5sum = dict['md5sum']
      else:
         md5sum = None
      if (len(path) < 1):
         raise ValueError('Dict %r creates invalid path with file_single=%s.' % (dict, file_single))
      
      return cls(path=path, length=dict['length'], md5sum=md5sum)
   
   def get_openness(self):
      return not (self.file is None)
   
   def file_open(self, basedir, bufsize=1024, mkdirs=True, lock_op=fcntl.LOCK_EX | fcntl.LOCK_NB):
      assert (self.file is None)
      path = os.path.normpath(os.path.join(basedir, self.path))
      if not (os.path.abspath(path).startswith(os.path.abspath(basedir))):
         raise BTClientError("Filepath %r of %s isn't safe to open." % (path, self))
      
      pathdir = os.path.dirname(path)
      if (not os.path.exists(pathdir)):
         os.makedirs(pathdir)
      if (os.path.exists(path)):
         # Note that there is a fundamental race condition here: if this file
         # is created by an external event before we do it, we'll truncate it.
         # OTOH, if there is any other process modifying the file in parallel
         # to us, the result likely won't be good even if things don't go wrong
         # on opening it.
         mode = 'r+b'
      else:
         mode = 'w+b'

      self.file = file(path, mode, bufsize)
      fcntl.lockf(self.file.fileno(), lock_op)
   
   def file_close(self):
      if not (self.file is None):
         fcntl.lockf(self.file.fileno(), fcntl.LOCK_UN)
         self.file.close()
         self.file = None
   
   def __repr__(self):
      return '%s%s' % (self.__class__.__name__, (self.path, self.length, self.md5sum))
   

if (__name__ == '__main__'):
   import sys
   tf_name = sys.argv[1]
   tf = file(tf_name)
   mi = BTMetaInfo.build_from_benc_stream(tf)

   print '\n'.join(mi.hr_format_lines())

