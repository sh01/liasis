#!/usr/bin/env python
#Copyright 2009 Sebastian Hagen
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

from hashlib import sha1
from collections import deque
import logging
import os
import socket

from gonium.fdm.stream import AsyncPopen, AsyncSockServer, AsyncLineStream

from liasis.benc_structures import BTMetaInfo, benc_str_from_py
from liasis.cc_client import BTControlConnectionClientGonium

def _copyfile(f1, f2, length):
   bufsize = 1024*1024
   rem = length
   while (rem):
      data = f1.read(min((bufsize, rem)))
      if (len(data) == 0):
         break
      rem -= len(data)
      f2.write(data)


class HashBuilder:
   def __init__(self, piece_len):
      self.piece_len = piece_len
      self.i = 0
      self.h = sha1()
      self.digests = deque()
   
   def add_file(self, fl):
      fl.seek(0)
      rem = self.piece_len - self.i
      while (1):
         data = fl.read(rem)
         self.h.update(data)
         if (len(data) != rem):
            self.i += len(data)
            break
         
         self.digests.append(self.h.digest())
         self.h = sha1()
         
         self.i = 0
         rem = self.piece_len
   
   def finish(self):
      if (self.i):
         self.digests.append(self.h.digest())
      self.h = None
      self.i = None

class _lbcccg(BTControlConnectionClientGonium):
   pass

class Tester:
   logger = logging.getLogger('liasis.test.daemon.Tester')
   log = logger.log
   cfs_name = b'liasis_test.conf.sock'
   conf_fmt = 'import sys; import socket; btm_config.control_socket_af = socket.AF_UNIX; btm_config.control_socket_address = {csaddr!a}; btc_config.port = {port}; btc_config.host = ""; btc_config.data_basepath = {data_basepath!a}'
   intermediate_ddname = b'test_data_set'
   http_prefix = b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/plain\r\n\r\n'
   
   piece_length = 1361
   dfile_lens = (piece_length-5,0,0,0,1,piece_length*50,4,piece_length*50,0,0,132)
   
   config_argsets = (
      (0, b'data_1', 'liasis_test.ctl.1'),
      (0, b'data_2', 'liasis_test.ctl.2')
   )
   
   def __init__(self, ed, daemon_binpath):
      self.ed = ed
      self.aps = deque()
      self.ccs = deque()
      self.mi = None
      self.tport = None
      self.tracker = None
      self.peer_data = set()
      self.daemon_binpath = daemon_binpath
      self._standalone = False
      self._shutting_down = False
   
   def run_tests(self):
      self._daemons_start()
      self._tracker_start()
      self._data_prepare()
      self._daemons_prime()
   
   def shutdown(self):
      if (self._shutting_down):
         return
      self.log(20, '{0!a} shutting down.'.format(self))
      self._shutting_down = True
      for ap in self.aps:
         for name in ('stdin', 'stdout', 'stderr'):
            name += '_async'
            if not (hasattr(ap,name)):
               continue
            stream = getattr(ap,name)
            if (not stream):
               continue
            stream.close()
      for cc in self.ccs:
         cc.close()
      
      if (self._standalone):
         self.ed.shutdown()
   
   @classmethod
   def run_standalone(cls, *args, **kwargs):
      from gonium.fdm.ed import ED_get
      ed = ED_get()()
      self = cls(ed, *args, **kwargs)
      self.run_tests()
      self._standalone = True
      ed.event_loop()
   
   def _cc_process_COMMANDFAIL(self, cmd, args):
      self.log(40, 'Got COMMANDFAIL on cc: {1!a}'.format(cmd,args))
   
   def _make_config(self, port, data_basepath, csaddr):
      return self.conf_fmt.format(**vars()).encode('ascii')
   
   def _process_in(self, line, i):
      self.log(20, 'TSO({0}): {1}'.format(i, bytes(line).decode().rstrip()))
   
   def _get_tracker_url(self):
      return 'http://127.0.0.1:{0}'.format(self.tport).encode('ascii')
   
   @staticmethod
   def _parse_uer(ued):
      from urllib.request import unquote, splitvalue
      data = ued.decode('utf-8', 'surrogateescape')
      data_l = data.split('&')
      rv = {}
      for e in data_l:
         (key,vu) = splitvalue(e)
         rv[key.encode('ascii')] = unquote(vu).encode('utf-8', 'surrogateescape')
      
      for key in (b'port',):
         if not (key in rv):
            continue
         rv[key] = int(rv[key])
      return rv
   
   def _t_build_http_response(self):
      body = benc_str_from_py(self._t_build_response())
      return (self.http_prefix + body)
   
   def _t_build_response(self):
      peers = [{b'peer id': peer_id, b'ip':b'127.0.0.1', b'port':port} for (port, peer_id) in self.peer_data]
      
      rv = {
         b'interval':86400,
         b'complete':1,
         b'incomplete':0,
         b'peers':peers
      }
      return rv
   
   def _t_process_connect(self, sock, addrinfo):
      self.log(20, 'Got connection from {0}.'.format(addrinfo))
      import time; time.sleep(1)
      data = sock.recv(102400)
      data_ue = data.split(b'?',1)[1].split(b' ',1)[0]
      dd = self._parse_uer(data_ue)
      response = self._t_build_http_response()
      sock.sendall(response)
      self.peer_data.add((dd[b'port'], dd[b'peer_id']))
   
   def _tracker_start(self):
      if not (self.tracker is None):
         raise Exception()
      self.tracker = AsyncSockServer(self.ed, ('',0))
      self.tport = self.tracker.sock.getsockname()[1]
      self.tracker.connect_process = self._t_process_connect
   
   def _data_prepare(self):
      if not (self.mi is None):
         raise Exception()
      
      self.log(20, 'Preparing data to transfer and generating metainfo.')
      rf = open('/dev/urandom','rb')
      hb = HashBuilder(self.piece_length)
      
      for cas in self.config_argsets:
         datadir = cas[1]
         if not (os.path.isdir(datadir)):
            os.mkdir(datadir)
         dd_intermediate = os.path.join(datadir, self.intermediate_ddname)
         if not (os.path.isdir(dd_intermediate)):
            os.mkdir(dd_intermediate)
      
      src_dd = self.config_argsets[0][1]
      
      i = 0
      file_dicts = deque()
      dfns = deque()
      for dfl in self.dfile_lens:
         dfn = str(i).encode('ascii')
         pn = os.path.join(src_dd, self.intermediate_ddname, dfn)
         df = open(pn, 'w+b')
         _copyfile(rf, df, dfl)
         hb.add_file(df)
         df.close()
         dfns.append(pn)
         file_dicts.append({b'length':dfl, b'path':[dfn]})
         i += 1
      
      hb.finish()
      rf.close()
      
      mi = BTMetaInfo.build_from_dict({
         b'announce':self._get_tracker_url(),
         b'info':{
            b'name':self.intermediate_ddname,
            b'piece length':self.piece_length,
            b'pieces':b''.join(hb.digests),
            b'files':list(file_dicts)
         }
      })
      self.mi = mi
   
   def _daemons_start(self):
      import time
      from stat import S_ISFIFO
      from subprocess import PIPE
      try:
         os.mkfifo(self.cfs_name.decode())
      except OSError:
         if not (S_ISFIFO(os.stat(self.cfs_name).st_mode)):
            raise
      
      self.log(20, 'Starting liasis daemons ...')
      i = 0
      for cas in self.config_argsets:
         cdata = self._make_config(*cas)
         ap = AsyncPopen(self.ed, (self.daemon_binpath, b'--ssm',
            self.cfs_name), stream_factory=AsyncLineStream,
            stdin=PIPE, stdout=PIPE, stderr=PIPE)
         
         self.aps.append(ap)
         
         def make_cb(i):
            def cb(line):
               self._process_in(line, i)
            return cb
         
         cb = make_cb(i)
         
         ap.stdout_async.process_input = cb
         ap.stderr_async.process_input = cb
         
         sf = open(self.cfs_name, 'wb')
         sf.write(cdata)
         sf.flush()
         sf.close()
         i += 1
         time.sleep(1)
      
   def _daemons_prime(self):
      mi_bytes = self.mi.build_benc_string()
      
      for cas in self.config_argsets:
         ctl_sockname = cas[2]
         self.log(20, 'Sending MI to {0!a}.'.format(ctl_sockname))
         cc = _lbcccg.build_sock_connect(self.ed, ctl_sockname,
            family=socket.AF_UNIX)
         cc.bth_add_from_metainfo(0, mi_bytes, True)
         cc.input_process_COMMANDFAIL = self._cc_process_COMMANDFAIL
         self.ccs.append(cc)
         cc.process_close = self.shutdown

