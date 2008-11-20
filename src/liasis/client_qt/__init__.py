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

import sys
import socket
import binascii

from PyQt4.QtCore import QObject, QAbstractItemModel, QModelIndex, Qt, QVariant, SIGNAL, SLOT
from PyQt4.QtGui import QApplication, QMainWindow, QIcon
from gonium.fd_management.event_dispatcher_qt import EventDispatcherQT

from liasis.cc_client import BTControlConnectionClientGonium, ThroughputCounter
from liasis.hr_data_formatting import HRFormattableFloat
from ui import Ui_main_window

QT_ROLE_DISPLAY = Qt.DisplayRole
QT_ROLE_STATUSTIP = Qt.StatusTipRole
QT_ROLE_WHATSTHIS = Qt.WhatsThisRole

connect = QObject.connect
disconnect = QObject.disconnect


def bandwith_avg(data):
   data = [d for d in data if not (d is None)]
   if (len(data) == 0):
      return None
   return 1.0*sum(data) / len(data)

def curry_last(callee, last_arg):
   def rv(*args, **kwargs):
      args += (last_arg,)
      return callee(*args, **kwargs)
   return rv


class Column:
   """Column to display"""
   __slots__ = ('desc', 'index', 'tp_col')
   def __init__(self, desc, index, tp_col):
      self.desc = desc
      self.index = index
      self.tp_col = tp_col

class ColumnList:
   """List of columns to display"""
   def __init__(self):
      self.column_order = []
      self.column_data = {}
      self.tp_col_min = None
      self.tp_col_max = None
   
   def column_add(self, name, desc, tp_col=False):
      """Add column to list"""
      if (name in self.column_order):
         self.column_order.remove(name)
      self.column_order.append(name)
      index = len(self.column_order) - 1
      self.column_data[name] = Column(desc, index, tp_col)
      self.state_update()
   
   def state_update(self):
      """Update summarizing variables"""
      tp_cols = []
      for col in self.column_data.values():
         if (col.tp_col):
            tp_cols.append(col.index)
      
      if (tp_cols == []):
         self.tp_col_min = self.tp_col_max = None
      else:
         self.tp_col_min = min(tp_cols)
         self.tp_col_max = max(tp_cols)
      
   def __getitem__(self, key):
      if (isinstance(key, int) or isinstance(key, long)):
         return self.column_data[self.column_order[key]]
      return self.column_data[key]
   
   def __len__(self):
      return len(self.column_order)

   def index(self, name):
      return self.column_data[name].index

cl_default = ColumnList()
cl_default.column_add('BASENAME', 'basename')
cl_default.column_add('DATA_SIZE', 'size')
cl_default.column_add('DATA_COMPLETED', 'completed')
cl_default.column_add('DATA_REMAINING', 'left')
cl_default.column_add('DATA_UPLOADED', 'uploaded')
cl_default.column_add('PROGRESS_TEXT', 'progress')
cl_default.column_add('SR', 'sr')
cl_default.column_add('DOWNSTREAM_100', 'ds100', tp_col=True)
cl_default.column_add('UPSTREAM_100', 'us100', tp_col=True)
cl_default.column_add('INFOHASH', 'info hash')


class BTHandlerMirrorFormatter(BTControlConnectionClientGonium.bthm_cls):
   def __init__(self, *args, **kwargs):
      BTControlConnectionClientGonium.bthm_cls.__init__(self, *args, **kwargs)
   
   def format_display_basename(self):
      """Format basename of this element"""
      return self.target_basename_get()
   
   def format_display_infohash(self):
      """Format infohash of this element"""
      return binascii.b2a_hex(self.metainfo.info_hash)

   def format_bandwith_downstream(self, count):
      """Format recorded downstream over last <count> seconds"""
      tpa = bandwith_avg(self.bandwith_logger_in[-count:])
      if (tpa is None):
         return None
      return '%.2f' % (tpa/1024.0,)

   def format_bandwith_upstream(self, count):
      """Format recorded upstream over last <count> seconds"""
      tpa = bandwith_avg(self.bandwith_logger_out[-count:])
      if (tpa is None):
         return None
      return '%.2f' % (tpa/1024.0,)
   
   def format_display_progress(self):
      """Return formatted textual progress report"""
      if (self.piece_count == 0):
         return '100%'
      
      return '%.3f%%' % (100*(self.pieces_have_count/self.piece_count))
   
   def format_display_data_size(self):
      """Format total size of data"""
      return HRFormattableFloat(self.metainfo.length_total).format_hr() + 'b'
   
   def format_display_data_completed(self):
      """Format size of downloaded and verified data"""
      # This isn't quite correct if we have the last piece. Difference should
      # be epsilon, though.
      return '%s (%s)' % (
         HRFormattableFloat(self.pieces_have_count*self.metainfo.piece_length).format_hr() + 'b',
         HRFormattableFloat(self.content_bytes_in).format_hr() + 'b')
   
   def format_display_data_remaining(self):
      """Format amount of remaining data"""
      return HRFormattableFloat(self.bytes_left).format_hr() + 'b'
   
   def format_display_data_uploaded(self):
      """Format amound of uploaded data"""
      upload = self.content_bytes_out + sum([c.content_bytes_out for c in self.peer_connections])
      return HRFormattableFloat(upload).format_hr() + 'b'
   
   def format_display_sr(self):
      """Format Share Ratio"""
      if (self.content_bytes_in == 0):
         return 'undef'
      else:
         return '%.3f' % (float(self.content_bytes_out)/self.content_bytes_in,)
   
   def format_display(self, col):
      """Format specified column entry of this element"""
      return self.FORMATTERS_DISPLAY[col](self)

   def row_count_return(self):
      return 0

   FORMATTERS_DISPLAY = {
      cl_default.index('BASENAME'):format_display_basename,
      cl_default.index('DATA_SIZE'):format_display_data_size,
      cl_default.index('DATA_COMPLETED'):format_display_data_completed,
      cl_default.index('DATA_REMAINING'):format_display_data_remaining,
      cl_default.index('DATA_UPLOADED'):format_display_data_uploaded,
      cl_default.index('PROGRESS_TEXT'):format_display_progress,
      cl_default.index('SR'):format_display_sr,
      cl_default.index('INFOHASH'):format_display_infohash,
      cl_default.index('DOWNSTREAM_100'):curry_last(format_bandwith_downstream, 100),
      cl_default.index('UPSTREAM_100'):curry_last(format_bandwith_upstream, 100)
   }


class BTClientMirrorFormatter(BTControlConnectionClientGonium.btcm_cls):
   bthm_cls = BTHandlerMirrorFormatter
   td_fmt = '%.2f'
   
   def __init__(self, *args, **kwargs):
      BTControlConnectionClientGonium.btcm_cls.__init__(self, *args, **kwargs)
      self.rows = []
      for val in self.torrents.values():
         self.rows.append(val)
      
   def row_count_return(self):
      """Return count of children"""
      return len(self.rows)

   def row_element_get(self, row):
      """Return specified child"""
      return self.rows[row]

   def format_bandwith_downstream(self, count):
      """Format recorded downstream over last <count> seconds"""
      tp_averages = []
      for bth in self.rows:
         avg = bandwith_avg(bth.bandwith_logger_in[-count:])
         if not (avg is None):
            tp_averages.append(avg)
         
      td_down = sum(tp_averages)/1024.0
      return self.td_fmt % (td_down,)
      
   def format_bandwith_upstream(self, count):
      """Format recorded upstream over last <count> seconds"""
      tp_averages = []
      for bth in self.rows:
         avg = bandwith_avg(bth.bandwith_logger_out[-count:])
         if not (avg is None):
            tp_averages.append(avg)
         
      td_up = sum(tp_averages)/1024.0
      return self.td_fmt % (td_up,)

   def format_display_basename(self):
      """Format basic client id string"""
      host = self.host
      if (host == ''):
         host = '*'
      return 'Client (%s:%d)' % (host, self.port)

   def format_display(self, col):
      """Format specified column entry of this element"""
      if (col in self.FORMATTERS_DISPLAY):
         return self.FORMATTERS_DISPLAY[col](self)
      else:
         return ''

   FORMATTERS_DISPLAY = {
      cl_default.index('BASENAME'):format_display_basename,
      cl_default.index('DOWNSTREAM_100'):curry_last(format_bandwith_downstream, 100),
      cl_default.index('UPSTREAM_100'):curry_last(format_bandwith_upstream, 100)
   }

class BTCCGQT(BTControlConnectionClientGonium, ThroughputCounter):
   btcm_cls = BTClientMirrorFormatter
   bthm_cls = BTHandlerMirrorFormatter
   TP_DISPLAY_DELAY = 10
   
   def __init__(self, event_dispatcher, parent):
      BTControlConnectionClientGonium.__init__(self, event_dispatcher)
      ThroughputCounter.__init__(self)
      self.parent = parent
      self.em_utd_change_true.EventListener(self.utd_change_true_process)
      self.em_throughput_block.EventListener(self.throughput_block_note)
      self.em_throughput_slice.EventListener(self.throughput_slice_note)
      self.tp_display_stale = False
      self.tp_display_timer = self.event_dispatcher.Timer(
         self.TP_DISPLAY_DELAY, self.throughput_display_update, 
         persistence=True)

   def utd_change_true_process(self, listener):
      """Process change in our up-to-date status"""
      self.parent.tlm.torrent_data_update(self.bt_clients)
   
   def throughput_slice_note(self, listener, client_idx, *args, **kwargs):
      """Note reception of throughput data slice"""
      self.tp_display_stale = True
      
   def throughput_block_note(self, listener, btc_idx, *args, **kwargs):
      """Note reception of throughput data block"""
      self.parent.tlm.throughput_redisplay(btc_idx)
      self.tp_display_stale = True
   
   def throughput_display_update(self):
      """Update displayed throughput data, if stale"""
      if (self.tp_display_stale):
         for btc_idx in range(len(self.bt_clients)):
            self.parent.tlm.throughput_redisplay(btc_idx)
         self.tp_display_stale = False

   def clean_up(self):
      """Close fds and cancel timers"""
      BTControlConnectionClientGonium.clean_up()
      if (self.tp_display_timer):
         self.tp_display_timer.stop()
         self.tp_display_timer = None

class ModelIndexProxy:
   """Helper class for Model implementation"""
   def __init__(self, data, mip_parent, subrow, subcol):
      self.data = data
      self.mip_parent = mip_parent
      self.subrow = subrow
      self.subcol = subcol

   def __eq__(self, other):
      return (self.data == other.data)
   
   def __neq__(self, other):
      return (self.data != other.data)
   
   def __hash__(self):
      return hash(self.data)


class TorrentListModel(QAbstractItemModel):
   """Model to be used by tree-view torrent list
   
   This is fairly ugly since the QT code can take pointers to python objects
   and pass them back to us, but will not modify their refcounts. So, we have
   to keep them reachable ourselves, too."""
   
   def __init__(self, *args):
      QAbstractItemModel.__init__(self, *args) # doesn't support **kwargs, even if empty
      self.bt_clients = []
      self.mips = {}
   
   def mip_build(self, *args, **kwargs):
      """Return MIP for specified constructor args and kwargs"""
      mip = ModelIndexProxy(*args, **kwargs)
      if (mip in self.mips):
         return self.mips[mip]
      self.mips[mip] = mip
      return mip

# --------------------------------------------------------- QT model interface
   def index(self, row, col, parent):
      """QT4 QAbstractItemModel interface function"""
      mip = parent.internalPointer()
      if (mip is None):
         if (self.bt_clients == []):
            return self.createIndex(row, col, None)
         return self.createIndex(row, col, self.mip_build(self.bt_clients[row], None, row, col))
      else:
         return self.createIndex(row, col, self.mip_build(mip.data.row_element_get(row), mip, row, col))
   
   def parent(self, index):
      """QT4 QAbstractItemModel interface function"""
      mip = index.internalPointer()
      if ((mip is None) or (mip.mip_parent is None)):
         return QModelIndex()
      return self.createIndex(mip.subrow, mip.subcol, mip.mip_parent)
   
   def rowCount(self, parent):
      """QT4 QAbstractItemModel interface function"""
      mip = parent.internalPointer()
      if (mip is None):
         return len(self.bt_clients)
      else:
         return mip.data.row_count_return()
   
   def headerData(self, col, orientation, role):
      """QT4 QAbstractItemModel interface function"""
      if (role == QT_ROLE_DISPLAY):
         return QVariant(cl_default[col].desc)
      return QVariant()
   
   def columnCount(self, parent):
      """QT4 QAbstractItemModel interface function"""
      return len(cl_default)
   
   def data(self, index, role):
      """QT4 QAbstractItemModel interface function"""
      mip = index.internalPointer()
      if (role == QT_ROLE_DISPLAY):
         return QVariant(str(mip.data.format_display(index.column())))
      return QVariant()

# --------------------------------------------------------- qt_client interface
   def torrent_data_update(self, bt_clients):
      """Replace btc list with specified object and redisplay data."""
      self.emit(SIGNAL('modelAboutToBeReset()'))
      self.bt_clients = bt_clients
      self.mips = {}
      self.emit(SIGNAL('modelReset()'))
   
   def throughput_redisplay(self, btc_idx):
      """Redisplay throughput of BTHs of specified BTC"""
      try:
         btc = self.bt_clients[btc_idx]
      except IndexError:
         raise ValueError('btc_idx %r is invalid' % (btc_idx,))

      mi_btc = self.index(btc_idx, 0, QModelIndex())
      mi_topleft = self.index(0, cl_default.tp_col_min, mi_btc)
      mi_bottomright = self.index(btc.row_count_return()-1, cl_default.tp_col_max, mi_btc)
      
      mi_btc_tl = self.index(btc_idx, cl_default.tp_col_min, QModelIndex())
      mi_btc_br = self.index(btc_idx, cl_default.tp_col_max, QModelIndex())
      self.emit(SIGNAL('dataChanged(const QModelIndex&,const QModelIndex&)'), mi_topleft, mi_bottomright)
      self.emit(SIGNAL('dataChanged(const QModelIndex&,const QModelIndex&)'), mi_btc_tl, mi_btc_br)


class ClientMain:
   def __init__(self, event_dispatcher, sock_AF, sock_path):
      self.event_dispatcher = event_dispatcher
      self.sock_AF = sock_AF
      self.sock_path = sock_path
      self.connection_init()
      
      self.main_window = main_window = QMainWindow()
      self.main_window.show()
      self.main_window.setWindowIcon(QIcon("/usr/share/icons/nuvola/128x128/filesystems/network.png")) # FIXME: put this somewhere liasis-specific
      self.ui = Ui_main_window()
      self.ui.setupUi(main_window)
      self.tlm = TorrentListModel()
      self.ui.torrent_list.setModel(self.tlm)

   def connection_init(self):
      self.sock = self.event_dispatcher.BTCCGQT(self)
      self.sock.connection_init(self.sock_path, self.sock_AF)
      self.sock.data_update()

   @classmethod
   def run_standalone(cls, *args):
      """Execute this client in a blocking fashion"""
      qtapp = QApplication(sys.argv)
      ed = EventDispatcherQT()
      cm = cls(ed, *args)
      
      ed.event_loop(qtapp)


if (__name__ == '__main__'):
   ClientMain.run_standalone(socket.AF_UNIX, "liasis_ctl.sock")

