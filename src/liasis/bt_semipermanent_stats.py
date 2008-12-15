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

"""Classes for keeping long-term statistics on finished torrents"""

class BTStatsTracker:
   """Long-term BTH stats keeping class"""
   def __init__(self):
      self.content_bytes_out = 0
      self.content_bytes_in = 0
      self.torrents_started = 0
      self.torrents_finished = 0

   def bth_process(self, bth):
      """Extract data from bth and add to stats
      
      This should be called exactly once for each bth, when it is dropped from
      the bth list."""
      cbo = bth.content_bytes_out
      cbi = bth.content_bytes_in
      if not (isinstance(cbo, int) and isinstance(cbi, int)):
         raise TypeError('Type of cbo={0!a} or cbi={1!a} is invalid'.format(cbo,cbi))
      
      if not ((0 <= cbo) and (0 <= cbi)):
         raise ValueError('Value of cbo={0!a} or cbi={1!a} is invalid'.format(cbo,cbi))
      
      self.content_bytes_out += cbo
      self.content_bytes_in += cbi
      
      if (bth.download_complete):
         self.torrents_finished += 1
      self.torrents_started += 1
      
