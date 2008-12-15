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


class HRFormattableFloat(float):
   suffixes = ('', 'K', 'M', 'G', 'T', 'P', 'E')
   
   def format_hr(self, base=1024, limit=1536, precision=2):
      """Format number as float with appropriate suffix"""
      v = float(self)
      i = 0
      max_i = len(self.suffixes) - 1
      while ((i < max_i) and (v > limit)):
         v /= base
         i += 1
      
      return '{1:.{0}f}{2}'.format(precision, v, self.suffixes[i])

