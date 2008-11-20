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

import cPickle
import os.path

class FileNamePickler:
   """Dump pickle data to a file whose name is specified at instantiation.
      This will dump the data to a temporary file, and then rename it to the
      desired filename, to avoid losing data in case of an interrupted
      pickling."""
   tmp_suffix = '.tmp'
   def __init__(self, filename):
      self.filename = os.path.abspath(filename)
      self.filename_tmp = self.filename + self.tmp_suffix
      
   def __call__(self, data, *args, **kwargs):
      """Pickle specified data to backing file"""
      f = file(self.filename_tmp, 'wb')
      cPickle.dump(data, f, *args, **kwargs)
      f.close()
      os.rename(self.filename_tmp, self.filename)
