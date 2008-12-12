#!/usr/bin/env python
#Copyright 2008 Sebastian Hagen
# This file is part of liasis.

# liasis is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation
#
# liasis is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
from distutils.core import setup

#if (sys.version_info[0] <= 2):
#   raise Exception('This liasis version needs a python >= 3.0')


setup(name='liasis',
   version='0.1',
   description='Liasis: Yet another bittorrent client',
   author='Sebastian Hagen',
   author_email='sebastian_hagen@memespace.net',
   url='http://git.memespace.net/git/liasis.git',
   packages=('liasis', 'liasis.client_qt'),
   scripts=(
      'src/tools/liasis_client_arg',
      'src/tools/liasis_client_qt',
      'src/tools/liasis_daemon',
      'src/tools/liasis_metainfo_print',
      'src/tools/liasis_tool_scrape'
   ),
   package_dir={'liasis':'src/liasis'}
)

