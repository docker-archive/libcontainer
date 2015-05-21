# setup.py: setup script
#
# Copyright (C) 2014 Parallels, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see
# <http://www.gnu.org/licenses/>.

from distutils.core import setup, Extension

module1 = Extension('libct.libctcapi',
		sources=['libct/libctmodule.c'],
		include_dirs=['../src/include/uapi'],
		library_dirs=['..', '../.shipped/libnl/lib/.libs/'],
		libraries=['ct', 'nl-route-3', 'nl-3'])

setup(name='libct',
	version='0.1.0',
	description='A containers management library.',
	author='Dmitry Guryanov',
	author_email='dguryanov@parallels.com',
	packages=["libct"],
	ext_modules=[module1])
