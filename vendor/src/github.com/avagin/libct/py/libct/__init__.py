# __init__.py: python classes for libct
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

import types

import libctcapi

consts = libctcapi.consts
errors = libctcapi.errors

class LibctError(Exception):
	def __init__(self, value):
		if type(value) in types.StringTypes:
			self.descr = value
		else:
			errs = filter(lambda x: x.startswith("LCTERR_"), dir(errors))
			for err in errs:
				if value == getattr(errors, err):
					self.descr = err
					break
			else:
				self.descr = "libct error %r" % value

	def __str__(self):
		return self.descr

class Session(object):

	def __init__(self, sess):
		self._sess = sess

	def close(self):
		libctcapi.session_close(self._sess)

	def container_create(self, name):
		ct = libctcapi.container_create(self._sess, name)
		if type(ct) != types.LongType:
			return Container(ct)
		else:
			raise LibctError(ct)

	def container_open(self, name):
		ct = libctcapi.container_open(self._sess, name)
		if type(ct) != types.LongType:
			return Container(ct)
		else:
			raise LibctError(ct)

def open(url):
	sess = libctcapi.session_open(url)
	if type(sess) != types.LongType:
		return Session(sess)
	else:
		raise LibctError(sess)

class Container(object):

	def __init__(self, ct):
		self._ct = ct

	def close(self):
		libctcapi.container_close(self._ct)

	def state(self):
		state = libctcapi.container_state(self._ct)
		return state

	def spawn_cb(self, cb, arg):
		ret = libctcapi.container_spawn_cb(self._ct, cb, arg)
		if ret:
			raise LibctError(ret)

	def spawn_execv(self, path, argv):
		ret = libctcapi.container_spawn_execv(self._ct, path, argv)
		if ret:
			raise LibctError(ret)

	def spawn_execve(self, path, argv, env):
		ret = libctcapi.container_spawn_execve(self._ct, path, argv, env)
		if ret:
			raise LibctError(ret)

	def spawn_execvfds(self, path, argv, fds):
		ret = libctcapi.container_spawn_execvfds(self._ct,
						path, argv, fds)
		if ret:
			raise LibctError(ret)

	def spawn_execvefds(self, path, argv, env, fds):
		ret = libctcapi.container_spawn_execvefds(self._ct,
						path, argv, env, fds)
		if ret:
			raise LibctError(ret)

	def enter_cb(self, cb, arg):
		ret = libctcapi.container_enter_cb(self._ct, cb, arg)
		if ret:
			raise LibctError(ret)

	def enter_execv(self, path, argv, fds=None):
		return libctcapi.container_enter_execvfds(self._ct, path, argv, fds)

	def enter_execve(self, path, argv, env, fds=None):
		return libctcapi.container_enter_execvefds(self._ct, path, argv, env, fds)

	def kill(self):
		ret = libctcapi.container_kill(self._ct)
		if ret:
			raise LibctError(ret)

	def wait(self):
		return libctcapi.container_wait(self._ct)

	def destroy(self):
		libctcapi.container_destroy(self._ct)

	def set_nsmask(self, ns_mask):
		ret = libctcapi.container_set_nsmask(self._ct, ns_mask)
		if ret:
			raise LibctError(ret)

	def controller_add(self, ctype):
		ret = libctcapi.controller_add(self._ct, ctype)
		if ret:
			raise LibctError(ret)

	def controller_configure(self, ctype, param, value):
		ret = libctcapi.controller_configure(self._ct, ctype, param, value)
		if ret:
			raise LibctError(ret)

	def uname(self, host, domain):
		ret = libctcapi.container_uname(self._ct, host, domain)
		if ret:
			raise LibctError(ret)

	def set_caps(self, mask, apply_to):
		ret = libctcapi.container_set_caps(self._ct, mask, apply_to)
		if ret:
			raise LibctError(ret)

	def set_root(self, root_path):
		ret = libctcapi.fs_set_root(self._ct, root_path)
		if ret:
			raise LibctError(ret)

	def set_private(self, fs_type, arg):
		ret = libctcapi.fs_set_private(self._ct, fs_type, arg)
		if ret:
			raise LibctError(ret)

	def add_mount(self, src, dst, flags):
		ret = libctcapi.fs_add_mount(self._ct, src, dst, flags)
		if ret:
			raise LibctError(ret)

	def del_mount(self, dst):
		ret = libctcapi.fs_del_mount(self._ct, dst)
		if ret:
			raise LibctError(ret)

	def net_add(self, ntype, arg):
		net = libctcapi.net_add(self._ct, ntype, arg)
		if type(net) != types.LongType:
			return Net(net)
		else:
			raise LibctError(net)

	def net_del(self, ntype, arg):
		ret = libctcapi.net_del(self._ct, ntype, arg)
		if ret:
			raise LibctError(ret)

class Net(object):

	def __init__(self, net):
		self._net = net
