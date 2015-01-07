Golang bindings for libseccomp
==============================

This provides a native Go interface to libseccomp (http://libseccomp.sf.net), an
easy-to-use and platform-independent library for interfacing with seccomp, the
Linux kernel's mechanism for restricting system calls.

Usage
=====

To use these bindings, the libseccomp library and associated headers must be
installed and in the library load path. These bindings were written against
version 2.1.1 of libseccomp, and is not guaranteed to work with versions earlier
than version 2.1.0.

Documentation can be generated via Godoc. The public API is entirely documented.
Additionally, the bindings closely follow the conventions of the libseccomp API,
and the documentation of libseccomp itself should be helpful.

The library ships with a test suite which can be run with "go test". This suite
verifies the functionality of the bindings and the libseccomp library itself.

Ongoing Development
===================

The following are major improvements being worked towards:

* Replace C error handling convention (returning ERRNO as error) where it is
  confusing. Some errno returns can be confusing as to the actual error. Given
  that we have a much more rich error-handling convention in Golang, these can
  be interpreted by the bindings to provide more context as to the actual error.
* Add virtual syscall defines, as are present in the libseccomp headers. Likely
  going to be implemented similar to the present constants.
* Investigate improved unit testing of filter loading/matching - likely to
  require extensive work, given Golang runs all tests in the same process by
  default

Contributing
============

Feel free to contribute changes. Pull requests are always welcome!

When submitting pull requests, please sign all commits (for example, using git
commit -s).

Licensing
=========

These bindings are licensed under version 2.1 of the Lesser GNU Public License.
This matches the license of the libseccomp library. See LICENSE for full license
text.
