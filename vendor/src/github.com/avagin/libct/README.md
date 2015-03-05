[![Build Status](https://travis-ci.org/xemul/libct.svg)](https://travis-ci.org/xemul/libct)

LIBCT
=====

Libct is a containers management library which provides convenient API for
frontend programs to rule a container during its whole lifetime.

The library operates on two entities:

* session -- everyone willing to work with container must first open a
session. Currently there is only one type of session -- local, when all
containers are created as child tasks of the caller using namespaces,
cgroups etc.;

* container -- a container. By default container is "empty", when started
it is merely a fork()-ed process. Container can be equipped with various
things, e.g.

  - Namespaces. Libct accepts clone mask with which container is started

  - Controllers. One may configure all existing CGroup controllers inside
    which container will be started.

  - Root on a filesystem. This is a directory into which container will
    be chroot()-ed (or pivot_root()-ed if mount namespace is used).

  - Private area. This is where the files for container are. Currently
    only one type is supported -- a directory that will be bind-mounted
    into root.

  - Network. Caller may assign host NIC of veth pair's end to container
    on start.


For more details, see [Documentation/libct.txt](Documentation/libct.txt).
For usage examples, see [test](test/) directory.
All the API calls, types and constants are collected in
[src/include/uapi/libct.h](src/include/uapi/libct.h).
