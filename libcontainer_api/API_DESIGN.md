# Design of the libcontainer api

## Introduction

“A *container* is a self-contained directory (sic) that is able to run one or more processes without
affecting the host system.”

At its heart, a container is a means of executing one or more processes in isolation from the host
system.
If two or more containers execute on a single host, they
should not influence or access each others' (isolated) resources.

The resources available to the processes of a container are determined by the container
*configuration*.

In general, a container may be constructed which is more or less “porous”: the resources need not all be
isolated. There can be “process” isolation, “network” isolation, “file system” isolation, and so on.
The resources not isolated are shared with the host.

The `libcontainer_api` package defines the public interfaces to container and configuration functions.
Where possible
these interfaces have been separated into groups of related methods. This allows the possibility of multiple
implementations at different levels of functional support.

## Requirements

### Basic requirements

Start, run, interact with, and retrieve results from, a (user) process executing in a
Container.

Resources (such as file system, processors, network connections and RAM allocations) may be
allocated to, and subject to limits in, a Container.

### Multiple user processes

Multiple user processes can be executed together in a single Container.
All user processes running in the Container are subject to
the same isolation requirements and resource limits.
User processes are *peers* in the sense that they share a common parent
and one user process may terminate without
terminating any other.

### Life cycle

A Container has a *state*, which the host may interrogate.
It must be possible to create a new Container with no user processes so that,
for example, system settings (which are not available on the API) may be changed before
the first user process runs.

A Container should continue to exist after user processes have terminated so that, for example,
system settings are not lost before the Container is re-used.

Events, which include resource exhaustion and state transitions, must be monitorable by the host.

### Dynamic reconfiguration

A Container may be reconfigured after it has been created.
There may be limitations in what can be reconfigured, and in what states, but these must be kept to a
bare minimum.
(In particular, it must be possible to reconfigure the Container’s resource limits and network settings.)

## Design

### Packaging

The API is described in separate files, keeping related methods and types together. They are:

* [container_api](container_api.go) — create a Container and a configuration builder; define the Container interface
* [state_api](state_api.go) — examine or change the Container state (see below)
* [runner_api](runner_api.go) — run a process in the Container
* [config_api](config_api.go) — access and update the configuration of the Container
* [event_api](event_api.go) — Container event types and the registrar interface
* [stats_api](stats_api.go) — interface for collecting statistics from a Container

We describe the container state here (also in the [state_api](state_api.go) file).

Container states are:

* **ACTIVE** processes may be added, and will execute
* **STOPPING** processes may not be added, and executing ones are being terminated
* **STOPPED** there are no user processes
* **PAUSING** processes may not be added, and executing ones are being paused (‘frozen’)
* **PAUSED** processes may be added, all processes are paused
* **DESTROYED** the container's resources have been reclaimed, nothing further may be done.

The following diagram shows the intended transitions, and associated operations:

     ┌─────>ACTIVE───────────────>PAUSING<───┐
     │   Stop│ ^  Pause         Stop│ │(tau) │
     │       │ │         ┌──────────┘ │      │
     │       │ │         │            │      │
     │       │ └─────────│──────────┐ │      │
     │       │           │          │ │      │
     │       │ ┌─────────┘          │ │      │
     │       │ │                    │ │      │
     │       v v            Continue│ v      │
     │    STOPPING<───────────────PAUSED     │
     │        │(tau)          Stop           │
     │        │                              │
     │Start   v   Pause                      │
     └─────STOPPED───────────────────────────┘
              │Destroy
              │
              v
          DESTROYED

The operations are **Start**, **Stop**, **Pause**, **Continue** and **Destroy**; the allowed
transitions that change the state are shown.

The initial state is **ACTIVE**, and the Container may be destroyed only in the **STOPPED** state
(unless it is forced — not shown).

(Two internal state transitions from the **PAUSING** and **STOPPING** states are labelled (tau).
This means that the transition may occur asynchronously, without a triggering operation. It
also means that it may not occur at all.
**PAUSING** and **STOPPING** are required so as to avoid having to synchronise certain
other Container API operations during
a **Pause** or **Stop** operation, which may take some time or may fail.)

A state transition may be detected by examining the state or listening to events (see [event_api](event_api.go)).

## API design points

### Channels

We use channels (`chan<-` or `<-chan`) in the API in a couple of places for inter-process communication
of typed values.
This is a natural Go idiom, and makes life a lot easier for the programmer
(no assumption of threads, no marshalling/parsing bytes, type-safe usage and so on).
Where channels have implications upon the rest of the system (blocking, &c.) we put notes in the interface.
Elsewhere io.Reader and io.Writer interfaces are used.

### Threads()

Collecting thread ids appears not generally useful, and it ought to be possible to get the thread ids from the
process ids (which are, in Linux, synonymous with Thread Group ids—`tgid`), although we have not verified this.

### Panics

Expected failures produce errors. Where the contract of the method cannot be met, for example where a partially
constructed Container state cannot be cleaned up when an error occurs, it might be appropriate to panic.  We do not
document these cases, as we strive never to panic; but you never know.

Conversely, if we do not panic, the API should guarantee a valid internal state,
even if we return an error.

### Collection types

It might be tempting to define Containers with names, and group them in a collection. We have
deliberately avoided this. The management of multiple Containers, with perhaps hierarchical naming
mechanisms, is a separable concern, which can be implemented using this package.

### Container identifier and display name

Both a container identifier and a display name appear on the interface.  A display name is a user-defined
string which is placed in messages, and so on. There is no need to provide distinct display names.

Each Container has a container identifier, which is generated and allocated when the Container is
constructed. Each Container knows its own container id, and each Container's id is distinct from
every other Container's in the host system.
The container id is used to disambiguate messages or
event information.

### Process structure

A Container normally runs with its own PID namespace. The first process created (which 'carries' the
namespaces) acts as a virtual 'root' process. In order to manage the processes run in a Container, to
collect their exit statuses reliably, and to deal with them when they (or their parents) terminate, we
recommend a special process for each Container which is not one of the user processes.

For consistency of the user interface, we recommend this even if
the Container does *not* have a PID namespace (as defined by its configuration). All (user) processes
run in a Container run (initially) as children of this 'root' process.
