Copyright 2012 Ricardo Garcia Gonzalez
See the COPYING file and section 7 of this document for license details.
--

saircd User Guide

1. About
2. Build instructions
3. Installation
4. Running the server
5. Supported features
	5.1. Network
	5.2. IRC protocol
		5.2.1. Limitations and unsupported features
		5.2.2. Supported optional features
		5.2.3. IRC operators
		5.2.4. Supported user modes
		5.2.5. Supported channel types and modes
	5.3. Special features
6. Recommendations
7. License
8. Contact information



1. About

saircd is a Stand-Alone IRC Daemon, that is, a simple IRC daemon oriented to
home and corporate use which does not support being connected to other IRC
servers. It is very easy to configure and use and will happily deliver several
thousand messages per second between users if run on appropriate hardware.

saircd is designed to build and run on most UNIX-like operaring systems.



2. Build instructions

saircd is written in plain C, so you will need a C compiler and a make tool. In
addition, it uses SQLite (www.sqlite.org) and the PCRE library (www.pcre.org).
You will need the development files from both libraries if you intend to build
the program.

Once your system meets the appropriate requirements, running "make" in the base
directory of the source code should build the executable file called "saircd"
and run some unit tests. If everything is fine, the make command will finish
successfully.

A manpage is provided in AsciiDoc format. If you want to generate it, you need
"asciidoc" and "xmlto". It can be generated running "make man".



3. Installation

Strictly speaking, the "saircd" binary file is the only one needed to run the
server, so once it has been built you can copy it to any directory in your
system and optionally create a configuration file somewhere (see the next
section).

However, for ease of use, an "install" target is provided in the Makefile. It
supports DESTDIR, PREFIX, BINDIR, MANDIR and other variables. It will install
the program, the default config file and the server manpage in the specified
directories. If you want to change them, you can edit the Makefile or set the
appropriate environment variables and run make with the "-e" option.

Other post-installation steps will be detailed in the next section.



4. Running the server

The server has a few configuration parameters that can be tuned from a
configuration file. If run without arguments, the server will use the default
value in every option. However, you can provide a single argument to the program
to indicate the path to a configuration file. In that file you can override
none, some or all the default configuration parameters and give them your own
values if you wish.

The "extra" directory in the source code distribution should contain a file
named "default-saircd.conf" describing the configuration file format and every
option in detail. That file can be used as a template to set your own values.
Other sample configuration files may be present in that directory too, tuned for
typical different use cases.

A brief description of every possible configuration option follows.

	max_clients
		Maximum number of clients the server will support.

	address
		Listening IP address for the server, if needed.

	port
		Listening server port.

	timeout_seconds
		Time to ping an inactive client and to wait for the reply.

	whowas_timeout_seconds
		Expiration time for WHOWAS entries.

	kill_timeout_seconds
		Amount of time a killed nick will be forbidden after the kill.

	max_channels
		Maximum number of channels that may be formed.

	max_client_channels
		Maximum number of channels a single client may be a member of.

	max_channel_members
		Absolute maximum number of client members for any given channel,
		independently of the limit set with the +l mode.

	max_bans
	max_exceptions
	max_invitations
		Maximum number of ban, exception and invite masks in any
		channel, for channel modes b, e and I.

	server_name
		Hostname or pseudo-hostname for the IRC server.

	motd
		Single line containing the message of the day.

	location
	entity
	email
		Information to be displayed in reply to the ADMIN command,
		specifying the server location, organization or company and
		administrator email, respectively.

	operators_file
		File containing username and passwords for IRC Operators. More
		information about this can be found in the "IRC protocol"
		section.

	username
		User to drop privileges to when running the server, after
		obtaining the listening socket and performing other server
		initialization steps.

	chroot_dir
		Directory to chroot to after initializing the server.

	daemonize
		Boolean option to run the server in the background or not.



5. Supported features


5.1. Network

The server works on TCP/IP and supports both IPv4 and IPv6. SSL is not
supported but external tools like stunnel (www.stunnel.org) could be used in
case SSL connections are needed.


5.2. IRC protocol

The server supports a broad subset of the protocol as specified in RFCs 1459 and
2812, and should be compatible with the most popular IRC clients in use. It has
been tested with mIRC, X-Chat or Irssi, among others.

A few IRC messages have been coded with limitations, and not every optional
feature has been implemented, but the resulting server should cover the needs of
most home and corporate uses.


5.2.1. Limitations and unsupported features

Messages related to server connections and services are not supported (e.g.
SERVICE, SQUIT, SQUERY or CONNECT).

A detailed list of limitations and unsupported messages follows.

  * During the connection registration phase, PASS is accepted but ignored.
  * SERVICE is not supported.
  * SQUIT is not supported.
  * Unlike other servers, saircd enforces "0" to be the only JOIN command
    argument if present, as required by the protocol specification. This means
    "JOIN 0" works but "JOIN #channel,0" does not.
  * NAMES and LIST cannot be used without arguments.
  * PRIVMSG and NOTICE require channels or nicknames. Masks are not supported.
  * Most messages accepting a server or subnet "target" argument ignore the
    argument or require it to match the server_name configuration parameter.
  * CONNECT is not supported.
  * SERVLIST is not supported.
  * SQUERY is not supported.
  * WHO and WHOIS require channels or nicknames. Masks are not supported.


5.2.2. Supported optional features

Server support for "optional features" as named in the RFCs is as follows.

  * AWAY is supported.
  * DIE is supported.
  * USERHOST is supported.
  * ISON is supported.
  * REHASH is not supported.
  * RESTART is not supported.
  * SUMMON is not supported.
  * USERS is not supported.
  * WALLOPS is not supported.


5.2.3. IRC operators

The IRC operator status can be reached with the classic OPER command. For that
to work properly, the operators_file option must have been set in the
configuration file.

As described in the "default-saircd.conf" template, this option specifies a file
containing username and password pairs to authenticate as an IRC operator. If
one client is currently authenticated as an IRC operator, no other user will be
able to authenticate to the same username and password pair while the client
remains connected, receiving an authentication failure message.

Blank lines and lines starting with # are considered comments, but any other
line should contain one username/password pair each. The username and the
password must be separated by a space character.


5.2.4. Supported user modes

The following user modes are supported:

  * a: toggled using AWAY messages.
  * i: toggled with user MODE messages.
  * w: toggled with user MODE messages, but it will not be used for anything.
  * r: toggled with user MODE messages.
  * o: set with OPER messages, and unset with user MODE messages.
  * s: toggled with user MODE messages, but it will not be used for anything.


5.2.5. Supported channel types and modes

Channel types # and & are supported and equivalent. Channel types + and ! are
not supported. Most channel modes described in RFC 2811 are supported. In
particular:

  * Channel modes o and v are supported for voice and operator privileges.
  * Basic modes n are t are supported.
  * Mode i for invite-only channels is supported.
  * Mode m for moderated channels is supported.
  * Modes p and s are supported and cannot be set at the same time (RFC).
  * Mode q is supported, but it should be set before any other user joins the
    channel to achieve the desired effect.
  * Mode a for anonyous channels is supported and can be toggled in any given
    moment.
  * Modes k and l to set a key or a limit are supported.
  * Modes b and e are supported, to set ban masks and exception masks.
  * Mode I for invitation masks is supported.
  * Modes O and r are not supported.



5.3. Special features

The server has a few special features worth mentioning.

Nickname "anonymous" is reserved for anonymous channels as described by RFC
2811. In addition, nickname "root" is also reserved.

There is a special channel called #log that only IRC operators may join. It's a
special quiet channel where the special nickname "root" writes server log
messages about JOINs, PARTs, connection and disconnection messages, and also IRC
operator authentication-related messages. Any client joining this channel could
save the channel log, which results in having remotely-saved server logs.



6. Recommendations

The typical recommended way of running the server is as follows:

Store the server executable file in /usr/local/bin, /usr/bin or other equivalent
directory.

Create /usr/local/etc/saircd, /etc/saircd or other equivalent directory. In it,
store a configuration file typically named saircd.conf. Also in the same
directory, create an operators file with at least one operator username and
password pair. Typical advice for secure passwords apply. Inside the
configuration file, indicate the full path to the operators file using the
"operators_file" option. The operators file should belong to the superuser and
have restricted read permissions.

Create a specific unprivileged user to run the server as, and indicate that
username in the "username" option. Using a generic unprivileged user, typically
named "nobody", may also be acceptable.

Create a specific empty directory in the file system and indicate its path in
the "chroot_dir" option. Using a generic empty directory, typically /var/empty,
may also be acceptable.

Obviously, operator passwords are stored in plain text and travel unprotected
through the network unless an external tool like stunnel is being used. In case
a security breach takes place regarding operator username and passwords, you do
not want the attacker to gain access to anything outside the virtual world of
the IRC server, so the username and passwords should not match the ones from any
other system or service in the same machine or in the corporate network in
general.

In case the server code contains an exploitable bug, the username and chroot_dir
options should be able to help minimize the problems derived from it, preventing
the attacker from accessing system files or performing privileged operations.

Once the configuration has been set in the file, the server should be called
with its full path as its only argument.



7. License

This file is part of saircd.

saircd is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

saircd is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with saircd.  If not, see <http://www.gnu.org/licenses/>.



8. Contact information

Ricardo Garcia <r@rg3.name>

