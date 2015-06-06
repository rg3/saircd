# Copyright 2012 Ricardo Garcia Gonzalez
#
# This file is part of saircd.
# 
# saircd is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# 
# saircd is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with saircd.  If not, see <http://www.gnu.org/licenses/>.

CC = cc
CFLAGS = -O2 -W -Wall

PREFIX = /usr/local
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/man
ETCDIR = $(PREFIX)/etc/saircd

.SILENT: all build.h

.PHONY: all install clean man build.h

all: messages_test database_test buffer_test reader_test saircd
	./messages_test
	./database_test
	./buffer_test
	./reader_test

install: saircd man
	install -D -m 755 saircd $(DESTDIR)$(BINDIR)/saircd
	install -D -m 644 extra/default-saircd.conf $(DESTDIR)$(ETCDIR)/default-saircd.conf
	install -D -m 644 saircd.1 $(DESTDIR)$(MANDIR)/man1/saircd.1

clean:
	rm -f messages_test database_test buffer_test reader_test saircd build.h *.o *.1 *.xml

man: saircd.1

saircd.1: saircd.txt
	asciidoc -b docbook -d manpage saircd.txt
	xmlto man saircd.xml

messages_test: messages_test.o messages.o
	$(CC) -o messages_test messages_test.o messages.o `pcre-config --libs`

messages_test.o: messages_test.c messages.h
	$(CC) $(CFLAGS) -c messages_test.c

messages.o: messages.c messages.h
	$(CC) $(CFLAGS) `pcre-config --cflags` -c messages.c

database_test: database_test.o database.o util.o
	$(CC) -o database_test database_test.o database.o util.o `pkg-config --libs sqlite3`

database_test.o: database_test.c messages.h database.h util.h
	$(CC) $(CFLAGS) `pkg-config --cflags sqlite3` -c database_test.c

database.o: database.c database.h
	$(CC) $(CFLAGS) `pkg-config --cflags sqlite3` -c database.c

buffer_test: buffer_test.o buffer.o
	$(CC) -o buffer_test buffer_test.o buffer.o

buffer_test.o: buffer_test.c buffer.h
	$(CC) $(CFLAGS) -c buffer_test.c

reader_test: reader_test.o reader.o buffer.o util.o
	$(CC) -o reader_test reader_test.o reader.o buffer.o util.o

reader_test.o: reader_test.c messages.h buffer.h reader.h util.h
	$(CC) $(CFLAGS) -c reader_test.c

saircd: main.o buffer.o database.o messages.o reader.o server.o util.o
	$(CC) -o saircd main.o buffer.o database.o messages.o reader.o server.o util.o \
		`pcre-config --libs` `pkg-config --libs sqlite3`

reader.o: reader.c buffer.h reader.h
	$(CC) $(CFLAGS) -c reader.c

buffer.o: buffer.c buffer.h
	$(CC) $(CFLAGS) -c buffer.c

util.o: util.c util.h
	$(CC) $(CFLAGS) -c util.c

server.o: server.c messages.h database.h buffer.h reader.h server.h util.h build.h
	$(CC) $(CFLAGS) -c server.c

main.o: main.c messages.h database.h buffer.h reader.h server.h
	$(CC) $(CFLAGS) -c main.c

build.h: build.h.in
	sed \
		-e "s!@@UNAME@@!`uname -mnsrv`!" \
		-e "s!@@DATE@@!`env -i LANG=C date -u`!" \
		build.h.in >build.h
