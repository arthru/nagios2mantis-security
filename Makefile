DESTDIR=/usr/local

COVERAGE?=coverage
COVERAGE_REPORT=$(COVERAGE) report -m
COVERAGE_PARSE_RATE=$(COVERAGE_REPORT) | tail -n 1 | sed "s/ \+/ /g" | cut -d" " -f4

all: tests install

include autobuild.mk

tests:
	$(COVERAGE) run -p --source=nagios2mantis_security tests.py
	$(COVERAGE) combine
	$(COVERAGE_REPORT)
	if [ "100%" != "`$(COVERAGE_PARSE_RATE)`" ] ; then exit 1 ; fi

install:
	mkdir -p $(DESTDIR)/usr/bin
	cp nagios2mantis_security.py $(DESTDIR)/usr/bin/
	mkdir -p $(DESTDIR)/etc
	cp nagios2mantis_security.ini $(DESTDIR)/etc
