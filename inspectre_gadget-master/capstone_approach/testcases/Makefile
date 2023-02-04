ALLSOURCES := $(wildcard src/*)

.PHONY:	sources $(ALLSOURCES)

sources:	$(ALLSOURCES)

$(ALLSOURCES):
	export SRCNAME=$(notdir $@); \
	$(MAKE) -C $@