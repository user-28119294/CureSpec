ALLSOURCES := $(wildcard */)

.PHONY:	sources $(ALLSOURCES) clean

sources:	$(ALLSOURCES)


$(ALLSOURCES):
	export SRCNAME=$(notdir $@); \
	$(MAKE) -C $@
