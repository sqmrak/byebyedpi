# host tests and the deb. the device build needs the variables build_deb.sh lists
.PHONY: test sanitize deb clean

test:
	env PATH=/usr/local/bin:/usr/bin:/bin $(MAKE) -C tests test

sanitize:
	env PATH=/usr/local/bin:/usr/bin:/bin $(MAKE) -C tests sanitize

deb:
	./build_deb.sh

clean:
	$(MAKE) -C tests clean
	$(MAKE) -C daemon -f Makefile.ios clean
