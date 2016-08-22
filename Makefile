default: build
all: build

ICED=node_modules/.bin/iced
BUILD_STAMP=build-stamp
TEST_STAMP=test-stamp
WD=`pwd`
BROWSERIFY=node_modules/.bin/browserify

lib/%.js: src/%.iced
	$(ICED) -I browserify -c -o `dirname $@` $<

$(BUILD_STAMP): lib/main.js lib/util.js lib/format.js lib/nonce.js lib/header.js lib/payload.js lib/stream.js
	date > $@

clean:
	find lib -type f -name *.js -exec rm {} \;
	rm -rf $(BUILD_STAMP) $(TEST_STAMP) test/browser/test.js

setup:
	npm install -d

coverage: $(BUILD_STAMP)
	./node_modules/.bin/istanbul cover $(ICED) test/run.iced

test: test-server test-browser

build: $(BUILD_STAMP)

browser: $(BROWSER)

$(BROWSER): lib/main.js $(BUILD_STAMP)
	$(BROWSERIFY) -s libweb $< > $@

test-server: $(BUILD_STAMP)
	$(ICED) test/run.iced

test-browser: $(TEST_STAMP) $(BUILD_STAMP)
	@echo "Please visit in your favorite browser --> file://$(WD)/test/browser/index.html"

$(TEST_STAMP): test/browser/test.js
	date > $@

test/browser/test.js: test/browser/main.iced $(BUILD_STAMP)
	$(BROWSERIFY) -t icsify $< > $@

browser-demo: $(TEST_STAMP) $(BUILD_STAMP)
	node_modules/.bin/browserify -t icsify test/browser/demo.iced > test/browser/demo.js

.PHONY: clean setup test test-browser coverage browser-demo
