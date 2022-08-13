BUILD_DIR = build
RUN_SCRIPT = ../../utils/mininet-setup.py
P4C = p4c-bm2-mtpsa

SOURCES	:= $(shell find . ! -name "main.p4" -name "*.p4")
OBJECTS	:= $(SOURCES:%.p4=$(BUILD_DIR)/%.json)

all: dirs $(BUILD_DIR)/main.json $(OBJECTS)
	sudo python $(RUN_SCRIPT) -t topology/topology.json -j build/main.json -b mtpsa_switch \
		--user 1@build/user01.json \
		--user 2@build/user02.json \
		--user 3@build/user03.json \
		--user 4@build/user04.json

$(BUILD_DIR)/main.json: main.p4
	$(P4C) --p4v 16 -o $@ $<

$(OBJECTS): $(BUILD_DIR)/%.json: %.p4
	$(P4C) --user --p4v 16 -o $@ $<

dirs:
	mkdir -p $(BUILD_DIR) pcaps logs
stop:
	sudo mn -c
clean: stop
	rm -f *.pcap *.pyc
	rm -rf $(BUILD_DIR) pcaps logs
