BUILD_DIR = build

source = $(wildcard *.p4)
compiled_json := $(source:.p4=.json)

DEFAULT_PROG = $(wildcard *.p4)
DEFAULT_JSON = $(BUILD_DIR)/$(DEFAULT_PROG:.p4=.json)

ifndef BMV2_SWITCH_EXE
	BMV2_SWITCH_EXE = simple_switch_grpc
endif

ifndef P4C
	P4C = p4c-bm2-ss
endif

ifndef RUN_SCRIPT
	RUN_SCRIPT = utils/mininet-setup.py
endif

all: build
	sudo python $(RUN_SCRIPT) -t topology/topology.json -j $(DEFAULT_JSON)  -b $(BMV2_SWITCH_EXE)
build: dirs $(compiled_json)

%.json: %.p4
ifeq ($(BMV2_SWITCH_EXE),simple_switch_grpc)
	sudo $(P4C) --p4v 16 --p4runtime-files $(BUILD_DIR)/$(basename $@).p4.p4info.txt -o $(BUILD_DIR)/$@ $<
else
	$(P4C) --p4v 16 -o $(BUILD_DIR)/$@ $<
endif

dirs:
	mkdir -p $(BUILD_DIR) pcaps logs
stop:
	sudo mn -c
clean: stop
	rm -f *.pcap *.pyc
	rm -rf $(BUILD_DIR) pcaps logs
