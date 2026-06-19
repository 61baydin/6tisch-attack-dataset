CONTIKI_PROJECT = decrease-rank-attack-client
all: $(CONTIKI_PROJECT)

#linker optimizations
SMALL=1

MAKE_MAC = MAKE_MAC_4EMAC
MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC

MODULES += os/services/simple-energest
MODULES += os/net/app-layer/attack-analyzer

CONTIKI = ../../../..
include $(CONTIKI)/Makefile.include
