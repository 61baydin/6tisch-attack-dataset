CONTIKI_PROJECT=border-router-server
all: $(CONTIKI_PROJECT)

MAKE_MAC = MAKE_MAC_4EMAC
MAKE_ROUTING = MAKE_ROUTING_RPL_CLASSIC

# The BR is either native or embedded, and in the latter case must support SLIP
PLATFORMS_EXCLUDE = nrf52dk

#linker optimizations
SMALL=1

# Include RPL BR module
MODULES += os/services/rpl-border-router
MODULES += os/net/app-layer/attack-analyzer

CONTIKI=../../../..
include $(CONTIKI)/Makefile.include
