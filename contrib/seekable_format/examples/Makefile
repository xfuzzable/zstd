# ################################################################
# Copyright (c) 2017-present, Facebook, Inc.
# All rights reserved.
#
# This source code is licensed under both the BSD-style license (found in the
# LICENSE file in the root directory of this source tree) and the GPLv2 (found
# in the COPYING file in the root directory of this source tree).
# ################################################################

ZSTDLIB_PATH = ../../../lib
ZSTDLIB_NAME = libzstd.a
ZSTDLIB = $(ZSTDLIB_PATH)/$(ZSTDLIB_NAME)

CPPFLAGS += -I../ -I../../../lib -I../../../lib/common

CFLAGS ?= -O3
CFLAGS += -g

SEEKABLE_OBJS = ../zstdseek_compress.c ../zstdseek_decompress.c $(ZSTDLIB)

.PHONY: default all clean test

default: all

all: seekable_compression seekable_decompression seekable_decompression_mem \
	parallel_processing

$(ZSTDLIB):
	$(MAKE) -C $(ZSTDLIB_PATH) $(ZSTDLIB_NAME)

seekable_compression : seekable_compression.c $(SEEKABLE_OBJS)

seekable_decompression : seekable_decompression.c $(SEEKABLE_OBJS)

seekable_decompression_mem : seekable_decompression_mem.c $(SEEKABLE_OBJS)

parallel_processing : LDFLAGS += -pthread
parallel_processing : parallel_processing.c $(SEEKABLE_OBJS)

parallel_compression : LDFLAGS += -pthread
parallel_compression : parallel_compression.c $(SEEKABLE_OBJS)

CP   ?= cp
CAT  ?= cat
HEAD ?= head
TAIL ?= tail
CMP  ?= cmp
test : all parallel_compression
	$(CP) seekable_compression tmp
	./seekable_compression tmp 4096
	./seekable_decompression tmp.zst 6000 32000 > tmp1
	$(CAT) tmp | $(HEAD) -c 32000 | $(TAIL) -c 26000 > tmp2
	$(CMP) tmp1 tmp2
	./seekable_decompression_mem tmp.zst 6000 32000 > tmp3
	$(CMP) tmp3 tmp2
	./parallel_processing tmp.zst 2
	./parallel_compression tmp 4096 2
	./seekable_decompression tmp.zst 6000 32000 > tmp1
	$(CMP) tmp1 tmp2


clean:
	@$(RM) core *.o tmp* result* *.zst \
		seekable_compression seekable_decompression \
		seekable_decompression_mem \
		parallel_processing parallel_compression
	@echo Cleaning completed
