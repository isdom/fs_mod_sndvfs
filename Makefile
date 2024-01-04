SER_CC_PRE=
#CLI_CC_PRE=ppc_4xx-

SER_CC=$(SER_CC_PRE)g++
CLI_CC=$(CLI_CC_PRE)g++
SER_STRIP=$(SER_CC_PRE)strip
CLI_STRIP=$(CLI_CC_PRE)strip


CFLAGS += -g -shared -fPIC -O2 -Wall
SER_SRCS=mod_sndmem.cpp

FREESWITCH_LIBS=-L/usr/local/freeswitch/lib -lfreeswitch
FREESWITCH_INCLUDE=-I/usr/local/freeswitch/include/freeswitch

SNDFILE_LIBS=-loss_c_sdk_static -lapr-1 -laprutil-1 -lcurl -lmxml -lsndfile -ldl -D_GLIBCXX_USE_CXX11_ABI=0
OSS_INCLUDE=-I/usr/include/apr-1.0

TARGET_SER=mod_sndmem.so

SER_OBJS=$(SER_SRCS:.c=.o)

default: $(TARGET_SER)

$(TARGET_SER): $(SER_OBJS) $(HEADERS)
	$(SER_CC) $(CFLAGS) -o $(TARGET_SER) $(SER_OBJS) $(SNDFILE_LIBS) $(FREESWITCH_INCLUDE) $(FREESWITCH_LIBS) $(OSS_INCLUDE)
#	$(SER_STRIP) $(TARGET_SER)

#$(SER_OBJS):%.o:%.c
#	$(SER_CC) $(SDK_INCLUDE) $(FREESWITCH_INCLUDE) $(CFLAGS) -c $< -o $@

install:
	echo "nothing to do"
clean:
	rm -rf  $(TARGET_SER)
