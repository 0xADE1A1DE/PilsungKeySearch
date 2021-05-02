SRCS=keysearch.c gentables.c perm.c pilsung.c
OBJS=${SRCS:.c=.o}
PROJ=keysearch
TPROJ=testkey
CFLAGS=-g --std=gnu99 -O3
LDFLAGS=-g
LDLIBS=-lcrypto

all: ${PROJ} ${TPROJ}

${PROJ}: ${OBJS}
	${CC} -o $@ ${LDFLAGS} ${OBJS} ${LDLIBS}

${TPROJ}: pilsung.c testkey.c
	${CC} -o ${TPROJ} testkey.c ${LDLIBS}


clean:
	rm -f ${PROJ} ${TPROJ} ${OBJS}

keysearch.o: tables.h rand.h
mktables.o: tables.h
perm.o: rand.h
