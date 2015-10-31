# net utils includes conveniences for doing network related stuff
SET(SRCS net_utils.c)
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/include)

ADD_LIBRARY(netutils SHARED ${SRCS})
