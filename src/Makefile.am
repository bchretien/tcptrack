bin_PROGRAMS = tcptrack

tcptrack_SOURCES = Collector.cc main.cc TCContainer.cc \
                 TextUI.cc  PacketBuffer.cc \
                 Sniffer.cc TCPConnection.cc util.cc \
                 SortedIterator.cc TCPPacket.cc \
                 IPv4Address.cc IPv6Address.cc \
                 TCPHeader.cc TCPCapture.cc \
                 TCPTrack.cc SocketPair.cc \
								 IPAddress.cc \
                 AppError.cc PcapError.cc GenericError.cc Guesser.cc

noinst_HEADERS = Collector.h PacketBuffer.h TextUI.h \
								 defs.h Sniffer.h headers.h \
								 SortedIterator.h util.h TCContainer.h \
								 TCPConnection.h Guesser.h \
								 TCPPacket.h IPv4Address.h IPv6Address.h \
								 TCPHeader.h TCPCapture.h \
								 TCPTrack.h SocketPair.h \
								 IPAddress.h \
								 AppError.h PcapError.h GenericError.h

man_MANS = tcptrack.1

EXTRA_DIST = tcptrack.1

# no-deprecated required due to hash_map
AM_CXXFLAGS = -Werror -Wno-deprecated -Wall

