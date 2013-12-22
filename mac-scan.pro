#TEMPLATE = app
#CONFIG += console
#CONFIG -= app_bundle
#CONFIG -= qt

SOURCES += main.cpp \
    arpcapture.cpp \
    arprequest.cpp \
    arprequestpacket.cpp \
    controller.cpp \
    comhdr.cpp

HEADERS += \
    arpcapture.h \
    comhdr.h \
    queue.hpp \
    arprequest.h \
    arprequestpacket.h \
    controller.h

CONFIG += c++11

INCLUDEPATH += \
    /usr/include

LIBS += \
    -L/usr/lib -lpthread \
    -lpcap

