QT -= gui
QT += core network

TEMPLATE = lib
DEFINES += QTAWSSIGNATUREV4_LIBRARY

CONFIG += c++17

# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0

SOURCES += \
    awscredentials.cpp \
    awsendpoint.cpp \
    awssignaturev4.cpp \

HEADERS += \
    awscredentials.h \
    awsendpoint.h \
    awssignaturev4.h \
    qt-aws-signaturev4_global.h \

# Default rules for deployment.
unix {
    target.path = /usr/lib
}
!isEmpty(target.path): INSTALLS += target
