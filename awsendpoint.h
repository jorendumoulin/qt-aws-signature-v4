#ifndef AWSENDPOINT_H
#define AWSENDPOINT_H

#include "qt-aws-signaturev4_global.h"
#include <QStringList>
#include <QString>

class QTAWSSIGNATUREV4_EXPORT AwsEndpoint
{
public:

    enum Transport {
        HTTP = 0x01,
        HTTPS = 0x02,
        SMTP = 0x04,
        AnyTransport = HTTP|HTTPS|SMTP
    };

    explicit AwsEndpoint(const QString &url);
    ~AwsEndpoint();

    bool isValid() const;
    QString hostName() const;
    QString regionName() const;
    QString serviceName() const;

private:
    QString host;
    QString region;
    QString service;

};

#endif // AWSENDPOINT_H
