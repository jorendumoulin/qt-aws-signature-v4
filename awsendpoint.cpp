#include "awsendpoint.h"

// Construct an AwsEndpoint for the given AWS Hostname
AwsEndpoint::AwsEndpoint(const QString &url)
{
    QStringList sl = url.split(".");
    host = sl[3];
    region = sl[2];
    service = sl[1];
}

QString AwsEndpoint::hostName() const {
    return host;
};

QString AwsEndpoint::regionName() const {
    return region;
};

QString AwsEndpoint::serviceName() const {
    return service;
};
