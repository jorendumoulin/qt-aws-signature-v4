#ifndef AWSCREDENTIALS_H
#define AWSCREDENTIALS_H

#include "qt-aws-signaturev4_global.h"
#include <QString>

class QTAWSSIGNATUREV4_EXPORT AwsCredentials
{
public:
    explicit AwsCredentials(const QString &accessKeyId, const QString &secretKey);

    QString accessKeyId() const;
    QString secretKey() const;

private:
    QString access_key;
    QString secret_key;
};



#endif // AWSCREDENTIALS_H
