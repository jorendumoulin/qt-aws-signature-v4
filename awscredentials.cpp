#include "awscredentials.h"

AwsCredentials::AwsCredentials(const QString &accessKeyId, const QString &secretKey)
{
    access_key = accessKeyId;
    secret_key = secretKey;
}


QString AwsCredentials::accessKeyId() const {
    return access_key;
};

QString AwsCredentials::secretKey() const {
    return secret_key;
};


