#ifndef AWSSIGNATUREV4_H
#define AWSSIGNATUREV4_H

#include "qt-aws-signaturev4_global.h"
#include "awscredentials.h"
#include <QCryptographicHash>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkRequest>
#include <QMessageAuthenticationCode>
#include <QUrlQuery>
#include <QDir>
#include <QUrl>
#include <QByteArray>
#include <QList>

class QTAWSSIGNATUREV4_EXPORT AwsSignaturev4
{
public:
    AwsSignaturev4();
    void sign(const AwsCredentials &credentials,
                     const QNetworkAccessManager::Operation operation,
                     QNetworkRequest &request,
                     const QByteArray &data = QByteArray()) const;
protected:
    void setAuthorizationHeader(const AwsCredentials &credentials,
                                const QNetworkAccessManager::Operation operation,
                                QNetworkRequest &request, const QByteArray &payload,
                                const QDateTime &timestamp) const;

    QDateTime setDateHeader(QNetworkRequest &request, const QDateTime &dateTime = QDateTime::currentDateTimeUtc()) const;
    void setContentHeader(QNetworkRequest &request, const QByteArray &data = QByteArray()) const;

    static const QLatin1String DateFormat;
    static const QLatin1String DateTimeFormat;

    const QCryptographicHash::Algorithm hashAlgorithm; ///< Hash algorithm to use when signing.

    QByteArray algorithmDesignation(const QCryptographicHash::Algorithm algorithm) const;

    QByteArray authorizationHeaderValue(const AwsCredentials &credentials,
                                        const QNetworkAccessManager::Operation operation,
                                        QNetworkRequest &request, const QByteArray &payload,
                                        const QDateTime &timestamp) const;

    QByteArray canonicalHeader(const QByteArray &headerName, const QByteArray &headerValue) const;

    QByteArray canonicalHeaders(const QNetworkRequest &request, QByteArray * const signedHeaders) const;

    QByteArray canonicalRequest(const QNetworkAccessManager::Operation operation, const QNetworkRequest &request,
                                const QByteArray &payload, QByteArray * const signedHeaders) const;

    QByteArray credentialScope(const QDate &date, const QString &region, const QString &service) const;

    QByteArray signingKey(const AwsCredentials &credentials, const QDate &date,
                          const QString &region, const QString &service) const;

    QByteArray stringToSign(const QByteArray &algorithmDesignation, const QDateTime &requestDate,
                            const QByteArray &credentialScope, const QByteArray &canonicalRequest) const;

    QString httpMethod(const QNetworkAccessManager::Operation operation) const;

    QString canonicalPath(const QUrl &url) const;

    virtual QByteArray canonicalQuery(const QUrlQuery &query) const;

};

#endif // AWSSIGNATUREV4_H
