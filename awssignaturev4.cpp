#include "awssignaturev4.h"
#include "awsendpoint.h"

AwsSignaturev4::AwsSignaturev4()
    : hashAlgorithm(QCryptographicHash::Sha256) //simply default to sha256
{

}

const QLatin1String AwsSignaturev4::DateFormat("yyyyMMdd");
const QLatin1String AwsSignaturev4::DateTimeFormat("yyyyMMddThhmmssZ");


void AwsSignaturev4::sign(const AwsCredentials &credentials,
                 const QNetworkAccessManager::Operation operation,
                 QNetworkRequest &request,
                 const QByteArray &data) const
{
    QDateTime datetime = setDateHeader(request);
    setContentHeader(request, data);
    setAuthorizationHeader(credentials, operation, request, data, datetime);
}



void AwsSignaturev4::setAuthorizationHeader(const AwsCredentials &credentials,
                            const QNetworkAccessManager::Operation operation,
                            QNetworkRequest &request, const QByteArray &payload,
                            const QDateTime &timestamp) const
{
    request.setRawHeader("Authorization", authorizationHeaderValue(credentials, operation, request, payload, timestamp));
}

QDateTime AwsSignaturev4::setDateHeader(QNetworkRequest &request, const QDateTime &dateTime) const
{
    request.setRawHeader("x-amz-date", dateTime.toString(DateTimeFormat).toUtf8());
    return dateTime;
}

void AwsSignaturev4::setContentHeader(QNetworkRequest &request, const QByteArray &data) const
{
    request.setRawHeader("x-amz-content-sha256", QCryptographicHash::hash(data, hashAlgorithm).toHex());
}

QByteArray AwsSignaturev4::algorithmDesignation(const QCryptographicHash::Algorithm algorithm) const
{
    switch (algorithm) {
        case QCryptographicHash::Md4:      return "AWS4-HMAC-MD4";
        case QCryptographicHash::Md5:      return "AWS4-HMAC-MD5";
        case QCryptographicHash::Sha1:     return "AWS4-HMAC-SHA1";
        case QCryptographicHash::Sha224:   return "AWS4-HMAC-SHA224";
        case QCryptographicHash::Sha256:   return "AWS4-HMAC-SHA256";
        case QCryptographicHash::Sha384:   return "AWS4-HMAC-SHA384";
        case QCryptographicHash::Sha512:   return "AWS4-HMAC-SHA512";
        default:
            Q_ASSERT_X(false, Q_FUNC_INFO, "invalid algorithm");
            return "invalid-algorithm";
    }
}

QByteArray AwsSignaturev4::authorizationHeaderValue(const AwsCredentials &credentials,
                                    const QNetworkAccessManager::Operation operation,
                                    QNetworkRequest &request, const QByteArray &payload,
                                    const QDateTime &timestamp) const
{
    const QByteArray algorithmDesignation = this->algorithmDesignation(hashAlgorithm);
    //AwsEndpoint endpoint(request.url().host());
    //Don't use external endpoint class to avoid linking errors i am unable to resolve
    QString host = request.url().host();
    QStringList hostlist = host.split(".");
    QString region = hostlist[2];
    QString service = hostlist[1];

    //const QByteArray credentialScope = this->credentialScope(timestamp.date(), endpoint.regionName(), endpoint.serviceName());
    const QByteArray credentialScope = this->credentialScope(timestamp.date(), region, service);

    QByteArray signedHeaders;
    const QByteArray canonicalRequest = this->canonicalRequest(operation, request, payload, &signedHeaders);

    const QByteArray stringToSign = this->stringToSign(algorithmDesignation, timestamp, credentialScope, canonicalRequest);

    //const QByteArray signingKey = this->signingKey(credentials, timestamp.date(), endpoint.regionName(), endpoint.serviceName());
    const QByteArray signingKey = this->signingKey(credentials, timestamp.date(), region, service);


    const QByteArray signature = QMessageAuthenticationCode::hash(stringToSign, signingKey, hashAlgorithm);

    return algorithmDesignation + " Credential=" + credentials.accessKeyId().toUtf8() + '/' + credentialScope +
            ", SignedHeaders=" + signedHeaders + ", Signature=" + signature.toHex();
}


/*
 * From https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 *
 *
 *
*/
QByteArray AwsSignaturev4::canonicalHeader(const QByteArray &headerName, const QByteArray &headerValue) const
{
    QByteArray header = headerName.toLower() + ':';
    const QByteArray trimmedHeaderValue = headerValue.trimmed();
    bool isInQuotes = false;
    char previousChar = '\0';
    for (int index = 0; index < trimmedHeaderValue.size(); ++index) {
        char thisChar = trimmedHeaderValue.at(index);
        header += thisChar;
        if (isInQuotes) {
            if ((thisChar == '"') && (previousChar != '\\'))
                isInQuotes = false;
        } else {
            if ((thisChar == '"') && (previousChar != '\\')) {
                isInQuotes = true;
            } else if (isspace(thisChar)) {
                while ((index < trimmedHeaderValue.size()-1) &&
                       (isspace(trimmedHeaderValue.at(index+1))))
                    ++index;
            }
        }
        previousChar = thisChar;
    }
    return header;
}


/*
 * From https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 *
 *
 *
*/
QByteArray AwsSignaturev4::canonicalHeaders(const QNetworkRequest &request, QByteArray * const signedHeaders) const
{
    signedHeaders->clear();

    /* Note, Amazon says we should combine duplicate headers with comma separators...
     * conveniently for us, QNetworkRequest requires that to have been done already.
     * See note in QNetworkRequest::setRawHeader.
     */

    // Convert the raw headers list to a map to sort on (lowercased) header names only.
    QMap<QByteArray,QByteArray> headers;
    foreach (const QByteArray &rawHeader, request.rawHeaderList()) {
        headers.insert(rawHeader.toLower(), request.rawHeader(rawHeader));
    }
    // The "host" header is not included in QNetworkRequest::rawHeaderList, but will be sent by Qt.
    headers.insert("host", request.url().host().toUtf8());

    // Convert the headers map to a canonical string, keeping track of which headers we've included too.
    QByteArray canonicalHeaders;
    for (QMap<QByteArray,QByteArray>::const_iterator iter = headers.constBegin(); iter != headers.constEnd(); ++iter) {
        canonicalHeaders += canonicalHeader(iter.key(), iter.value()) + '\n';
        if (!signedHeaders->isEmpty()) *signedHeaders += ';';
        *signedHeaders += iter.key();
    }
    return canonicalHeaders;
}

/*
 *  From https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 *
 *
 *  CanonicalRequest =
 *      HTTPRequestMethod + '\n' +
 *      CanonicalURI + '\n' +
 *      CanonicalQueryString + '\n' +
 *      CanonicalHeaders + '\n' +
 *      SignedHeaders + '\n' +
 *      HexEncode(Hash(RequestPayload))
 *
 */
QByteArray AwsSignaturev4::canonicalRequest(const QNetworkAccessManager::Operation operation, const QNetworkRequest &request,
                            const QByteArray &payload, QByteArray * const signedHeaders) const
{
    return httpMethod(operation).toUtf8() + '\n' +
       canonicalPath(request.url()).toUtf8() + '\n' +
       canonicalQuery(QUrlQuery(request.url()))  + '\n' +
       canonicalHeaders(request, signedHeaders) + '\n' +
       *signedHeaders + '\n' +
       QCryptographicHash::hash(payload, hashAlgorithm).toHex();
}

/*
 * From https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
 *
 * Append the credential scope value, followed by a newline character.
 * This value is a string that includes the date, the Region you are targeting,
 * the service you are requesting, and a termination string ("aws4_request") in
 * lowercase characters. The Region and service name strings must be UTF-8 encoded.
 *
 */
QByteArray AwsSignaturev4::credentialScope(const QDate &date, const QString &region, const QString &service) const
{
    return date.toString(DateFormat).toUtf8() + '/' + region.toUtf8() + '/' + service.toUtf8() + "/aws4_request";
}

/*
 *
 * From https://docs.aws.amazon.com/general/latest/gr/sigv4-calculate-signature.html
 *
 * kSecret = your secret access key
 * kDate = HMAC("AWS4" + kSecret, Date)
 * kRegion = HMAC(kDate, Region)
 * kService = HMAC(kRegion, Service)
 * kSigning = HMAC(kService, "aws4_request")
 *
 */
QByteArray AwsSignaturev4::signingKey(const AwsCredentials &credentials, const QDate &date,
                      const QString &region, const QString &service) const
{
    return QMessageAuthenticationCode::hash("aws4_request",
           QMessageAuthenticationCode::hash(service.toUtf8(),
           QMessageAuthenticationCode::hash(region.toUtf8(),
           QMessageAuthenticationCode::hash(date.toString(DateFormat).toUtf8(), "AWS4"+credentials.secretKey().toUtf8(),
           hashAlgorithm), hashAlgorithm), hashAlgorithm), hashAlgorithm);
}

/*
 * From https://docs.aws.amazon.com/general/latest/gr/sigv4-create-string-to-sign.html
 *
 * StringToSign =
 *   Algorithm + \n +
 *   RequestDateTime + \n +
 *   CredentialScope + \n +
 *   HashedCanonicalReques
 *
 *
 */
QByteArray AwsSignaturev4::stringToSign(const QByteArray &algorithmDesignation, const QDateTime &requestDate,
                        const QByteArray &credentialScope, const QByteArray &canonicalRequest) const
{
    return algorithmDesignation + '\n' +
         requestDate.toString(DateTimeFormat).toUtf8() + '\n' +
         credentialScope + '\n' +
         QCryptographicHash::hash(canonicalRequest, hashAlgorithm).toHex();
}


/*
 * This should be clear
 */
QString AwsSignaturev4::httpMethod(const QNetworkAccessManager::Operation operation) const
{
    switch (operation) {
        case QNetworkAccessManager::DeleteOperation: return QLatin1String("DELETE");
        case QNetworkAccessManager::HeadOperation:   return QLatin1String("HEAD");
        case QNetworkAccessManager::GetOperation:    return QLatin1String("GET");
        case QNetworkAccessManager::PostOperation:   return QLatin1String("POST");
        case QNetworkAccessManager::PutOperation:    return QLatin1String("PUT");
        case QNetworkAccessManager::CustomOperation: // Fall through.
        default:
            // Catch this in debug mode for easier development / debugging.
            Q_ASSERT_X(false, Q_FUNC_INFO, "invalid operation");
    }
    return QString(); // Operation was invalid / unsupported.
}

/*
 * From https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 *
 * To construct the canonical query string, complete the following steps:

 *   Sort the parameter names by character code point in ascending order. Parameters with duplicate names should be sorted by value. For example, a parameter name that begins with the uppercase letter F precedes a parameter name that begins with a lowercase letter b.

 *    URI-encode each parameter name and value according to the following rules:

 *      Do not URI-encode any of the unreserved characters that RFC 3986

 *    defines: A-Z, a-z, 0-9, hyphen ( - ), underscore ( _ ), period ( . ), and tilde ( ~ ).

 *  Percent-encode all other characters with %XY, where X and Y are hexadecimal characters (0-9 and uppercase A-F). For example, the space character must be encoded as %20 (not using '+', as some encoding schemes do) and extended UTF-8 characters must be in the form %XY%ZA%BC.

 *  Double-encode any equals ( = ) characters in parameter values.

 *  Build the canonical query string by starting with the first parameter name in the sorted list.

 *  For each parameter, append the URI-encoded parameter name, followed by the equals sign character (=), followed by the URI-encoded parameter value. Use an empty string for parameters that have no value.

 *  Append the ampersand character (&) after each parameter value, except for the last value in the list.

 *
 *
*/
QByteArray AwsSignaturev4::canonicalQuery(const QUrlQuery &query) const
{
    typedef QPair<QString, QString> QStringPair;
    QList<QStringPair> list = query.queryItems(QUrl::FullyDecoded);
    std::sort(list.begin(), list.end());
    QString result;
    foreach (const QStringPair &pair, list) {
        if (!result.isEmpty()) result += QLatin1Char('&');
        result += QString::fromUtf8(QUrl::toPercentEncoding(pair.first)) + QLatin1Char('=') +
                  QString::fromUtf8(QUrl::toPercentEncoding(pair.second));
    }
    return result.toUtf8();
}

/*
 * From https://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
 *
 * The canonical URI is the URI-encoded version of the absolute path component of the URI,
 * which is everything in the URI from the HTTP host to the question mark character ("?")
 * that begins the query string parameters (if any).
 *
*/
QString AwsSignaturev4::canonicalPath(const QUrl &url) const
{
    QString path = QDir::cleanPath(url.path(QUrl::FullyEncoded));
    if (path.isEmpty()) {
        return QString::fromLatin1("/");
    }

    // If the path begins with "//", remove one of the redundant slashes.
    // Note, this is only needed on Windows, because there QDir::speparator is
    // '\', and internally QDir::cleanPath swaps all separators to '/', before
    // calling qt_normalizePathSegments with allowUncPaths set to true, so that
    // '//' is preserved to allow of Windows UNC paths beginning with '\\'.
    // This should probably be reported as a bug in Qt::cleanPath("//...").
#ifdef Q_OS_WIN
    if (path.startsWith(QLatin1String("//"))) {
        path.remove(0, 1); // Remove the first of two forward slashes.
    }
#endif

    // Restore the trailing '/' if QDir::cleanPath (rightly) removed one.
    if ((url.path().endsWith(QLatin1Char('/'))) && (!path.endsWith(QLatin1Char('/')))) {
        path += QLatin1Char('/');
    }

    return path;
}
