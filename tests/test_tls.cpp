// Regression test for the media path's TLS posture.
//
// Reolink devices serve HTTPS with a SELF-SIGNED certificate; the app accepts
// that everywhere (the HTTP-CGI transport sets CURLOPT_SSL_VERIFYPEER 0). The
// media path used to rely on FFmpeg's old tls_verify=0 default instead of
// saying so — and FFmpeg 8.0 flipped that default to 1, which broke playback
// with "Peer certificate failed verification" on any system with a modern
// FFmpeg (Arch/AUR today; the bundled builds whenever their base image moves).
//
// The assertion deliberately does NOT look at error strings or decode success:
// it serves HTTPS from a self-signed cert and checks whether the server ever
// receives the HTTP request. If certificate verification is on, FFmpeg aborts
// during the TLS handshake and no request arrives. If it is off, the request
// lands. That is a direct, wording-independent probe of the regression.
#include "media/StreamPlayer.h"

#include <QSslKey>
#include <QSslServer>
#include <QSslSocket>
#include <QTcpSocket>
#include <QtTest>

static const char *kTestCertPem =
    "-----BEGIN CERTIFICATE-----\n"
    "MIIDJzCCAg+gAwIBAgIUdL5PP6GuEi2lYdgNaumHk/ifX1AwDQYJKoZIhvcNAQEL\n"
    "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDgxMjE0MjIyMFoYDzIxMjYw\n"
    "NzE5MTQyMjIwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB\n"
    "AQUAA4IBDwAwggEKAoIBAQC7HaBhhwu5L5vOsnyfTlnlUYaJQBeHexZ5QHaAGLI1\n"
    "Qr9t299CNK/bd12dVa101WMl7i0r2yH0a+0Z48im8ibzkIFrHQ182az3GQrMLo7s\n"
    "8vIpIgc0IsSRVVGpRzLXJJOihej3eSXNkMVff3zmhK6UgzfXRrh5o3BUbAMMDwBh\n"
    "m5q52GSbVGeLV8SIaOLWWH+hsmIv6t3XUJBUfEbugGLeX0HqNagKsA3RU18/jWXC\n"
    "lTMKeORsUXRXIaFmI1GIL4FVNGRJr5vGj5aVfd3yJtvd+5DhJDF6kvuvOBXplEA+\n"
    "9yu+SbJzPbVHJ4+/DidnimIJ08mB2o5Hh0dSW1/8cdfTAgMBAAGjbzBtMB0GA1Ud\n"
    "DgQWBBRGMqQ9HSpHVviBzTUSEfkPTXdqdzAfBgNVHSMEGDAWgBRGMqQ9HSpHVviB\n"
    "zTUSEfkPTXdqdzAPBgNVHRMBAf8EBTADAQH/MBoGA1UdEQQTMBGHBH8AAAGCCWxv\n"
    "Y2FsaG9zdDANBgkqhkiG9w0BAQsFAAOCAQEAYIpn1xG8rs3Ll8qc22R5EKm1p0oS\n"
    "xUVQOP9DDXcx52BpZTu6stq7aZ5zKH+yuTHHi7gQq011ArK9hKVoE1LkFKdKgE8q\n"
    "0BHb/Jwlplg8rp4YKOPSL5R/6FxvYV6ELYt3MFubSaoKUtc9FFmoy6wPTn2t++0A\n"
    "ofazHMmnFVfNs126tXY7Foxq+EisV5bLwmWCuLSDUsunGzKSXOX9RDnusyRzSqIQ\n"
    "Qn8er/9se1j4vEHjgp0tS7uZhpDLvZXalA2TPsJgm0foseOH3EmvooBTqCRBcsCt\n"
    "1V+YSrFtRJAGQrD1jT3L9Gs/v45eFQBDuAPfRwX0FnB3Ww+At4TeO0lfsA==\n"
    "-----END CERTIFICATE-----\n";

static const char *kTestKeyPem =
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7HaBhhwu5L5vO\n"
    "snyfTlnlUYaJQBeHexZ5QHaAGLI1Qr9t299CNK/bd12dVa101WMl7i0r2yH0a+0Z\n"
    "48im8ibzkIFrHQ182az3GQrMLo7s8vIpIgc0IsSRVVGpRzLXJJOihej3eSXNkMVf\n"
    "f3zmhK6UgzfXRrh5o3BUbAMMDwBhm5q52GSbVGeLV8SIaOLWWH+hsmIv6t3XUJBU\n"
    "fEbugGLeX0HqNagKsA3RU18/jWXClTMKeORsUXRXIaFmI1GIL4FVNGRJr5vGj5aV\n"
    "fd3yJtvd+5DhJDF6kvuvOBXplEA+9yu+SbJzPbVHJ4+/DidnimIJ08mB2o5Hh0dS\n"
    "W1/8cdfTAgMBAAECggEARrym/memu23vmX7pVPIyUtp0oVtc6cdTEiiYA8oSSMdA\n"
    "hiAKcUVou++OsOWMavAmiNbXNc6kMfpBCroNh2tg5VAaVOuJR0slM87AQbtSJeqc\n"
    "OIeYMJH6PLUD55o2cpXtyBGWpkOi0mkp7HXOOnkrZJKMoDIomDd8xjWFG2BqdPtP\n"
    "9+yv66taZ9y97H+kHfyWjlJYD5WuvrpIvt4ZE+cfJXwYUmjWzs2Kr/PnGHL/eOFF\n"
    "CyBonKNsli2awRblkadPpPQinpOheAUxTOOKZ+qahuhJK1lZYYGWMl0HVHMWyc34\n"
    "M9ddH7bIaoUcaRoTKyW2eeuW0+PE0yLR9FrSnj14OQKBgQDppCQZeqIHpMVH5ab2\n"
    "HHaIXurwFmRvQHzEiao8bHlgRVlJl3kLM4zbBeYPq7JiMUsepy2p7439+tvE1nLn\n"
    "coXIe3kZJwI1sLnPHBrXyY915pm068kzEpu6Fny+QA4ku9ozSBPNUw9uzOqujgj1\n"
    "FQhEh9i7Ts1FBxmy+WOLS700aQKBgQDNBa6COpKJ3CJzXWHr7IrO8CYYYtF4b+81\n"
    "j/Ij8n4YU5Wg9u72S4cPS+DMyA+bz+X965gba90nCiv34mQlfWkbqlex6y65NgUh\n"
    "jKYWAm6sFaN7YbHNZN8bPed+EHHGds3c1skGIgv6vCp3o81e8oNBeYxnfDpLJhKh\n"
    "HKR0sV2y2wKBgC1MF3uhHPziYyU3TxF0Hz79OAtoK/ytwgLQteKVHUse5tqvtVYI\n"
    "noxwLlRnc2Q6Llg5DU9fFGZjVmxpL0nUGD/wQGAyAemq47tVtZaUi23OUYqUFCQE\n"
    "vZBsf67a+GMC0KEUnlI2gk13CSDihLYPZ9TxiYF3G7EAWWkrlLMS8hHRAoGBAIlV\n"
    "kPvzOE3Yg8s7dmiO3ryX6SzUpPREJrx+W/jwar7o3oYgYxngpev9K+yA5tO8g5d/\n"
    "xTg5HL8V9TXrFKJ4S3wYsv2fSIEQSoeaq3Z60p+7LvNrEatAMqMQ6Ixtf4kt8+BG\n"
    "kAnnrJacjOXvd5ZuZLXrMb3wXSwRqND7Wr5AQT+ZAoGADlFrdYBOZ2w+3lUozsgS\n"
    "+SCQOVmjMamog+nWj65A860m+ehHXo26ikaVnEItUAJmAeTICyr7hx0OtzCQA4nr\n"
    "zP/kM7BXCpsMjnFPSt63IM6Gzw3swCreIacPnuoXI9RvBbkAjt2FQ8K0Ql6KJ4OP\n"
    "v8+at7q8QCgeeLyLaUKtSxI=\n"
    "-----END PRIVATE KEY-----\n";

using namespace rl;

class TestTls : public QObject
{
    Q_OBJECT

private slots:
    void initTestCase()
    {
        if (!QSslSocket::supportsSsl())
            QSKIP("no TLS backend available in this Qt build");
    }

    // Serve HTTPS with a self-signed cert; the media path must get past the
    // handshake and actually issue its GET.
    void mediaPathAcceptsSelfSignedCertificate()
    {
        const QSslCertificate cert(QByteArray(kTestCertPem), QSsl::Pem);
        const QSslKey key(QByteArray(kTestKeyPem), QSsl::Rsa, QSsl::Pem);
        QVERIFY(!cert.isNull());
        QVERIFY(!key.isNull());

        QSslConfiguration cfg = QSslConfiguration::defaultConfiguration();
        cfg.setLocalCertificate(cert);
        cfg.setPrivateKey(key);
        cfg.setPeerVerifyMode(QSslSocket::VerifyNone); // don't ask the client for one

        QSslServer server;
        server.setSslConfiguration(cfg);
        QVERIFY2(server.listen(QHostAddress::LocalHost), qPrintable(server.errorString()));

        bool sawRequest = false;
        connect(&server, &QSslServer::pendingConnectionAvailable, this, [&] {
            while (QTcpSocket *s = server.nextPendingConnection()) {
                connect(s, &QTcpSocket::readyRead, this, [&sawRequest, s] {
                    if (s->readAll().contains("GET"))
                        sawRequest = true; // handshake completed and FFmpeg spoke HTTP
                });
                connect(s, &QTcpSocket::disconnected, s, &QObject::deleteLater);
            }
        });

        StreamPlayer player;
        player.setSource(QStringLiteral("https://127.0.0.1:%1/playback.flv").arg(server.serverPort()));
        player.start();

        // Poll rather than assert immediately: the open runs on a worker thread.
        QTRY_VERIFY_WITH_TIMEOUT(sawRequest, 15000);
        player.stop();
    }
};

QTEST_MAIN(TestTls)
#include "test_tls.moc"
