#ifndef SSLSERVER_H
#define SSLSERVER_H

#include <QObject>
#include <QTcpServer>
#include <QSslSocket>
#include <QSslKey>
#include <QSslCertificate>
#include <QVector>
#include <QDir>

class SSLServer : public QTcpServer
{
    Q_OBJECT
public:
    explicit SSLServer(QObject *parent = nullptr);

private:
    QVector<QSslSocket*> sockets;
    QString pathToCert,pathToPrivateKey;

    QSslKey m_key;
    QSslCertificate m_cert;

protected:
    void incomingConnection(qintptr socketDescriptor) override;
private slots:
    void disconnectedSlot();
    void errorSlot(QAbstractSocket::SocketError);
    void stateChangedSlot(QAbstractSocket::SocketState);
    void sslErrorsSlot(const QList<QSslError> &);
    void receiveMessage();
    void link();
    bool onSendMessage(QString message);
signals:
    void appendToLog(const QString&);
    void updateClientList(const QVector<QSslSocket*>&);
    void receiveString(QString);
};

#endif // SSLSERVER_H
