#include "sslserver.h"
#include <QBuffer>
#include <QTcpSocket>
#include <QFile>
#include <QMessageBox>
#include <QSslConfiguration>

SSLServer::SSLServer(QObject *parent) : QTcpServer(parent)
{
#if 0
    pathToCert = QString(PRO_PWD)+"/server.pem";
    pathToPrivateKey= QString(PRO_PWD)+"/server.key";
    qDebug() << pathToCert;
#else
    pathToPrivateKey = QString(SERVER_KEY);
    QFile key_file(pathToPrivateKey);
    if(!key_file.open(QFile::ReadOnly))
    {
        QMessageBox::critical(nullptr, QString("File open error"), QString("Can't open %1").arg(SERVER_KEY));
        return;
    }

    m_key = QSslKey(key_file.readAll(), QSsl::Rsa);
    key_file.close();

    pathToCert = QString(SERVER_PEM);
    QFile cert_file(pathToCert);
    if(!cert_file.open(QFile::ReadOnly))
    {
        QMessageBox::critical(nullptr, QString("File open error"), QString("Can't open %1").arg(SERVER_PEM));
        return;
    }
    m_cert = QSslCertificate(cert_file.readAll());
    cert_file.close();

#endif
}

void SSLServer::incomingConnection(qintptr socketDescriptor)
{
#ifndef SELF_SIGN
    QSslSocket* socket = new QSslSocket(this);

    //connect(socket, SIGNAL(disconnected()),this, SLOT(disconnectedSlot()));
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)),this, SLOT(errorSlot(QAbstractSocket::SocketError)));
    connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),this, SLOT(stateChangedSlot(QAbstractSocket::SocketState)));
    connect(socket, SIGNAL(sslErrors(const QList<QSslError> &)),this, SLOT(sslErrorsSlot(const QList<QSslError> &)));
    //connect(socket, SIGNAL(readyRead()), this, SLOT(receiveMessage()), Qt::DirectConnection);
    connect(this, &SSLServer::newConnection, this, &SSLServer::link);

   if(socket->setSocketDescriptor(socketDescriptor))
   {
//       QList<QSslCertificate> certificates = QSslConfiguration::systemCaCertificates();
//       QSslConfiguration configuration = QSslConfiguration::defaultConfiguration();
//       configuration.setCaCertificates(certificates);
//       QSslConfiguration::setDefaultConfiguration(configuration);
//       socket->setSslConfiguration(configuration);
       socket->setPrivateKey(m_key);
       socket->setLocalCertificate(m_cert);
       addPendingConnection(socket);
       socket->startServerEncryption();
       //socket->addCaCertificates(CLIENT_CA_PEM);
   }else {
        delete socket;
   }
    socket->setPeerVerifyMode(QSslSocket::VerifyNone);
    socket->ignoreSslErrors ({QSslError :: SelfSignedCertificate});


    qDebug() << socket->localCertificate().isNull();

    this->sockets.push_back(socket);
    emit appendToLog("Server received a new connection [socket descriptor: " + QString::number(socketDescriptor) + "]");
    emit updateClientList(this->sockets);
#else
    QSslSocket * sock = new QSslSocket(this);

        if(sock->setSocketDescriptor(socketDescriptor))
        {
            connect(sock, &QSslSocket::encrypted, [sock, this]
            {	addPendingConnection(sock);
                Q_EMIT receiveMessage();
            });

            connect(sock, static_cast<void (QSslSocket:: *)(const QList<QSslError> &)>(&QSslSocket::sslErrors), [sock](const QList<QSslError> & errors)
            {	for(const QSslError & e : errors)
                {
                    qCritical("SSL Handshake error: %s", qPrintable(e.errorString()));
                }
            delete sock;
            });
            connect(sock, static_cast<void (QAbstractSocket:: *)(QAbstractSocket::SocketError)>(&QAbstractSocket::error), [sock](QAbstractSocket::SocketError e)
            {
                switch(e)
                {
                    case QAbstractSocket::RemoteHostClosedError: return;
                    default:
                    qWarning("Client '%s' error: %s", qPrintable(sock->peerAddress().toString()), qPrintable(sock->errorString()));
                    sock->disconnectFromHost();
                }
            });

            sock->ignoreSslErrors({QSslError::SelfSignedCertificate});
            sock->startServerEncryption();
            //addPendingConnection(sock);

            qDebug() << sock->localCertificate().isNull();

            this->sockets.push_back(sock);
            emit appendToLog("Server received a new connection [socket descriptor: " + QString::number(socketDescriptor) + "]");
            emit updateClientList(this->sockets);
        }
        else
        {
            delete sock;
        }
#endif
}

void SSLServer::link()
{
    QSslSocket *clientSocket;

    clientSocket = (QSslSocket*)nextPendingConnection();
    connect(clientSocket, &QSslSocket::readyRead, this, &SSLServer::receiveMessage);
    connect(clientSocket, &QSslSocket::disconnected, this, &SSLServer::disconnectedSlot);
}

bool SSLServer::onSendMessage(QString message)
{
    foreach (QSslSocket* socket, sockets) {
        QByteArray data = message.toLatin1();
        qint64 bytes = socket->write((const char*)data);
        qDebug() << "Send data bytes:" << bytes;
    }
    return true;
}

void SSLServer::disconnectedSlot()
{
    QSslSocket* socket = qobject_cast<QSslSocket*>(sender());
    this->sockets.removeOne(socket);

    emit appendToLog("Client disconnected " + socket->peerAddress().toString() + ":" + QString::number(socket->peerPort()));
    emit updateClientList(this->sockets);
}

void SSLServer::errorSlot(QAbstractSocket::SocketError e)
{
    emit appendToLog("Socket Error: " + QString::number(e));
}

void SSLServer::stateChangedSlot(QAbstractSocket::SocketState s)
{
  emit appendToLog("Socket State: " + QString::number(s));
}

void SSLServer::sslErrorsSlot(const QList<QSslError> &)
{
    emit appendToLog("SSL Error");
}

void SSLServer::receiveMessage()
{
    QSslSocket* socket = static_cast<QSslSocket*>(sender());
    QBuffer* buffer = new QBuffer(this);
    // missing some checks for returns values for the sake of simplicity
    buffer->open(QIODevice::ReadWrite);
    QByteArray array = socket->readAll();
    emit receiveString(QString(array));
}
