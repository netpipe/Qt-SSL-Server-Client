#include "sslserver.h"
#include <QBuffer>
#include <QTcpSocket>
#include <QFile>
SSLServer::SSLServer(QObject *parent) : QTcpServer(parent)
{
#if 0
    pathToCert = QString(PRO_PWD)+"/server.pem";
    pathToPrivateKey= QString(PRO_PWD)+"/server.key";
    qDebug() << pathToCert;
#else
    pathToPrivateKey = QString("../certificates/server_local.key");
    QFile key_file(pathToPrivateKey);
    key_file.open(QFile::ReadOnly);

    m_key = QSslKey(key_file.readAll(), QSsl::Rsa);
    key_file.close();

    pathToCert = QString("../certificates/server_local.pem");
    QFile cert_file(pathToCert);
    cert_file.open(QFile::ReadOnly);
    m_cert = QSslCertificate(cert_file.readAll());
    cert_file.close();

#endif
}

void SSLServer::incomingConnection(qintptr socketDescriptor)
{
    QSslSocket* socket = new QSslSocket(this);

    //connect(socket, SIGNAL(disconnected()),this, SLOT(disconnectedSlot()));
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)),this, SLOT(errorSlot(QAbstractSocket::SocketError)));
    connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),this, SLOT(stateChangedSlot(QAbstractSocket::SocketState)));
    connect(socket, SIGNAL(sslErrors(const QList<QSslError> &)),this, SLOT(sslErrorsSlot(const QList<QSslError> &)));
    //connect(socket, SIGNAL(readyRead()), this, SLOT(receiveMessage()), Qt::DirectConnection);
    connect(this, &SSLServer::newConnection, this, &SSLServer::link);

    socket->setSocketDescriptor(socketDescriptor);
    socket->setPrivateKey(m_key);
    socket->setLocalCertificate(m_cert);
    socket->addCaCertificates("../certificates/client_ca.pem");
    socket->setPeerVerifyMode(QSslSocket::VerifyPeer);
    socket->startServerEncryption();

    addPendingConnection(socket);

    qDebug() << socket->localCertificate().isNull();

    this->sockets.push_back(socket);
    emit appendToLog("Server received a new connection [socket descriptor: " + QString::number(socketDescriptor) + "]");
    emit updateClientList(this->sockets);
}

void SSLServer::link()
{
    QTcpSocket *clientSocket;

    clientSocket = nextPendingConnection();
    connect(clientSocket, &QTcpSocket::readyRead, this, &SSLServer::receiveMessage);
    connect(clientSocket, &QTcpSocket::disconnected, this, &SSLServer::disconnectedSlot);
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
//    qint64 bytes = buffer->write(socket->readAll());
//    qDebug() << "Reading From: " << socket <<"@@ bytes:" << bytes;
//    buffer->seek(buffer->pos() - bytes);



//    while (buffer->canReadLine()) {
//        QByteArray line = buffer->readLine();
//        //this list holds the sockets currently connected:
////        foreach (QSslSocket* connection, connections) {
////            qDebug() << "Writing to: " << connection;

////            connection->write(line);
////        }
//    }
}
