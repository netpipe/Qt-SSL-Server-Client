#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QThread>
#include <QMessageBox>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    socket = new QSslSocket(this);

    connect(socket, SIGNAL(connected()),this,SLOT(connectedSlot()));
    connect(socket, SIGNAL(disconnected()),this,SLOT(disconnectedSlot()));
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)),this,SLOT(errorSlot(QAbstractSocket::SocketError)));
    connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),this,SLOT(stateChangedSlot(QAbstractSocket::SocketState)));
    connect(socket, SIGNAL(encrypted()),this, SLOT(encryptedSlot()));
    connect(socket, SIGNAL(sslErrors(const QList<QSslError> &)),this, SLOT(sslErrorsSlot(const QList<QSslError> &)));
    connect(socket, SIGNAL(readyRead()), this, SLOT(onReceiveMessage()), Qt::DirectConnection);
#if 0
    QString certify = QString(PRO_PWD) + "/server.pem";
#else
    socket->addCaCertificates("../certificates/server_ca.pem");
    socket->setPrivateKey("../certificates/client_local.key");
    socket->setLocalCertificate("../certificates/client_local.pem");
    socket->setPeerVerifyMode(QSslSocket::VerifyPeer);

    ui->statusbar->showMessage("Unconnected");
#endif
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_button_connect_clicked()
{
    socket->connectToHostEncrypted(ui->ip->text(),ui->port->text().toUInt());

    if (socket->waitForEncrypted()) {
        socket->write("Authentication Suceeded");
    }
    else {
        qDebug("Unable to connect to server");
    }

}

void MainWindow::connectedSlot()
{
    ui->log->append("Connected successfully [socket descriptor: " + QString::number(socket->socketDescriptor()) + "]");
    ui->statusbar->showMessage("Connected");
}

void MainWindow::disconnectedSlot()
{
    ui->log->append("Disconnected");
    ui->statusbar->showMessage("Disconnected");
}

void MainWindow::errorSlot(QAbstractSocket::SocketError e)
{
    ui->log->append("Error [" + QString::number(e) + "]: " + this->socket->errorString());
}

void MainWindow::stateChangedSlot(QAbstractSocket::SocketState s)
{
    ui->log->append("State: " + QString::number(s));
}

void MainWindow::encryptedSlot()
{
    ui->log->append("Connection is encrypted");
}

void MainWindow::sslErrorsSlot(const QList<QSslError> &errors)
{

    for(const QSslError& e : errors){
        ui->log->append("SSL Error: " + e.errorString());
    }
}

void MainWindow::on_button_send_clicked()
{
    qDebug() << socket->isEncrypted() << "Encrypted";
    QByteArray byte_array = ui->textEdit->toPlainText().toLatin1();
    qint64 bytes = socket->write((const char*)byte_array);
    socket->flush();

    qDebug() << "Message sent : " << bytes << "bytes";
}

void MainWindow::onReceiveMessage()
{
    QByteArray array = socket->readAll();
    ui->edt_receive_data->append(QString(array));
}
