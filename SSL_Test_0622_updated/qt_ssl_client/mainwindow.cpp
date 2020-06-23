#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
#include <QThread>
#include <QProcess>
#include <QDateTime>
#include <QSslCertificate>
#include <QSslKey>
#include <QFile>

#include "keybuilder.h"
#include "certificaterequestbuilder.h"
#include "certificaterequest.h"
#include "certificatebuilder.h"
#include "randomgenerator.h"
#include "certificate.h"

QT_USE_NAMESPACE_CERTIFICATE

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    ui->btn_generate->setVisible(false);
    createCertificates();
}

void save_key(const QString &filename, const QSslKey &key)
{
    QFile k(filename);
    k.open(QIODevice::WriteOnly);
    k.write(key.toPem());
    k.close();
}

void save_request(const QString &filename, CertificateRequest &req)
{
    QFile k(filename);
    k.open(QIODevice::WriteOnly);
    k.write(req.toPem());
    k.close();
}

void save_certificate(const QString &filename, const QSslCertificate &crt)
{
    QFile k(filename);
    k.open(QIODevice::WriteOnly);
    k.write(crt.toPem());
    k.close();
}

void MainWindow::createCertificates()
{
    //
    // Create the CA key
    //
    QSslKey cakey = KeyBuilder::generate(QSsl::Rsa, KeyBuilder::StrengthNormal);
    save_key(CLIENT_KEY, cakey);

    CertificateRequestBuilder careqbuilder;
    careqbuilder.setVersion(1);
    careqbuilder.setKey(cakey);
    careqbuilder.addNameEntry(Certificate::EntryCountryName, "GB");
    careqbuilder.addNameEntry(Certificate::EntryOrganizationName, "Westpoint CA Key");
    careqbuilder.addNameEntry(Certificate::EntryOrganizationName, "Westpoint");

    // Sign the request
    CertificateRequest careq = careqbuilder.signedRequest(cakey);
    //save_request(CLIENT_PEM, careq);

    //
    // Now make a certificate
    //
    CertificateBuilder cabuilder;
    cabuilder.setRequest(careq);

    cabuilder.setVersion(3);
    cabuilder.setSerial(RandomGenerator::getPositiveBytes(16));
    cabuilder.setActivationTime(QDateTime::currentDateTimeUtc());
    cabuilder.setExpirationTime(QDateTime::currentDateTimeUtc());
    cabuilder.setBasicConstraints(true);
    cabuilder.setKeyUsage(CertificateBuilder::UsageCrlSign|CertificateBuilder::UsageKeyCertSign);
    cabuilder.addSubjectKeyIdentifier();

    QSslCertificate cacert = cabuilder.signedCertificate(cakey);
    save_certificate(CLIENT_PEM, cacert);
    save_certificate(CLIENT_CA_PEM, cacert);

//    //
//    // Create the leaf
//    //
//    QSslKey leafkey = KeyBuilder::generate(QSsl::Rsa, KeyBuilder::StrengthNormal);
//    //save_key("leaf.key", leafkey);

//    CertificateRequestBuilder leafreqbuilder;
//    leafreqbuilder.setVersion(1);
//    leafreqbuilder.setKey(leafkey);
//    leafreqbuilder.addNameEntry(Certificate::EntryCountryName, "GB");
//    leafreqbuilder.addNameEntry(Certificate::EntryOrganizationName, "Westpoint");
//    leafreqbuilder.addNameEntry(Certificate::EntryCommonName, "www.example.com");
//    leafreqbuilder.addSubjectAlternativeNameEntry(QSsl::DnsEntry, "www.example.com");
//    leafreqbuilder.addSubjectAlternativeNameEntry(QSsl::EmailEntry, "test@example.com");

//    CertificateRequest leafreq = leafreqbuilder.signedRequest(leafkey);
//    //save_request("leaf.req", leafreq);

//    CertificateBuilder leafbuilder;
//    leafbuilder.setRequest(leafreq);

//    leafbuilder.setVersion(3);
//    leafbuilder.setSerial(RandomGenerator::getPositiveBytes(16));
//    leafbuilder.setActivationTime(QDateTime::currentDateTimeUtc());
//    leafbuilder.setExpirationTime(QDateTime::currentDateTimeUtc());
//    leafbuilder.copyRequestExtensions(leafreq);
//    leafbuilder.setBasicConstraints(false);
//    leafbuilder.addKeyPurpose(CertificateBuilder::PurposeWebServer);
//    leafbuilder.setKeyUsage(CertificateBuilder::UsageKeyAgreement|CertificateBuilder::UsageKeyEncipherment);
//    leafbuilder.addSubjectKeyIdentifier();
//    leafbuilder.addAuthorityKeyIdentifier(cacert);

//    QSslCertificate leafcert = leafbuilder.signedCertificate(cacert, cakey);
//    //save_certificate("leaf.crt", leafcert);
}

void MainWindow::createSocket()
{
#ifdef SELF_SIGN
    socket = new CSslSocket(this);
#else

    socket = new QSslSocket(this);
    socket->addCaCertificates(SERVER_CA_PEM);
//    QList<QSslCertificate> certificates = QSslConfiguration::systemCaCertificates();
//    QSslConfiguration configuration = QSslConfiguration::defaultConfiguration();
//    configuration.setCaCertificates(certificates);
//    QSslConfiguration::setDefaultConfiguration(configuration);
//    socket->setSslConfiguration(configuration);

    socket->setPrivateKey(CLIENT_KEY);
    socket->setLocalCertificate(CLIENT_PEM);

    socket->setPeerVerifyMode(QSslSocket::VerifyNone);
#endif
    socket->ignoreSslErrors({QSslError::SelfSignedCertificate});

    connect(socket, SIGNAL(connected()),this,SLOT(connectedSlot()));
    connect(socket, SIGNAL(disconnected()),this,SLOT(disconnectedSlot()));
    connect(socket, SIGNAL(error(QAbstractSocket::SocketError)),this,SLOT(errorSlot(QAbstractSocket::SocketError)));
    connect(socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)),this,SLOT(stateChangedSlot(QAbstractSocket::SocketState)));
    connect(socket, SIGNAL(encrypted()),this, SLOT(encryptedSlot()));
    connect(socket, SIGNAL(sslErrors(const QList<QSslError> &)),this, SLOT(sslErrorsSlot(const QList<QSslError> &)));
    connect(socket, SIGNAL(readyRead()), this, SLOT(onReceiveMessage()), Qt::DirectConnection);

    ui->statusbar->showMessage("Unconnected");

    connect(ui->btn_generate, SIGNAL(clicked(bool)), this, SLOT(onGenerateKey(bool)));
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::onGenerateKey(bool clicked)
{
    createCertificates();
}

void MainWindow::on_button_connect_clicked()
{
    createSocket();

    socket->connectToHostEncrypted(ui->ip->text(), ui->port->text().toUInt());

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
