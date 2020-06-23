#include "mainwindow.h"
#include "ui_mainwindow.h"
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

    ui->client_table->insertColumn(0);
    ui->client_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    ui->client_table->setHorizontalHeaderLabels(QStringList() << "Client information");

    createCertificates();
    startServer();

    initConnects();
}

MainWindow::~MainWindow()
{
    delete ui;
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
    save_key(SERVER_KEY, cakey);

    CertificateRequestBuilder careqbuilder;
    careqbuilder.setVersion(1);
    careqbuilder.setKey(cakey);
    careqbuilder.addNameEntry(Certificate::EntryCountryName, "GB");
    careqbuilder.addNameEntry(Certificate::EntryOrganizationName, "Westpoint CA Key");
    careqbuilder.addNameEntry(Certificate::EntryOrganizationName, "Westpoint");

    // Sign the request
    CertificateRequest careq = careqbuilder.signedRequest(cakey);
    //save_request(SERVER_PEM, careq);

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
    save_certificate(SERVER_PEM, cacert);
    save_certificate(SERVER_CA_PEM, cacert);

//    //
//    // Create the leaf
//    //
//    QSslKey leafkey = KeyBuilder::generate(QSsl::Rsa, KeyBuilder::StrengthNormal);
//    //save_key(SERVER_KEY, leafkey);

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

void MainWindow::startServer()
{
    m_server = new SSLServer();
    if(m_server->listen(QHostAddress(ui->ip->text()),ui->port->text().toUInt())){
        ui->log->append("Server listening on " + ui->ip->text() + ":" + ui->port->text());
    }
    else{
        ui->log->append("Server has failed to start.");
    }
}

void MainWindow::stopServer()
{
    m_server->close();
    if(!m_server->isListening()){
        ui->log->append("Server is stopped");
    }
    else{
        ui->log->append("Server has failed to stop.");
    }
}

void MainWindow::initConnects()
{
    connect(m_server,           SIGNAL(appendToLog(const QString&)),    this,       SLOT(appendToLogSlot(const QString&)));
    connect(m_server,           SIGNAL(receiveString(QString)),         this,       SLOT(onClientData(QString)));
    connect(m_server,           SIGNAL(updateClientList(const QVector<QSslSocket*>&)),
            this,               SLOT(updateClientListSlot(const QVector<QSslSocket*>&)));
    connect(this,               SIGNAL(sendMessage(QString)),           m_server,   SLOT(onSendMessage(QString)));
    connect(ui->btn_send,       SIGNAL(clicked(bool)),                  this,       SLOT(onSendClicked(bool)));
    connect(ui->btn_generate,   SIGNAL(clicked(bool)),                  this,       SLOT(onGenerateKey(bool)));
}

void MainWindow::on_button_start_server_clicked()
{
    startServer();
}

void MainWindow::on_button_stop_server_clicked()
{
    stopServer();
}

//! [ Slots ]

void MainWindow::appendToLogSlot(const QString & str)
{
    ui->log->append(str);
}

void MainWindow::updateClientListSlot(const QVector<QSslSocket*>& connectedSockets)
{
    ui->client_table->clearContents();
    ui->client_table->setRowCount(0);

    for(QSslSocket* const &  s : connectedSockets){
        ui->client_table->insertRow(ui->client_table->rowCount());

       ui->client_table->setItem(ui->client_table->rowCount()-1,0, new QTableWidgetItem(s->peerAddress().toString() + ":" + QString::number(s->peerPort()) + " [" + QString::number(s->socketDescriptor()) + "]"));
      //ui->client_table->setItem(ui->client_table->rowCount()-1,0, new QTableWidgetItem("ahoj"));

    }
}

void MainWindow::onClientData(QString data)
{
    ui->client_data->append(data);
}

void MainWindow::onSendClicked(bool clicked)
{
    Q_UNUSED(clicked);

    QString msg_str = ui->edt_send_data->toPlainText();
    emit sendMessage(msg_str);
}

bool MainWindow::onGenerateKey(bool clicked)
{
    Q_UNUSED(clicked);
    createCertificates();
    return true;
}

//! [ Slots ]
