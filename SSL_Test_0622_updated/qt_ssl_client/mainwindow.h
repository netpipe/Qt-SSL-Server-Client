#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QAbstractSocket>
#include <QSslError>
#include <QPixmap>
#include <QDebug>
#include "define.h"

#ifdef SELF_SIGN
    #include "csslsocket.h"
#else
    #include <QSslSocket>
#endif

QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

    void run();
public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void createSocket();
    void createCertificates();
private slots:
    void on_button_connect_clicked();
    void connectedSlot();
    void disconnectedSlot();
    void errorSlot(QAbstractSocket::SocketError);
    void stateChangedSlot(QAbstractSocket::SocketState s);
    void encryptedSlot();
    void sslErrorsSlot(const QList<QSslError> &errors);

    void on_button_send_clicked();

    void onReceiveMessage();
    void onGenerateKey(bool clicked);
private:
    Ui::MainWindow *ui;
#ifdef SELF_SIGN
    CSslSocket* socket;
#else
    QSslSocket* socket;
#endif
};
#endif // MAINWINDOW_H
