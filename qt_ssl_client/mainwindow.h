#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QAbstractSocket>
#include <QSslSocket>
#include <QSslError>
#include <QPixmap>
#include <QDebug>

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
private:
    Ui::MainWindow *ui;
    QSslSocket* socket;
};
#endif // MAINWINDOW_H
