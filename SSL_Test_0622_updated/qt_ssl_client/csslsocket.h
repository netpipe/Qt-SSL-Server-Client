#ifndef CSSLSOCKET_H
#define CSSLSOCKET_H

#include <QObject>
#include <QSslSocket>


class CSslSocket : public QSslSocket
{
    Q_OBJECT
public:
    CSslSocket(QObject* parent = 0);
};

#endif // CSSLSOCKET_H
