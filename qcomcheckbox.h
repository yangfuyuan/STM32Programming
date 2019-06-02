#ifndef QCOMCHECKBOX_H
#define QCOMCHECKBOX_H

#include <QComboBox>
#include <QMouseEvent>

class QComCheckBox : public QComboBox
{
    Q_OBJECT
public:
   explicit QComCheckBox(QWidget *parent = Q_NULLPTR);

protected:
    virtual void mousePressEvent(QMouseEvent *e);

signals:
    void clicked();
    void rightClicked();
};

#endif // QCOMCHECKBOX_H
