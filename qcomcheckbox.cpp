#include "qcomcheckbox.h"

QComCheckBox::QComCheckBox(QWidget *parent) : QComboBox(parent)
{

}


void QComCheckBox::mousePressEvent(QMouseEvent *e)
{
    if (e->button() == Qt::LeftButton)
    {
        emit clicked();
    }else if(e->button() == Qt::RightButton) {
        emit rightClicked();
    }
    QComboBox::mousePressEvent(e);
}
