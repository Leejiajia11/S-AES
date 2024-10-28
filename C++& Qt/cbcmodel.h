#ifndef CBCMODEL_H
#define CBCMODEL_H

#include <QDialog>

namespace Ui {
class CBCmodel;
}

class CBCmodel : public QDialog
{
    Q_OBJECT

public:
    explicit CBCmodel(QWidget *parent = nullptr);
    ~CBCmodel();

private slots:
    void on_cbcEncryptButton_clicked();

    void on_cbcDecryptButton_clicked();

    void on_tamperCiphertextButton_clicked();

private:
    Ui::CBCmodel *ui;
};

#endif // CBCMODEL_H
