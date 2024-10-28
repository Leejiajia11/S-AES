#ifndef ATTACK_H
#define ATTACK_H

#include <QDialog>

namespace Ui {
class Attack;
}

class Attack : public QDialog
{
    Q_OBJECT

public:
    explicit Attack(QWidget *parent = nullptr);
    ~Attack();


private slots:
    void on_MiddleAttack_clicked();

private:
    Ui::Attack *ui;

    void MeetInTheMiddleAttack(uint16_t plaintext, uint16_t ciphertext); // 确保 MeetInTheMiddleAttack 是类的私有成员函数
    void DecryptTask(uint16_t ciphertext, uint16_t start, uint16_t end);
};

#endif // ATTACK_H
