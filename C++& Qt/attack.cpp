#include "attack.h"
#include "ui_attack.h"
#include <cstdint>
#include <QString>
#include <QDebug>
#include <omp.h>
#include <QHash>
#include <QtConcurrent/QtConcurrent>
#include <thread>
#include <mutex>
#include <vector>

Attack::Attack(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Attack)
{
    ui->setupUi(this);
}

Attack::~Attack()
{
    delete ui;
}

// 声明常量和函数为外部的
extern const uint8_t SBox[4][4];
extern const uint8_t RCON1;
extern const uint8_t RCON2;
extern const uint8_t GF_MulTable[16][16];

extern uint8_t SubNib(uint8_t nibble);
extern void KeyExpansion(uint16_t key, uint16_t& roundKey1, uint16_t& roundKey2);
extern uint16_t AddRoundKey(uint16_t state, uint16_t roundKey);
extern uint16_t NibbleSubstitution(uint16_t state);
extern uint16_t ShiftRows(uint16_t state);
extern uint16_t MixColumns(uint16_t state);
extern uint8_t GF_Multiply(uint8_t a, uint8_t b);
extern uint16_t BinaryStringToUInt16(const QString& binaryStr);
extern uint16_t Encrypt(uint16_t plaintext, uint16_t key);
extern uint16_t Decrypt(uint16_t plaintext, uint16_t key);


// 全局变量
QHash<uint16_t, QPair<uint16_t, bool>> map;  // 存储 E_{K1}(P) 和 D_{K2}(C) -> (密钥, 标记)
std::mutex mapMutex;  // 保护共享哈希表的互斥锁
bool keyFound = false;  // 用于标记是否已找到密钥对

// 中间相遇攻击的实现
void Attack::MeetInTheMiddleAttack(uint16_t plaintext, uint16_t ciphertext) {
    const int numThreads = 16;  // 设置线程数
       std::vector<std::thread> threads;

       // 第一步：创建16个线程进行 E_{K1}(P) 计算
       uint16_t rangeSize = 65536 / numThreads;
       for (int i = 0; i < numThreads; ++i) {
           uint16_t start = i * rangeSize;
           uint16_t end = (i == numThreads - 1) ? 65535 : (start + rangeSize - 1);
           threads.push_back(std::thread([this, i,plaintext, start, end]() {
               for (uint16_t K1 = start; K1 <= end; ++K1) {
                   uint16_t intermediateValue = Encrypt(plaintext, K1);  // E_{K1}(P)
                       qDebug()<<i;
                   // 加锁，确保对哈希表的操作是线程安全的
                   std::lock_guard<std::mutex> lock(mapMutex);
                   map.insert(intermediateValue, QPair<uint16_t, bool>(K1, false));  // 插入K1的值
               }
           }));
       }

       // 等待所有 E_{K1}(P) 线程完成
       for (auto& thread : threads) {
           if (thread.joinable()) thread.join();
       }

       threads.clear();  // 清空线程容器

       // 第二步：创建16个线程进行 D_{K2}(C) 计算和查找匹配
       for (int i = 0; i < numThreads; ++i) {

           uint16_t start = i * rangeSize;
           uint16_t end = (i == numThreads - 1) ? 65535 : (start + rangeSize - 1);
           threads.push_back(std::thread([this,i, ciphertext, start, end]() {
               for (uint16_t K2 = start; K2 <= end; ++K2) {
                   if (keyFound) return;  // 如果已经找到密钥对，提前退出
                            qDebug()<<-i;
                   uint16_t intermediateValue = Decrypt(ciphertext, K2);  // D_{K2}(C)

                   std::lock_guard<std::mutex> lock(mapMutex);
                   if (map.contains(intermediateValue)) {
                       QPair<uint16_t, bool>& value = map[intermediateValue];
                       if (!value.second) {  // 匹配E_{K1}(P)的中间值
                           uint16_t K1 = value.first;
                           uint16_t K2 = K2;

                           // 显示找到的密钥对
                           QString keyPairText = QString("K1 = %1, K2 = %2")
                               .arg(QString::number(K1, 2).rightJustified(16, '0'))  // 二进制格式输出
                               .arg(QString::number(K2, 2).rightJustified(16, '0'));

                           ui->keyPair->setText(keyPairText);
                           qDebug() << "找到匹配的密钥对: " << keyPairText;
                           keyFound = true;  // 标记为找到密钥对
                           return;
                       }
                   }
               }
           }));
       }

       // 等待所有 D_{K2}(C) 线程完成
       for (auto& thread : threads) {
           if (thread.joinable()) thread.join();
       }

       if (!keyFound) {
           ui->keyPair->setText("未找到匹配的密钥对");
           qDebug() << "未找到匹配的密钥对";
       }

}



//中间相遇碰撞
void Attack::on_MiddleAttack_clicked()
{
    QString plaintext =  ui->inputPlaintext->text(); // 明文
       QString ciphertext =  ui->inputCiphertext->text(); // 密文

       // 将二进制字符串转换为16位无符号整数
           uint16_t plain = BinaryStringToUInt16(plaintext);
           uint16_t cipher = BinaryStringToUInt16(ciphertext);

//       // 调用中间相遇攻击函数
//       MeetInTheMiddleAttack(plain, cipher);
       // 调用中间相遇攻击函数，将其放在异步线程中运行
          QtConcurrent::run(this, &Attack::MeetInTheMiddleAttack, plain, cipher);
}
