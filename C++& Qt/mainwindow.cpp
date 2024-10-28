#include "mainwindow.h"
#include "ui_mainwindow.h"
#include "attack.h"
#include "cbcmodel.h"
#include <cstdint>
#include <QString>
#include <QDebug>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    // 连接加密按钮和槽函数
    connect(ui->encryptButton, &QPushButton::clicked, this, &MainWindow::on_encryptButton_clicked);
}

MainWindow::~MainWindow()
{

    delete ui;
}



// GF(2^4) 乘法表 (模多项式 x^4 + x + 1)
const uint8_t GF_MulTable[16][16] = {
    // 乘法表的行列分别对应 a 和 b 的值
    {0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, // 0x0
    {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF}, // 0x1
    {0x0, 0x2, 0x4, 0x6, 0x8, 0xA, 0xC, 0xE, 0x3, 0x1, 0x7, 0x5, 0xB, 0x9, 0xF, 0xD}, // 0x2
    {0x0, 0x3, 0x6, 0x5, 0xC, 0xF, 0xA, 0x9, 0xB, 0x8, 0xD, 0xE, 0x7, 0x4, 0x1, 0x2}, // 0x3
    {0x0, 0x4, 0x8, 0xC, 0x3, 0x7, 0xB, 0xF, 0x6, 0x2, 0xE, 0xA, 0x5, 0x1, 0xD, 0x9}, // 0x4
    {0x0, 0x5, 0xA, 0xF, 0x7, 0x2, 0xD, 0x8, 0xE, 0xB, 0x4, 0x1, 0x9, 0xC, 0x3, 0x6}, // 0x5
    {0x0, 0x6, 0xC, 0xA, 0xB, 0xD, 0x7, 0x1, 0x5, 0x3, 0x9, 0xF, 0xE, 0x8, 0x2, 0x4}, // 0x6
    {0x0, 0x7, 0xE, 0x9, 0xF, 0x8, 0x1, 0x6, 0xD, 0xA, 0x3, 0x4, 0x2, 0x5, 0xC, 0xB}, // 0x7
    {0x0, 0x8, 0x3, 0xB, 0x6, 0xE, 0x5, 0xD, 0xC, 0x4, 0xF, 0x7, 0xA, 0x2, 0x9, 0x1}, // 0x8
    {0x0, 0x9, 0x1, 0x8, 0x2, 0xB, 0x3, 0xA, 0x4, 0xD, 0x5, 0xC, 0x6, 0xF, 0x7, 0xE}, // 0x9
    {0x0, 0xA, 0x7, 0xD, 0xE, 0x4, 0x9, 0x3, 0xF, 0x5, 0x8, 0x2, 0x1, 0xB, 0x6, 0xC}, // 0xA
    {0x0, 0xB, 0x5, 0xE, 0xA, 0x1, 0xF, 0x4, 0x7, 0xC, 0x2, 0x9, 0xD, 0x6, 0x8, 0x3}, // 0xB
    {0x0, 0xC, 0xB, 0x7, 0x5, 0x9, 0xE, 0x2, 0xA, 0x6, 0x1, 0xD, 0xF, 0x3, 0x4, 0x8}, // 0xC
    {0x0, 0xD, 0x9, 0x4, 0x1, 0xC, 0x8, 0x5, 0x2, 0xF, 0xB, 0x6, 0x3, 0xE, 0xA, 0x7}, // 0xD
    {0x0, 0xE, 0xF, 0x1, 0xD, 0x3, 0x2, 0xC, 0x9, 0x7, 0x6, 0x8, 0x4, 0xA, 0xB, 0x5}, // 0xE
    {0x0, 0xF, 0xD, 0x2, 0x9, 0x6, 0x4, 0xB, 0x1, 0xE, 0xC, 0x3, 0x8, 0x7, 0x5, 0xA}  // 0xF
};

// 使用GF(2^4)乘法表实现乘法运算
uint8_t GF_Multiply(uint8_t a, uint8_t b) {
    return GF_MulTable[a & 0xF][b & 0xF];  // 限制 a 和 b 为4位，并查表
}

// 将二进制字符串转换为16位整数
uint16_t BinaryStringToUInt16(const QString& binaryStr) {
    bool ok;
    return static_cast<uint16_t>(binaryStr.toUInt(&ok, 2));  // 二进制解析
}


// 将16位的无符号整数转换为二进制字符串表示
QString UInt16ToBinaryString(uint16_t value) {
    return QString("%1").arg(value, 16, 2, QChar('0')).toUpper();  // 转换为16位的二进制字符串
}


/**************************************************加密主流程******************************************************/
//S-box盒
const uint8_t SBox[4][4] = {
    {0x9, 0x4, 0xA, 0xB},
    {0xD, 0x1, 0x8, 0x5},
    {0x6, 0x2, 0x0, 0x3},
    {0xC, 0xE, 0xF, 0x7}
};

// RCON常量
const uint8_t RCON1 = 0x80;
const uint8_t RCON2 = 0x30;


// 密钥扩展半字节代替（查表操作）
uint8_t SubNib(uint8_t nibble) {
    uint8_t row = (nibble>>2) & 0x3;  // 前两位用于确定行
    uint8_t col = nibble & 0x3;          // 后两位用于确定列
    return SBox[row][col];
}

// 密钥扩展函数
/* 1.列循环（swap） 2.Sbox替换 3.与轮常量异或 */
void KeyExpansion(uint16_t key, uint16_t& roundKey1, uint16_t& roundKey2) {
    uint8_t w0 = (key >> 8) & 0xFF;
    uint8_t w1 = key & 0xFF;

    uint8_t w1_swapped = (w1 >> 4) | (w1 << 4);
    uint8_t w2 = static_cast<uint8_t>(w0 ^ RCON1 ^ (SubNib((w1_swapped & 0xF0) >> 4) << 4 | SubNib(w1_swapped & 0x0F)));
    uint8_t w3 = w2 ^ w1;

    uint8_t w3_swapped = (w3 >> 4) | (w3 << 4);
    uint8_t w4 = static_cast<uint8_t>(w2 ^ RCON2 ^ (SubNib((w3_swapped & 0xF0) >> 4) << 4 | SubNib(w3_swapped & 0x0F)));
    uint8_t w5 = w4 ^ w3;

    roundKey1 = (w2 << 8) | w3;
    roundKey2 = (w4 << 8) | w5;
}


// 密钥加 (状态矩阵与轮密钥逐位异或)
uint16_t AddRoundKey(uint16_t state, uint16_t roundKey) {
    return state ^ roundKey;
}


// 半字节代替（处理整个16位状态）
uint16_t NibbleSubstitution(uint16_t state) {
    // 将 state 的每个4位（半字节）部分提取出来并替换
    uint16_t upperNibble = SubNib((state >> 12) & 0xF) << 12;  // 提取最高4位，并替换
    uint16_t upperLowerNibble = SubNib((state >> 8) & 0xF) << 8;  // 提取次高4位，并替换
    uint16_t lowerUpperNibble = SubNib((state >> 4) & 0xF) << 4;  // 提取次低4位，并替换
    uint16_t lowerNibble = SubNib(state & 0xF);  // 提取最低4位，并替换

    // 将替换后的4部分组合起来，形成新的16位值
    return upperNibble | upperLowerNibble | lowerUpperNibble | lowerNibble;
}


// 行移位函数，按矩阵处理
uint16_t ShiftRows(uint16_t state) {
    // 提取 4 位半字节，形成 2x2 矩阵
    uint8_t s0 = (state >> 12) & 0xF;  // 提取最高4位
    uint8_t s1 = (state >> 8) & 0xF;   // 提取次高4位
    uint8_t s2 = (state >> 4) & 0xF;   // 提取次低4位
    uint8_t s3 = state & 0xF;          // 提取最低4位

    // 执行行移位操作
    // 第一行保持不变：s0, s2
    // 第二行左移一位：s1, s3 交换
    uint8_t new_s1 = s3;
    uint8_t new_s3 = s1;

    // 将结果重新组合为16位值
    uint16_t result = (s0 << 12) | (new_s1 << 8) | (s2 << 4) | new_s3;

    return result;
}

// 列混淆
uint16_t MixColumns(uint16_t state) {
    // 将16位状态解析为4个半字节
    uint8_t s00 = (state >> 12) & 0xF;  // 第一列的上半字节（最高4位）
    uint8_t s10 = (state >> 8) & 0xF;   // 第一列的下半字节（次高4位）
    uint8_t s01 = (state >> 4) & 0xF;   // 第二列的上半字节（次低4位）
    uint8_t s11 = state & 0xF;          // 第二列的下半字节（最低4位）

//    qDebug() << "Before MixColumns:";
//    qDebug() << "s00 =" << QString::number(s00, 2).rightJustified(4, '0');
//    qDebug() << "s10 =" << QString::number(s10, 2).rightJustified(4, '0');
//    qDebug() << "s01 =" << QString::number(s01, 2).rightJustified(4, '0');
//    qDebug() << "s11 =" << QString::number(s11, 2).rightJustified(4, '0');

    // 列混淆矩阵乘法
      uint8_t new_s00 = GF_Multiply(1, s00) ^ GF_Multiply(4, s10);
      uint8_t new_s10 = GF_Multiply(4, s00) ^ GF_Multiply(1, s10);
      uint8_t new_s01 = GF_Multiply(1, s01) ^ GF_Multiply(4, s11);
      uint8_t new_s11 = GF_Multiply(4, s01) ^ GF_Multiply(1, s11);

//      qDebug() << "After MixColumns:";
//          qDebug() << "new_s00 =" << QString::number(new_s00, 2).rightJustified(4, '0');
//          qDebug() << "new_s10 =" << QString::number(new_s10, 2).rightJustified(4, '0');
//          qDebug() << "new_s01 =" << QString::number(new_s01, 2).rightJustified(4, '0');
//          qDebug() << "new_s11 =" << QString::number(new_s11, 2).rightJustified(4, '0');

      // 将新的半字节重新组合为16位状态
      return (new_s00 << 12) | (new_s10 << 8) | (new_s01 << 4) | new_s11;
}


uint16_t Encrypt(uint16_t plaintext, uint16_t key) {
    uint16_t roundKey1, roundKey2;

    // 执行密钥扩展，生成两个轮密钥
    KeyExpansion(key, roundKey1, roundKey2);
       qDebug() << "key:" << QString::number(key, 2).rightJustified(16, '0');
       qDebug() << "roundKey1:" << QString::number(roundKey1, 2).rightJustified(16, '0');
       qDebug() << "roundKey2:" << QString::number(roundKey2, 2).rightJustified(16, '0');

    // 第一步：初始密钥加
    uint16_t state = AddRoundKey(plaintext, key);
    qDebug() << "初始密钥加的结果：" << QString::number(state, 2).rightJustified(16, '0');

    // 第二步：半字节代替
    state = NibbleSubstitution(state);
    qDebug() << "半字节代替的结果：" << QString::number(state, 2).rightJustified(16, '0');

    // 第三步：行移位
    state = ShiftRows(state);
    qDebug() << "行移位的结果：" << QString::number(state, 2).rightJustified(16, '0');

    // 第四步：列混淆
    state = MixColumns(state);
    qDebug() << "列混淆的结果：" << QString::number(state, 2).rightJustified(16, '0');

    // 第五步：第二次密钥加
    state = AddRoundKey(state, roundKey1);
    qDebug() << "第二次密钥加的结果：" << QString::number(state, 2).rightJustified(16, '0');

    // 第二轮加密
    state = NibbleSubstitution(state);
    qDebug() << "第二轮加密,半字节代替的结果：" << QString::number(state, 2).rightJustified(16, '0');

    state = ShiftRows(state);
    qDebug() << "第二轮加密,行移位的结果：" << QString::number(state, 2).rightJustified(16, '0');

    state = AddRoundKey(state, roundKey2);
    qDebug() << "第二轮加密,列混淆的结果：" << QString::number(state, 2).rightJustified(16, '0');

    return state;
}



/*********************************************************解密主流程*******************************************************************/
//ReS-box盒
const uint8_t ReSBox[4][4] = {
    {0xA, 0x5, 0x9, 0xB},
    {0x1, 0x7, 0x8, 0xF},
    {0x6, 0x0, 0x2, 0x3},
    {0xC, 0x4, 0xD, 0xE}
};

// 密钥扩展半字节代替（查表操作）
uint8_t ReSubNib(uint8_t nibble) {
    uint8_t row = (nibble>>2) & 0x3;  // 前两位用于确定行
    uint8_t col = nibble & 0x3;          // 后两位用于确定列
    return ReSBox[row][col];
}


// 逆半字节代替（处理整个16位状态）
uint16_t ReNibbleSubstitution(uint16_t state) {
    // 将 state 的每个4位（半字节）部分提取出来并替换
    uint16_t upperNibble = ReSubNib((state >> 12) & 0xF) << 12;  // 提取最高4位，并替换
    uint16_t upperLowerNibble = ReSubNib((state >> 8) & 0xF) << 8;  // 提取次高4位，并替换
    uint16_t lowerUpperNibble = ReSubNib((state >> 4) & 0xF) << 4;  // 提取次低4位，并替换
    uint16_t lowerNibble = ReSubNib(state & 0xF);  // 提取最低4位，并替换

    // 将替换后的4部分组合起来，形成新的16位值
    return upperNibble | upperLowerNibble | lowerUpperNibble | lowerNibble;
}


// 逆列混淆
uint16_t ReMixColumns(uint16_t state) {
    // 将16位状态解析为4个半字节
    uint8_t s00 = (state >> 12) & 0xF;  // 第一列的上半字节（最高4位）
    uint8_t s10 = (state >> 8) & 0xF;   // 第一列的下半字节（次高4位）
    uint8_t s01 = (state >> 4) & 0xF;   // 第二列的上半字节（次低4位）
    uint8_t s11 = state & 0xF;          // 第二列的下半字节（最低4位）

    // 列混淆矩阵乘法
      uint8_t new_s00 = GF_Multiply(9, s00) ^ GF_Multiply(2, s10);
      uint8_t new_s10 = GF_Multiply(2, s00) ^ GF_Multiply(9, s10);
      uint8_t new_s01 = GF_Multiply(9, s01) ^ GF_Multiply(2, s11);
      uint8_t new_s11 = GF_Multiply(2, s01) ^ GF_Multiply(9, s11);


      // 将新的半字节重新组合为16位状态
      return (new_s00 << 12) | (new_s10 << 8) | (new_s01 << 4) | new_s11;
}


// 解密主流程
uint16_t Decrypt(uint16_t ciphertext, uint16_t key) {
    uint16_t roundKey1, roundKey2;

    // 执行密钥扩展，生成两个轮密钥
    KeyExpansion(key, roundKey1, roundKey2);
//       qDebug() << "key:" << QString::number(key, 2).rightJustified(16, '0');
//       qDebug() << "roundKey1:" << QString::number(roundKey1, 2).rightJustified(16, '0');
//       qDebug() << "roundKey2:" << QString::number(roundKey2, 2).rightJustified(16, '0');

       //初始轮密钥加
       uint16_t state = AddRoundKey(ciphertext, roundKey2);
//       qDebug() << "初始密钥加的结果：" << QString::number(state, 2).rightJustified(16, '0');

     // 第一步：逆行移位
        state= ShiftRows(state);
//       qDebug() << "逆行移位的结果：" << QString::number(state, 2).rightJustified(16, '0');

       // 第二步：逆半字节代替
       state = ReNibbleSubstitution(state);
//       qDebug() << "逆半字节代替的结果：" << QString::number(state, 2).rightJustified(16, '0');

     //第三步：轮密钥加
       state = AddRoundKey(state, roundKey1);
//       qDebug() << "第二次密钥加的结果：" << QString::number(state, 2).rightJustified(16, '0');

    // 第四步：逆列混淆
    state = ReMixColumns(state);
//    qDebug() << "逆列混淆的结果：" << QString::number(state, 2).rightJustified(16, '0');

    // 第二轮加密
    // 逆行移位
    state= ShiftRows(state);
//    qDebug() << "第二轮加密,逆行移位的结果：" << QString::number(state, 2).rightJustified(16, '0');

    // 逆半字节代替
    state = ReNibbleSubstitution(state);
//    qDebug() << "第二轮加密,逆半字节代替的结果：" << QString::number(state, 2).rightJustified(16, '0');

    //轮密钥加
      state = AddRoundKey(state, key);
//      qDebug() << "第三次密钥加的结果：" << QString::number(state, 2).rightJustified(16, '0');

    return state;
}



/**********************************************************扩展功能*****************************************************************/

// 判断输入是否为二进制字符串
bool isBinaryString(const QString& str) {
    return !str.contains(QRegExp("[^01]"));  // 返回true表示只包含 '0' 和 '1'
}

// 将字符串的两个字符转为一个16位的无符号整数
uint16_t ASCIIStringToUInt16(const QString& str, int index) {
    uint8_t highByte = static_cast<uint8_t>(str.at(index).unicode());       // 第一个字符的ASCII值
    uint8_t lowByte = static_cast<uint8_t>(str.at(index + 1).unicode());    // 第二个字符的ASCII值
    return (highByte << 8) | lowByte;   // 组合两个字节为16位
}

// 将16位的无符号整数转换为字符串表示
QString UInt16ToHexString(uint16_t value) {
    return QString("%1").arg(value, 4, 16, QChar('0')).toUpper();  // 转换为4位的十六进制字符串
}

// 将16位的无符号整数转换为ASCII字符串表示
QString UInt16ToASCIIString(uint16_t value) {
    uint8_t highByte = (value >> 8) & 0xFF;  // 高位字节
    uint8_t lowByte = value & 0xFF;          // 低位字节

    // 将两个字节转换为可显示的ASCII字符
    QString result;
    result.append(QChar(highByte));
    result.append(QChar(lowByte));
    return result;
}


/********************************************************点击单次加密*******************************************************************/
void MainWindow::on_encryptButton_clicked()
{
    QString plaintextStr = ui->inputPlaintext->text();
    QString keyStr = ui->inputKey->text();

    // 验证密钥输入是否为16位的二进制字符串
    if (keyStr.length() != 16 || !isBinaryString(keyStr)) {
        ui->outputCiphertext_2->setText("请输入正确的16bit密钥");
        return;
    }

    // 将密钥从二进制字符串转换为16位无符号整数
    uint16_t key = BinaryStringToUInt16(keyStr);

     QString encryptedText;

     // 判断输入的明文是否为二进制字符串
         if (isBinaryString(plaintextStr)) {
             // 处理二进制输入
             if (plaintextStr.length() != 16) {
                 ui->outputCiphertext_2->setText("请输入正确的16bit明文");
                 return;
             }

             // 将二进制字符串转换为16位无符号整数
             uint16_t plaintext = BinaryStringToUInt16(plaintextStr);

             // 调用加密函数
             uint16_t ciphertext = Encrypt(plaintext, key);

             // 将密文转换为二进制字符串显示
                QString ciphertextBinary = QString("%1").arg(ciphertext, 16, 2, QChar('0')).toUpper();
                ui->outputCiphertext->setText(ciphertextBinary);
                  qDebug()<<"最终密文："<<ciphertextBinary;
         }


         else {
             // 处理ASCII输入
             if (plaintextStr.length() % 2 != 0) {
                 ui->outputCiphertext_2->setText("请输入正确的ASCII码");
                 return;
             }

             // 每两个ASCII字符组成一个16位的无符号整数进行加密
             for (int i = 0; i < plaintextStr.length(); i += 2) {
                 // 将两个ASCII字符转为16位的整数
                 uint16_t plaintextBlock = ASCIIStringToUInt16(plaintextStr, i);

                 // 调用加密函数
                 uint16_t ciphertextBlock = Encrypt(plaintextBlock, key);

                 // 将加密结果转换为ASCII字符串并拼接到结果中
                 encryptedText.append(UInt16ToASCIIString(ciphertextBlock));

                 // 将加密后的密文（ASCII字符）显示出来
                 ui->outputCiphertext->setText(encryptedText);
                 qDebug() << "最终密文：" << encryptedText;
             }
         }


}



/*************************************************************双重加密*****************************************************************/

// 双重加密主流程
uint16_t DoubleEncrypt(uint16_t plaintext, uint32_t key) {
    // 将32位密钥拆分为两个16位子密钥
    uint16_t K1 = (key >> 16) & 0xFFFF;  // 高16位作为 K1
    uint16_t K2 = key & 0xFFFF;          // 低16位作为 K2

    // 第一次加密，使用 K1
    uint16_t intermediateCiphertext = Encrypt(plaintext, K1);

    // 第二次加密，使用 K2
    uint16_t finalCiphertext = Encrypt(intermediateCiphertext, K2);

    return finalCiphertext;
}

void MainWindow::on_encryptButton_2_clicked()
{
    QString plaintextStr = ui->inputPlaintext->text();
       QString keyStr = ui->inputKey->text();

       // 验证密钥输入是否为32位的二进制字符串
       if (keyStr.length() != 32 || keyStr.contains(QRegExp("[^01]"))) {
           ui->outputCiphertext_2->setText("Invalid key input. Please enter a 32-bit binary value.");
           return;
       }

       // 将密钥从二进制字符串转换为32位无符号整数
       bool ok;
       uint32_t key = keyStr.toUInt(&ok, 2);

       // 判断输入的明文是否为二进制字符串
       if (plaintextStr.length() != 16 || plaintextStr.contains(QRegExp("[^01]"))) {
           ui->outputCiphertext_2->setText("Invalid plaintext input. Please enter a 16-bit binary plaintext.");
           return;
       }

       // 将明文转换为16位无符号整数
       uint16_t plaintext = BinaryStringToUInt16(plaintextStr);

       // 调用双重加密函数
       uint16_t ciphertext = DoubleEncrypt(plaintext, key);

       // 将密文转换为二进制字符串显示
          QString ciphertextBinary = UInt16ToBinaryString(ciphertext);
          ui->outputCiphertext->setText(ciphertextBinary);
          qDebug() << "最终密文：" << ciphertextBinary;
}



/*********************************************************三重加密**********************************************************************/
// 三重加密主流程
uint16_t TripleEncrypt(uint16_t plaintext, uint32_t key) {
    // 将32位密钥拆分为两个16位子密钥
    uint16_t K1 = (key >> 16) & 0xFFFF;  // 高16位作为 K1
    uint16_t K2 = key & 0xFFFF;          // 低16位作为 K2

    // 第一次加密，使用 K1
    uint16_t intermediateCiphertext = Encrypt(plaintext, K1);

    // 第二次解密，使用 K2
    uint16_t middleCiphertext = Decrypt(intermediateCiphertext, K2);

    // 第三次加密，使用 K1
    uint16_t finalCiphertext = Encrypt(plaintext, K1);

    return finalCiphertext;
}

void MainWindow::on_encryptButton_3_clicked()
{
    QString plaintextStr = ui->inputPlaintext->text();
       QString keyStr = ui->inputKey->text();

       // 验证密钥输入是否为32位的二进制字符串
       if (keyStr.length() != 32 || keyStr.contains(QRegExp("[^01]"))) {
           ui->outputCiphertext_2->setText("Invalid key input. Please enter a 32-bit binary value.");
           return;
       }

       // 将密钥从二进制字符串转换为32位无符号整数
       bool ok;
       uint32_t key = keyStr.toUInt(&ok, 2);

       // 判断输入的明文是否为二进制字符串
       if (plaintextStr.length() != 16 || plaintextStr.contains(QRegExp("[^01]"))) {
           ui->outputCiphertext_2->setText("Invalid plaintext input. Please enter a 16-bit binary plaintext.");
           return;
       }

       // 将明文转换为16位无符号整数
       uint16_t plaintext = BinaryStringToUInt16(plaintextStr);

       // 调用双重加密函数
       uint16_t ciphertext = TripleEncrypt(plaintext, key);

       // 将密文转换为二进制字符串显示
          QString ciphertextBinary = UInt16ToBinaryString(ciphertext);
          ui->outputCiphertext->setText(ciphertextBinary);
          qDebug() << "最终密文：" << ciphertextBinary;
}


/**********************************************************中间相遇攻击****************************************************************/
void MainWindow::on_pushButton_clicked()
{
    Attack *attack =new Attack;
    attack->show();
}

void MainWindow::on_pushButton_2_clicked()
{
    CBCmodel *cbcmodel =new CBCmodel;
    cbcmodel->show();
}
