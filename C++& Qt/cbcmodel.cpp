#include "cbcmodel.h"
#include "ui_cbcmodel.h"
#include <QRandomGenerator>
#include <vector>
#include <QString>
#include <QDebug>

CBCmodel::CBCmodel(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::CBCmodel)
{
    ui->setupUi(this);
}

CBCmodel::~CBCmodel()
{
    delete ui;
}

extern uint16_t BinaryStringToUInt16(const QString& binaryStr);
extern QString UInt16ToBinaryString(uint16_t value);
extern uint16_t Encrypt(uint16_t plaintext, uint16_t key);
extern uint16_t Decrypt(uint16_t plaintext, uint16_t key);


// 随机生成 16 位初始向量 (IV)
uint16_t GenerateRandomIV() {
    return static_cast<uint16_t>(QRandomGenerator::global()->bounded(65536));  // 生成 0 到 65535 之间的随机数
}

// 将二进制字符串拆分为多个 16 位块
std::vector<uint16_t> SplitIntoBlocks(const QString& input) {
    std::vector<uint16_t> blocks;
    for (int i = 0; i < input.length(); i += 16) {
        QString blockStr = input.mid(i, 16);
        blocks.push_back(BinaryStringToUInt16(blockStr));
    }
    return blocks;
}


// CBC 模式加密
std::vector<uint16_t> CBC_Encrypt(const std::vector<uint16_t>& plaintextBlocks, uint16_t key, uint16_t iv) {
    std::vector<uint16_t> ciphertextBlocks;
    uint16_t previousBlock = iv;

    for (const auto& block : plaintextBlocks) {
        uint16_t xorResult = block ^ previousBlock;  // 明文块与前一块密文（或IV）异或
        uint16_t encryptedBlock = Encrypt(xorResult, key);  // 加密
        ciphertextBlocks.push_back(encryptedBlock);
        previousBlock = encryptedBlock;  // 更新前一块密文
    }

    return ciphertextBlocks;
}

// CBC 模式解密
std::vector<uint16_t> CBC_Decrypt(const std::vector<uint16_t>& ciphertextBlocks, uint16_t key, uint16_t iv) {
    std::vector<uint16_t> decryptedBlocks;
    uint16_t previousBlock = iv;

    for (const auto& block : ciphertextBlocks) {
        uint16_t decryptedBlock = Decrypt(block, key);  // 解密
        uint16_t originalBlock = decryptedBlock ^ previousBlock;  // 异或得到原始明文
        decryptedBlocks.push_back(originalBlock);
        previousBlock = block;  // 更新前一块密文
    }

    return decryptedBlocks;
}

void CBCmodel::on_cbcEncryptButton_clicked()
{
    QString plaintextStr = ui->inputPlaintext->text();
        QString keyStr = ui->inputKey->text();

        // 验证密钥输入是否正确
        if (keyStr.length() != 16 || keyStr.contains(QRegExp("[^01]"))) {
            ui->outputCiphertext->setText("Invalid key. Enter a 16-bit binary key.");
            return;
        }

        // 转换密钥为无符号整数
        uint16_t key = BinaryStringToUInt16(keyStr);

        // 生成随机 IV 并显示
        uint16_t iv = GenerateRandomIV();
        ui->outputIV->setText(UInt16ToBinaryString(iv));

        // 将明文拆分为多个 16 位块
        std::vector<uint16_t> plaintextBlocks = SplitIntoBlocks(plaintextStr);

        // 加密
        std::vector<uint16_t> ciphertextBlocks = CBC_Encrypt(plaintextBlocks, key, iv);

        // 显示加密结果
        QString ciphertext;
        for (const auto& block : ciphertextBlocks) {
            ciphertext += UInt16ToBinaryString(block) + " ";
        }
        ui->outputCiphertext->setText(ciphertext.trimmed());
}



void CBCmodel::on_cbcDecryptButton_clicked()
{
    QString ciphertextStr = ui->inputCiphertext->text();
    QString keyStr = ui->inputKey->text();
    QString ivStr = ui->inputIV->text();

    // 验证密钥和 IV 输入是否正确
    if (keyStr.length() != 16 || keyStr.contains(QRegExp("[^01]"))) {
        ui->outputPlaintext->setText("Invalid key. Enter a 16-bit binary key.");
        return;
    }
    if (ivStr.length() != 16 || ivStr.contains(QRegExp("[^01]"))) {
        ui->outputPlaintext->setText("Invalid IV. Enter a 16-bit binary IV.");
        return;
    }

    // 转换密钥和 IV 为无符号整数
    uint16_t key = BinaryStringToUInt16(keyStr);
    uint16_t iv = BinaryStringToUInt16(ivStr);

    // 将密文拆分为多个 16 位块
    QStringList blockList = ciphertextStr.split(" ");
    std::vector<uint16_t> ciphertextBlocks;
    for (const auto& blockStr : blockList) {
        ciphertextBlocks.push_back(BinaryStringToUInt16(blockStr));
    }

    // 解密
    std::vector<uint16_t> decryptedBlocks = CBC_Decrypt(ciphertextBlocks, key, iv);

    // 显示解密结果
    QString plaintext;
    for (const auto& block : decryptedBlocks) {
        plaintext += UInt16ToBinaryString(block) + " ";
    }
    ui->outputPlaintext->setText(plaintext.trimmed());
}

void CBCmodel::on_tamperCiphertextButton_clicked()
{
    QString ciphertextStr = ui->inputCiphertext->text();
       QStringList blockList = ciphertextStr.split(" ");

       // 篡改第一块密文
       if (!blockList.isEmpty()) {
           blockList[0] = UInt16ToBinaryString(BinaryStringToUInt16(blockList[0]) ^ 0xFFFF);  // 异或全 1 掩码
       }

       // 显示篡改后的密文
       QString tamperedCiphertext = blockList.join(" ");
       ui->inputCiphertext->setText(tamperedCiphertext);
       qDebug() << "Tampered Ciphertext:" << tamperedCiphertext;
}
