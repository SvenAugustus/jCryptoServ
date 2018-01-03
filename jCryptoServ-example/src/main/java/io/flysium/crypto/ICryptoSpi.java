
package io.flysium.crypto;

/**
 *
 * 加解密SPI（可逆SPI）<br/>
 * Java加密扩展（Java Cryptographic Extension）：<br/>
 * 采用遵循美国出口控制条例的加密服务来增强JCA功能，<br/>
 * 同时支持加密、解密操作，<br/>
 * 支持密钥的生成和协商以及支持消息验证码算法（Message Authentication Code）。<br/>
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public interface ICryptoSpi extends ISecretSpi {

  /**
   * 获取转换名，“算法名/算法模式/填充模式”
   */
  String getTransforms();

  /**
   * 获取密钥
   *
   * @return 密钥文本
   */
  byte[] getSecret();

  /**
   * 设置密钥
   *
   * @param secretKey 密钥文本
   */
  void setSecret(byte[] secretKey);

  /**
   * 根据初始密钥长度，随机生成密钥
   */
  void generateKey();

  /**
   * 解密
   *
   * @param cipherText 密文数据
   * @return 明文数据
   */
  byte[] decrypt(byte[] cipherText);

  /**
   * 解密过程
   *
   * @param cipherText 密文文本
   * @return 明文文本
   */
  String decryptString(String cipherText);

  /**
   * 解密过程
   *
   * @param cipherTextB64 Base64编码形式的密文文本
   * @return 明文文本
   */
  String decryptStringB64(String cipherTextB64);

  /**
   * 解密过程
   *
   * @param cipherTextHex Hex编码形式的密文文本
   * @return 明文文本
   */
  String decryptStringHex(String cipherTextHex);

  /**
   * 解密过程
   *
   * @param cipherText 密文文本
   * @param charsetName 编码
   * @return 明文文本
   */
  String decryptString(String cipherText, String charsetName);

  /**
   * 解密过程
   *
   * @param cipherTextB64 Base64编码形式的密文文本
   * @param charsetName 编码
   * @return 明文文本
   */
  String decryptStringB64(String cipherTextB64, String charsetName);

  /**
   * 解密过程
   *
   * @param cipherTextHex Hex编码形式的密文文本
   * @param charsetName 编码
   * @return 明文文本
   */
  String decryptStringHex(String cipherTextHex, String charsetName);

}
