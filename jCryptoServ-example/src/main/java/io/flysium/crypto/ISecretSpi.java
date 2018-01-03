package io.flysium.crypto;

import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;

/**
 *
 * 加密SPI</br>
 * 对应Java加密架构（Java Cryptograp Architecture）：</br>
 * 提供基本的加密服务和加密算法，包括对数字签名和消息摘要的支持。</br>
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public interface ISecretSpi {

  /**
   * 获取算法名
   */
  String getAlgorithm();

  /**
   * 获取提供者
   */
  Provider getProvider();

  /**
   * 获取初始密钥长度
   */
  int getKeyLength();

  /**
   * 设置初始密钥长度
   */
  void setKeyLength(int keyLength);

  /**
   * 获取加密参数规范
   */
  AlgorithmParameterSpec getAlgorithmParameterSpec();

  /**
   * 设置加密参数规范
   */
  void setAlgorithmParameterSpec(AlgorithmParameterSpec algorithmParameterSpec);

  /**
   * 加密
   *
   * @param plainText 明文数据
   * @return 密文数据
   */
  byte[] encrypt(byte[] plainText);

  /**
   * 加密
   *
   * @param plainText 明文数据
   * @return 密文数据
   */
  byte[] encrypt(char[] plainText);

  /**
   * 加密过程
   *
   * @param plainText 明文文本
   * @return 密文文本
   */
  String encryptString(String plainText);

  /**
   * 加密过程
   *
   * @param plainText 明文文本
   * @return Base64编码形式的密文文本
   */
  String encryptStringB64(String plainText);

  /**
   * 加密过程
   *
   * @param plainText 明文文本
   * @return Hex编码形式的密文文本
   */
  String encryptStringHex(String plainText);

  /**
   * 加密过程
   *
   * @param plainText 明文文本
   * @param charsetName 编码
   * @return 密文文本
   */
  String encryptString(String plainText, String charsetName);

  /**
   * 加密过程
   *
   * @param plainText 明文文本
   * @param charsetName 编码
   * @return Base64编码形式的密文文本
   */
  String encryptStringB64(String plainText, String charsetName);

  /**
   * 加密过程
   *
   * @param plainText 明文文本
   * @param charsetName 编码
   * @return Hex编码形式的密文文本
   */
  String encryptStringHex(String plainText, String charsetName);


}
