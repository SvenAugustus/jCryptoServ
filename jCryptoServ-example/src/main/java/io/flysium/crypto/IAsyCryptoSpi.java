package io.flysium.crypto;


/**
 *
 * 非对称加解密SPI
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public interface IAsyCryptoSpi extends ICryptoSpi, ISecretSpi {

  /**
   * 获取公钥文本
   *
   * @return Base64编码形式的公钥文本
   */
  String getPublicKey();

  /**
   * 获取私钥文本
   *
   * @return Base64编码形式的私钥文本
   */
  String getPrivateKey();

  /**
   * 设置公钥
   *
   * @param publicKeyB64 Base64编码形式的公钥文本
   */
  void setPublicKey(String publicKeyB64);

  /**
   * 设置私钥
   *
   * @param privateKeyB64 Base64编码形式的私钥文本
   */
  void setPrivateKey(String privateKeyB64);

  /**
   * 获取签名算法名
   */
  String getSignatureAlgorithm();

  /**
   * 设置签名算法名
   */
  void setSignatureAlgorithm(String signatureAlgorithm);

  /**
   * 数字签名
   *
   * @param input 输入缓冲区
   * @return 签名操作结果的签名字节
   */
  byte[] sign(byte[] input);

  /**
   * 签名校验
   *
   * @param input 输入缓冲区
   * @param sign 签名字节
   * @return 如果签名得到验证，则返回 true，否则将返回 false。
   */
  boolean verify(byte[] input, byte[] sign);

}
