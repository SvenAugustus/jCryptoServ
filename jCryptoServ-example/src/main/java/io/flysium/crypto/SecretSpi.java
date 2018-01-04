package io.flysium.crypto;

import io.flysium.crypto.utils.Util;
import java.io.UnsupportedEncodingException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;

/**
 *
 * 加密SPI
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public abstract class SecretSpi implements ISecretSpi {

  protected static final String DEFAULT_CHARSETNAME = "UTF-8";

  /* 算法名 */
  protected final String algorithm;
  /* 封装CipherSpi实现的提供者 */
  protected final Provider provider;
  /* 加密参数的（透明）规范 */
  protected AlgorithmParameterSpec algorithmParameterSpec;
  /* 支持 byte[] 加密 */
  protected final boolean _byte_encrypt_support;
  /* 支持 char[] 加密 */
  protected final boolean _char_encrypt_support;
  /* 空提供者 */
  protected static final Provider _nullProvider=null;

  public SecretSpi(String algorithm, Provider provider) {
    this(algorithm, provider, true, false);
  }

  public SecretSpi(String algorithm, Provider provider, boolean _byte_support,
      boolean _char__support) {
    super();
    this.algorithm = algorithm;
    this.provider = provider;
    this._byte_encrypt_support = _byte_support;
    this._char_encrypt_support = _char__support;
  }

  @Override
  public String getAlgorithm() {
    return algorithm;
  }

  @Override
  public Provider getProvider() {
    return provider;
  }

  @Override
  public AlgorithmParameterSpec getAlgorithmParameterSpec() {
    return algorithmParameterSpec;
  }

  @Override
  public void setAlgorithmParameterSpec(AlgorithmParameterSpec algorithmParameterSpec) {
    this.algorithmParameterSpec = algorithmParameterSpec;
  }

  @Override
  public String encryptString(String plainText) {
    return encryptString(plainText, DEFAULT_CHARSETNAME);
  }

  @Override
  public String encryptStringB64(String plainText) {
    return encryptStringB64(plainText, DEFAULT_CHARSETNAME);
  }

  @Override
  public String encryptStringHex(String plainText) {
    return encryptStringHex(plainText, DEFAULT_CHARSETNAME);
  }

  @Override
  public byte[] encrypt(byte[] plainText) {
    if (!_byte_encrypt_support)
      throw new UnsupportedOperationException("not support to encrypt byte[] in SecretSpi.");
    return null;
  }

  @Override
  public byte[] encrypt(char[] plainText) {
    if (!_char_encrypt_support)
      throw new UnsupportedOperationException("not support to encrypt char[] in SecretSpi.");
    return null;
  }

  /**
   * 加密过程
   *
   * @param plainText 明文文本
   * @param charsetName 编码
   * @return 密文文本
   */
  public byte[] encryptString2Bytes(String plainText, String charsetName) {
    try {
      byte[] encryptedData = null;
      if (_char_encrypt_support) {
        encryptedData = encrypt(plainText.toCharArray());
      } else {
        encryptedData = encrypt(plainText.getBytes(charsetName));
      }
      return encryptedData;
    } catch (UnsupportedEncodingException e) {
      fail(e);
    }
    return null;
  }

  /**
   * 加密过程
   *
   * @param plainText 明文文本
   * @param charsetName 编码
   * @return 密文文本
   */
  @Override
  public String encryptString(String plainText, String charsetName) {
    try {
      byte[] encryptedData = encryptString2Bytes(plainText, charsetName);
      return new String(encryptedData, charsetName);
    } catch (UnsupportedEncodingException e) {
      fail(e);
    }
    return null;
  }

  /**
   * 加密过程
   *
   * @param plainText 明文文本
   * @param charsetName 编码
   * @return Base64编码形式的密文文本
   */
  @Override
  public String encryptStringB64(String plainText, String charsetName) {
    try {
      byte[] encryptedData = encryptString2Bytes(plainText, charsetName);
      return new String(Util.armor(encryptedData), charsetName);
    } catch (UnsupportedEncodingException e) {
      fail(e);
    }
    return null;
  }

  /**
   * 加密过程
   *
   * @param plainText 明文文本
   * @param charsetName 编码
   * @return Hex编码形式的密文文本
   */
  public String encryptStringHex(String plainText, String charsetName) {
    byte[] encryptedData = encryptString2Bytes(plainText, charsetName);
    return new String(Util.hex(encryptedData));
  }

  protected void fail(Exception e) {
    throw new IllegalStateException(e);
  }

}
