package io.flysium.crypto;

import io.flysium.crypto.utils.Util;
import java.io.UnsupportedEncodingException;
import java.security.Provider;
import javax.crypto.Cipher;

/**
 *
 * 加解密SPI（可逆SPI）
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public abstract class CryptoSpi extends SecretSpi implements ICryptoSpi {

  /**
   * 转换的名称，“算法名/算法模式/填充模式”（Cipher Algorithm Names/Modes/Padding），例如 AES/ECB/PKCS5Padding。 </br>
   * 有关标准转换名称的信息，请参见 Java Cryptography Architecture Reference Guide 的附录A： </br>
   * <a>https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher</a>
   */
  protected final String transforms;
  /* Cipher本地线程变量 */
  protected ThreadLocal<Cipher> cipherThreadLocal = new ThreadLocal<Cipher>() {

    @Override
    public Cipher get() {
      Cipher cipher = super.get();
      if (cipher == null) {
        cipher = Util.getCipher(CryptoSpi.this.transforms, CryptoSpi.this.provider);
      }
      return cipher;
    }
  };

  public CryptoSpi(String algorithm, Provider provider, String transforms) {
    super(algorithm, provider);
    this.transforms = transforms;
  }

  @Override
  public String getTransforms() {
    return transforms;
  }

  @Override
  public String decryptString(String cipherText) {
    return decryptString(cipherText, DEFAULT_CHARSETNAME);
  }

  @Override
  public String decryptStringB64(String cipherTextB64) {
    return decryptStringB64(cipherTextB64, DEFAULT_CHARSETNAME);
  }

  @Override
  public String decryptStringHex(String cipherTextHex) {
    return decryptStringHex(cipherTextHex, DEFAULT_CHARSETNAME);
  }

  /**
   * 解密过程
   *
   * @param cipherText 密文文本
   * @param charsetName 编码
   * @return 明文文本
   */
  @Override
  public String decryptString(String cipherText, String charsetName) {
    try {
      byte[] decryptedData = decrypt(cipherText.getBytes(charsetName));
      return new String(decryptedData, charsetName);
    } catch (UnsupportedEncodingException e) {
      fail(e);
    }
    return null;
  }

  /**
   * 解密过程
   *
   * @param cipherTextB64 Base64编码形式的密文文本
   * @param charsetName 编码
   * @return 明文文本
   */
  @Override
  public String decryptStringB64(String cipherTextB64, String charsetName) {
    try {
      byte[] decryptedData = decrypt(Util.unarmor(cipherTextB64, charsetName));
      return new String(decryptedData, charsetName);
    } catch (UnsupportedEncodingException e) {
      fail(e);
    }
    return null;
  }

  /**
   * 解密过程
   *
   * @param cipherTextHex Hex编码形式的密文文本
   * @param charsetName 编码
   * @return 明文文本
   */
  public String decryptStringHex(String cipherTextHex, String charsetName) {
    try {
      byte[] decryptedData = decrypt(Util.unhex(cipherTextHex));
      return new String(decryptedData, charsetName);
    } catch (UnsupportedEncodingException e) {
      fail(e);
    }
    return null;
  }

}
