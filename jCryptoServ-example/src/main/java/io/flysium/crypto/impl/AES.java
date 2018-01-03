package io.flysium.crypto.impl;

import io.flysium.crypto.ICryptoSpi;
import io.flysium.crypto.ISecretSpi;
import io.flysium.crypto.Symmetric;
import java.security.Provider;
import javax.crypto.spec.SecretKeySpec;


/**
 * AES
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class AES extends Symmetric implements ICryptoSpi, ISecretSpi {

  /* 默认算法名 */
  /*
   * Advanced Encryption Standard as specified by NIST in FIPS 197. <br/> Also known as the Rijndael
   * algorithm by Joan Daemen and Vincent Rijmen, <br/> AES is a 128-bit block cipher supporting
   * keys of 128, 192, and 256 bits.<br/>
   */
  private static final String DEFAULT_ALGORITHM = "AES";
  /* 默认转换名 */
  private static final String DEFAULT_TRANSFORMS = "AES";
  /* 默认密钥长度，256 bits */
  private static final int DEFAULT_KEY_SIZE = 256;

  public AES() {
    this(null, DEFAULT_TRANSFORMS, DEFAULT_KEY_SIZE);
  }

  public AES(int keyLength) {
    this(null, DEFAULT_TRANSFORMS, keyLength);
  }

  public AES(Provider provider) {
    this(provider, DEFAULT_TRANSFORMS, DEFAULT_KEY_SIZE);
  }

  public AES(Provider provider, int keyLength) {
    this(provider, DEFAULT_TRANSFORMS, keyLength);
  }

  public AES(String transforms) {
    this(null, transforms, DEFAULT_KEY_SIZE);
  }

  public AES(Provider provider, String transforms) {
    this(provider, transforms, DEFAULT_KEY_SIZE);
  }

  public AES(Provider provider, String transforms, int keyLength) {
    super(DEFAULT_ALGORITHM, provider, transforms, keyLength);
  }

  /**
   * 设置密钥
   *
   * @param secretKey 密钥文本
   */
  @Override
  public void setSecret(byte[] secretKey) {
    if (secretKey == null) {
      this.keyLength = 0;
      return;
    }
    // 模式一：需先设置keyLength
    //    KeyGenerator keyGenerator = Util.getKeyGenerator(algorithm, provider);
    //    keyGenerator.init(this.keyLength, new SecureRandom(secretKey));
    //    this.secretKey = keyGenerator.generateKey();
    // 模式二：使用SecretKeySpec构建
    this.secretKey = new SecretKeySpec(secretKey, algorithm);
    this.setKeyLength(this.secretKey.getEncoded().length * 8);
  }

  @Override
  public void setKeyLength(int keyLength) {
    if (keyLength != 128 && keyLength != 192 && keyLength != 256) {
      throw new IllegalStateException("Invalid key size (" + keyLength + " bits)");
    }
    super.setKeyLength(keyLength);
  }

}
