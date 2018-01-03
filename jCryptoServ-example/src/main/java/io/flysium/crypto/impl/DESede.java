package io.flysium.crypto.impl;

import io.flysium.crypto.ICryptoSpi;
import io.flysium.crypto.ISecretSpi;
import io.flysium.crypto.Symmetric;
import java.security.Provider;
import javax.crypto.spec.SecretKeySpec;


/**
 * DESede(即3DES)
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public class DESede extends Symmetric implements ICryptoSpi, ISecretSpi {

  /* 默认算法名 */
  private static final String DEFAULT_ALGORITHM = "DESede";
  /* 默认转换名 */
  private static final String DEFAULT_TRANSFORMS = "DESede";
  /* 默认密钥长度，168 bits */
  private static final int DEFAULT_KEY_SIZE = 168;

  public DESede() {
    this(null, DEFAULT_TRANSFORMS, DEFAULT_KEY_SIZE);
  }

  public DESede(int keyLength) {
    this(null, DEFAULT_TRANSFORMS, keyLength);
  }

  public DESede(Provider provider) {
    this(provider, DEFAULT_TRANSFORMS, DEFAULT_KEY_SIZE);
  }

  public DESede(Provider provider, int keyLength) {
    this(provider, DEFAULT_TRANSFORMS, keyLength);
  }

  public DESede(String transforms) {
    this(null, transforms, DEFAULT_KEY_SIZE);
  }

  public DESede(Provider provider, String transforms) {
    this(provider, transforms, DEFAULT_KEY_SIZE);
  }

  public DESede(Provider provider, String transforms, int keyLength) {
    super(DEFAULT_ALGORITHM, provider, transforms, keyLength);
  }

  @Override
  public void setKeyLength(int keyLength) {
    if (keyLength < 112 || keyLength > 168) {
      throw new IllegalStateException("Invalid key size (" + keyLength + " bits)");
    }
    super.setKeyLength(keyLength);
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
    // 3DES 密钥填充必须为 24 B
    byte[] key = new byte[24];
    if (key.length > secretKey.length) {
      System.arraycopy(secretKey, 0, key, 0, secretKey.length);
    } else {
      System.arraycopy(secretKey, 0, key, 0, key.length);
    }
    this.secretKey = new SecretKeySpec(key, algorithm);
    // 密钥长度暂无法确定
  }


}
