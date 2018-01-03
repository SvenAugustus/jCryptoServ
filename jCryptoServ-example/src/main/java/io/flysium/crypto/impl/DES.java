package io.flysium.crypto.impl;

import io.flysium.crypto.ICryptoSpi;
import io.flysium.crypto.ISecretSpi;
import io.flysium.crypto.Symmetric;
import io.flysium.crypto.utils.Util;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;


/**
 * DES
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public class DES extends Symmetric implements ICryptoSpi, ISecretSpi {

  /* 默认算法名 */
  private static final String DEFAULT_ALGORITHM = "DES";
  /* 默认转换名 */
  private static final String DEFAULT_TRANSFORMS = "DES";
  /* 默认密钥长度，56 bits */
  private static final int DEFAULT_KEY_SIZE = 56;

  public DES() {
    this(null, DEFAULT_TRANSFORMS, DEFAULT_KEY_SIZE);
  }

  public DES(int keyLength) {
    this(null, DEFAULT_TRANSFORMS, keyLength);
  }

  public DES(Provider provider) {
    this(provider, DEFAULT_TRANSFORMS, DEFAULT_KEY_SIZE);
  }

  public DES(Provider provider, int keyLength) {
    this(provider, DEFAULT_TRANSFORMS, keyLength);
  }

  public DES(String transforms) {
    this(null, transforms, DEFAULT_KEY_SIZE);
  }

  public DES(Provider provider, String transforms) {
    this(provider, transforms, DEFAULT_KEY_SIZE);
  }

  public DES(Provider provider, String transforms, int keyLength) {
    super(DEFAULT_ALGORITHM, provider, transforms, keyLength);
  }

  @Override
  public void setKeyLength(int keyLength) {
    if (keyLength != 56) {
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
    try {
      // DES 密钥填充必须为 8 B
      byte[] key = new byte[8];
      if (key.length > secretKey.length) {
        System.arraycopy(secretKey, 0, key, 0, secretKey.length);
      } else {
        System.arraycopy(secretKey, 0, key, 0, key.length);
      }
      DESKeySpec secretKeySpec = new DESKeySpec(key);
      SecretKeyFactory keyFactory = Util.getSecretKeyFactory(algorithm, provider);
      this.secretKey = keyFactory.generateSecret(secretKeySpec);
    } catch (InvalidKeyException e) {
      fail(e);
    } catch (InvalidKeySpecException e) {
      fail(e);
    }
    // DES 密钥长度 56 Bits，另有8位 是奇偶校验位
    // this.setKeyLength(56);
    // 密钥长度暂无法确定
  }

}
