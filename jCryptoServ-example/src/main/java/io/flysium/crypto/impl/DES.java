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
  public static final int DEFAULT_KEY_SIZE = 56;

  public DES() {
    this(null, DEFAULT_TRANSFORMS);
  }

  public DES(Provider provider) {
    this(provider, DEFAULT_TRANSFORMS);
  }

  public DES(String transforms) {
    this(null, transforms);
  }

  public DES(Provider provider, String transforms) {
    super(DEFAULT_ALGORITHM, provider, transforms);
  }

  /**
   * 生成随机密钥
   */
  @Override
  public void generateKey() {
    generateKey(DEFAULT_KEY_SIZE);
  }

  @Override
  public void generateKey(int keyLength) {
    if (keyLength != 56) {
      throw new IllegalStateException("Invalid key size (" + keyLength + " bits)");
    }
    super.generateKey(keyLength);
  }

  /**
   * 设置密钥
   *
   * @param secretKey 密钥文本
   */
  @Override
  public void setSecret(byte[] secretKey) {
    if (secretKey == null) {
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
  }

}
