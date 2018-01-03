package io.flysium.crypto;

import io.flysium.crypto.utils.Util;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.Provider;
import javax.crypto.Mac;

/**
 *
 * MAC
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public class MAC extends SecretSpi implements IMacSpi, ISecretSpi {

  /* 默认算法名 */
  private static final String DEFAULT_ALGORITHM = "HmacSHA256";

  private Key key;

  public MAC() {
    super(DEFAULT_ALGORITHM, null);
  }

  public MAC(Provider provider) {
    super(DEFAULT_ALGORITHM, provider);
  }

  @Override
  public Key getKey() {
    return key;
  }

  @Override
  public void setKey(Key key) {
    this.key = key;
  }

  @Override
  public int getKeyLength() {
    throw new UnsupportedOperationException("not support to get KeyLength in Digest.");
  }

  @Override
  public void setKeyLength(int keyLength) {
    throw new UnsupportedOperationException("not support to set KeyLength in Digest.");
  }

  /**
   * 加密
   *
   * @param plainText 明文数据
   * @return 密文数据
   */
  @Override
  public byte[] encrypt(byte[] plainText) {
    Mac mac = Util.getMac(algorithm, provider);
    try {
      if (mac != null) {
        mac.init(key);
        return mac.doFinal(plainText);
      }
    } catch (InvalidKeyException e) {
      fail(e);
    }
    return null;
  }

}
