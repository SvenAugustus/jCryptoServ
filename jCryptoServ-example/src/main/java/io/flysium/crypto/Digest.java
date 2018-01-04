package io.flysium.crypto;

import io.flysium.crypto.utils.Util;
import java.security.MessageDigest;
import java.security.Provider;

/**
 * 信息摘要，不可逆加密算法
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public class Digest extends SecretSpi {

  /* MessageDigest本地线程变量 */
  protected ThreadLocal<MessageDigest> cipherThreadLocal = new ThreadLocal<MessageDigest>() {

    @Override
    public MessageDigest get() {
      MessageDigest messageDigest = super.get();
      if (messageDigest == null) {
        messageDigest = Util.getMessageDigest(Digest.this.algorithm, Digest.this.provider);
      }
      return messageDigest;
    }
  };

  public Digest(String algorithm, Provider provider) {
    super(algorithm, provider);
  }

  /**
   * 加密
   *
   * @param plainText 明文数据
   * @return 密文数据
   */
  @Override
  public byte[] encrypt(byte[] plainText) {
    MessageDigest messageDigest = cipherThreadLocal.get();
    if (messageDigest != null) {
      messageDigest.update(plainText);
      return messageDigest.digest();
    }
    return null;
  }

}
