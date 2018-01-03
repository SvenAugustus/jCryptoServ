package io.flysium.crypto;

import java.security.Provider;

/**
 * 指定随同以密码为基础的加密法 (PBE) 使用的参数集合，该加密法在 PKCS #5 标准中定义。
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public abstract class PBESpec extends SecretSpi {

  public PBESpec(String algorithm, Provider provider) {
    super(algorithm, provider, false, true);
  }

}
