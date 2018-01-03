package io.flysium.crypto.impl;

import io.flysium.crypto.Digest;
import io.flysium.crypto.ISecretSpi;
import java.security.Provider;

/**
 *
 * SHA1
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public class SHA1 extends Digest implements ISecretSpi {

  /* 默认算法名 */
  private static final String DEFAULT_ALGORITHM = "SHA-1";

  public SHA1() {
    super(DEFAULT_ALGORITHM, null);
  }

  public SHA1(Provider provider) {
    super(DEFAULT_ALGORITHM, provider);
  }

}
