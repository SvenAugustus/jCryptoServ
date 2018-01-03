package io.flysium.crypto.impl;

import io.flysium.crypto.Digest;
import io.flysium.crypto.ISecretSpi;
import java.security.Provider;

/**
 *
 * SHA256
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public class SHA256 extends Digest implements ISecretSpi {

  /* 默认算法名 */
  private static final String DEFAULT_ALGORITHM = "SHA-256";

  public SHA256() {
    super(DEFAULT_ALGORITHM, null);
  }

  public SHA256(Provider provider) {
    super(DEFAULT_ALGORITHM, provider);
  }

}
