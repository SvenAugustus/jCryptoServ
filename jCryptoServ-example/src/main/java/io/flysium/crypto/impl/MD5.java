package io.flysium.crypto.impl;

import io.flysium.crypto.Digest;
import io.flysium.crypto.ISecretSpi;
import java.security.Provider;

/**
 *
 * MD5
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public class MD5 extends Digest implements ISecretSpi {

  /* 默认算法名 */
  private static final String DEFAULT_ALGORITHM = "MD5";

  public MD5() {
    super(DEFAULT_ALGORITHM, null);
  }

  public MD5(Provider provider) {
    super(DEFAULT_ALGORITHM, provider);
  }

}
