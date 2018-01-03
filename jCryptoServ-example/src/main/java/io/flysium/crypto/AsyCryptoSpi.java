
package io.flysium.crypto;

import java.security.Provider;

/**
 *
 * 非对称加解密SPI
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public abstract class AsyCryptoSpi extends CryptoSpi implements IAsyCryptoSpi {

  public AsyCryptoSpi(String algorithm, Provider provider, String transforms) {
    super(algorithm, provider, transforms);
  }

}
