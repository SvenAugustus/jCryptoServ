package io.flysium.crypto;

import java.security.Key;

/**
 *
 * MAC技术
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public interface IMacSpi extends ISecretSpi {

  /**
   * 获取共享secret
   */
  Key getKey();

  /**
   * 设置共享secret
   */
  void setKey(Key key);

}
