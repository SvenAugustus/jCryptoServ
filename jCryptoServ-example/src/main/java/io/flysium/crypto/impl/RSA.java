package io.flysium.crypto.impl;

import io.flysium.crypto.Asymmetric;
import io.flysium.crypto.IAsyCryptoSpi;
import io.flysium.crypto.ISecretSpi;
import io.flysium.crypto.utils.Util;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import org.apache.commons.lang.StringUtils;

/**
 * RSA
 *
 * @author SvenAugustus
 * @version 1.0
 * @since JDK 1.7
 */
public class RSA extends Asymmetric implements IAsyCryptoSpi, ISecretSpi {

  /* 默认算法名 */
  private static final String DEFAULT_ALGORITHM = "RSA";// The RSA encryption algorithm as defined
                                                        // in PKCS #1
  /* 默认转换名 */
  private static final String DEFAULT_TRANSFORMS = "RSA";
  /* 默认密钥长度，1024 bits */
  private static final int DEFAULT_KEY_SIZE = 1024;
  /* 默认签名算法名 */
  private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA";

  public RSA() {
    this(null, DEFAULT_TRANSFORMS, DEFAULT_KEY_SIZE);
  }

  public RSA(int keyLength) {
    this(null, DEFAULT_TRANSFORMS, keyLength);
  }

  public RSA(Provider provider) {
    this(provider, DEFAULT_TRANSFORMS, DEFAULT_KEY_SIZE);
  }

  public RSA(Provider provider, int keyLength) {
    this(provider, DEFAULT_TRANSFORMS, keyLength);
  }

  public RSA(String transforms) {
    this(null, transforms, DEFAULT_KEY_SIZE);
  }

  public RSA(Provider provider, String transforms) {
    this(provider, transforms, DEFAULT_KEY_SIZE);
  }

  public RSA(Provider provider, String transforms, int keyLength) {
    super(DEFAULT_ALGORITHM, provider, transforms, keyLength);
    super.setSignatureAlgorithm(DEFAULT_SIGNATURE_ALGORITHM);
  }

  public RSA(String publicKeyStr, String privateKeyStr) {
    this(null, DEFAULT_TRANSFORMS, publicKeyStr, privateKeyStr);
  }

  public RSA(Provider provider, String transforms, String publicKeyB64, String privateKeyB64) {
    super(DEFAULT_ALGORITHM, provider, transforms, publicKeyB64, privateKeyB64);
    super.setSignatureAlgorithm(DEFAULT_SIGNATURE_ALGORITHM);
  }

  @Override
  public void setKeyPair(KeyPair keyPair) {
    super.setKeyPair(keyPair);
    this.keyLength = ((RSAPublicKey) publicKey).getModulus().bitLength();
  }

  /**
   * 设置公钥
   *
   * @param publicKeyB64 Base64编码形式的公钥文本
   */
  @Override
  public void setPublicKey(String publicKeyB64) {
    if (StringUtils.isEmpty(publicKeyB64)) {
      return;
    }
    try {
      byte[] buffer = Util.unarmor(publicKeyB64);
      X509EncodedKeySpec keySpec = new X509EncodedKeySpec(buffer);

      KeyFactory keyFactory = Util.getKeyFactory(algorithm, provider);
      this.publicKey = (PublicKey) keyFactory.generatePublic(keySpec);
    } catch (InvalidKeySpecException e) {
      fail(e);
    }
    this.keyLength = ((RSAPublicKey) publicKey).getModulus().bitLength();
  }

  /**
   * 设置私钥
   *
   * @param privateKeyB64 Base64编码形式的私钥文本
   */
  @Override
  public void setPrivateKey(String privateKeyB64) {
    if (StringUtils.isEmpty(privateKeyB64)) {
      return;
    }
    try {
      byte[] buffer = Util.unarmor(privateKeyB64);
      PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);

      KeyFactory keyFactory = Util.getKeyFactory(algorithm, provider);
      this.privateKey = (PrivateKey) keyFactory.generatePrivate(keySpec);
    } catch (InvalidKeySpecException e) {
      fail(e);
    }
  }


  /**
   * 整体加解密运算，完成加密或解密数据
   *
   * @param cipher Cipher对象
   * @param mode 模式
   * @param input 输入缓冲区
   * @return 包含结果的新缓冲区
   */
  @Override
  protected byte[] doFinal(Cipher cipher, int mode, byte[] input) {
    ByteArrayOutputStream out = null;
    try {
      // java.lang.ArrayIndexOutOfBoundsException: too much data for RSA block
      // Padding模式下，其中PKCS#1建议的Padding就占用了11个字节
      final int maxBlockLength = (cipher.getBlockSize() > 0) ? cipher.getBlockSize()
          : (Cipher.DECRYPT_MODE == mode) ? (this.keyLength / 8) : (this.keyLength / 8 - 11);
      int length = input.length;
      if (length <= maxBlockLength) {
        return cipher.doFinal(input);
      }

      out = new ByteArrayOutputStream();
      int offSet = 0;
      byte[] cache;
      int i = 0;
      while (length - offSet > 0) {
        if (length - offSet <= maxBlockLength) {
          cache = cipher.doFinal(input, offSet, length - offSet);
        } else {
          cache = cipher.doFinal(input, offSet, maxBlockLength);
        }
        out.write(cache, 0, cache.length);
        i++;
        offSet = i * maxBlockLength;
      }
      return out.toByteArray();

    } catch (IllegalBlockSizeException e) {
      fail(e);
    } catch (BadPaddingException e) {
      fail(e);
    } finally {
      try {
        if (out != null) {
          out.close();
        }
      } catch (IOException e) {
        e.printStackTrace();
      }
    }
    return null;
  }

}
