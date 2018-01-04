package io.flysium.crypto;

import io.flysium.crypto.utils.Util;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Provider;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * 对称加解密算法
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public abstract class Symmetric extends CryptoSpi {

  /* 对称密钥 */
  protected SecretKey secretKey = null;


  public Symmetric(String algorithm, Provider provider, String transforms) {
    super(algorithm, provider, transforms);
  }

  /**
   * 获取密钥
   *
   * @return 密钥文本
   */
  @Override
  public byte[] getSecret() {
    return secretKey.getEncoded();
  }


  @Override
  public void setAlgorithmParameterSpec(AlgorithmParameterSpec spec) {
    assert spec != null;
    if (spec instanceof IvParameterSpec) {
      byte[] iv = ((IvParameterSpec) spec).getIV();
      if (iv == null || iv.length != 16) {
        throw new IllegalStateException("Invalid iv size (" + iv.length + " bits)");
      }
    }
    super.setAlgorithmParameterSpec(spec);
  }

  /**
   * 生成随机密钥
   */
  @Override
  public void generateKey(int keyLength) {
    this.secretKey = Util.generateKey(keyLength, algorithm, provider);
  }

  /**
   * 加密
   *
   * @param plainText 明文数据
   * @return 密文数据
   */
  @Override
  public byte[] encrypt(byte[] plainText) {
    Cipher cipher = cipherThreadLocal.get();
    try {
      if (cipher != null) {
        if (algorithmParameterSpec != null) {
          cipher.init(Cipher.ENCRYPT_MODE, this.secretKey, algorithmParameterSpec);
        } else {
          cipher.init(Cipher.ENCRYPT_MODE, this.secretKey);
        }

        return doFinal(cipher, Cipher.ENCRYPT_MODE, plainText);
      }
    } catch (InvalidKeyException e) {
      fail(e);
    } catch (InvalidAlgorithmParameterException e) {
      fail(e);
    }
    return null;
  }

  /**
   * 解密
   *
   * @param cipherText 密文数据
   * @return 明文数据
   */
  @Override
  public byte[] decrypt(byte[] cipherText) {
    Cipher cipher = cipherThreadLocal.get();
    try {
      if (cipher != null) {
        if (algorithmParameterSpec != null) {
          cipher.init(Cipher.DECRYPT_MODE, this.secretKey, algorithmParameterSpec);
        } else {
          cipher.init(Cipher.DECRYPT_MODE, this.secretKey);
        }

        return doFinal(cipher, Cipher.DECRYPT_MODE, cipherText);
      }
    } catch (InvalidKeyException e) {
      fail(e);
    } catch (InvalidAlgorithmParameterException e) {
      fail(e);
    }
    return null;
  }

  /**
   * 整体加解密运算，完成加密或解密数据
   *
   * @param cipher Cipher对象
   * @param mode 模式
   * @param input 输入缓冲区
   * @return 包含结果的新缓冲区
   */
  protected byte[] doFinal(Cipher cipher, int mode, byte[] input) {
    try {
      return cipher.doFinal(input);
    } catch (IllegalBlockSizeException e) {
      fail(e);
    } catch (BadPaddingException e) {
      fail(e);
    }
    return null;
  }

}
