package io.flysium.crypto;

import io.flysium.crypto.utils.Util;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 * 非对称加解密算法
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public abstract class Asymmetric extends AsyCryptoSpi implements IAsyCryptoSpi {

  /* 公钥 */
  protected PublicKey publicKey;
  /* 私钥 */
  protected PrivateKey privateKey;
  /* 签名算法名 */
  protected String signatureAlgorithm;
  /* Signature本地线程变量 */
  protected ThreadLocal<Signature> signatureThreadLocal = new ThreadLocal<Signature>() {

    @Override
    public Signature get() {
      Signature signature = super.get();
      if (signature == null) {
        assert signatureAlgorithm != null;
        signature = Util.getSignature(Asymmetric.this.signatureAlgorithm, Asymmetric.this.provider);
      }
      return signature;
    }
  };

  public Asymmetric(String algorithm, Provider provider, String transforms) {
    super(algorithm, provider, transforms);
  }

  public Asymmetric(String algorithm, Provider provider, String transforms, String publicKeyB64,
      String privateKeyB64) {
    super(algorithm, provider, transforms);
    this.setPublicKey(publicKeyB64);
    this.setPrivateKey(privateKeyB64);
  }

  public Provider getProvider() {
    return provider;
  }

  public String getTransforms() {
    return transforms;
  }

  @Override
  public String getSignatureAlgorithm() {
    return signatureAlgorithm;
  }

  @Override
  public void setSignatureAlgorithm(String signatureAlgorithm) {
    this.signatureAlgorithm = signatureAlgorithm;
  }

  public KeyPair getKeyPair() {
    return new KeyPair(publicKey, privateKey);
  }

  public void setKeyPair(KeyPair keyPair) {
    this.publicKey = keyPair.getPublic();
    this.privateKey = keyPair.getPrivate();
  }

  @Override
  public byte[] getSecret() {
    throw new UnsupportedOperationException("not support to get secret in Asymmetric.");
  }

  @Override
  public void setSecret(byte[] secretKey) {
    throw new UnsupportedOperationException("not support to set secret in Asymmetric.");
  }

  /**
   * 获取公钥文本
   *
   * @return Base64编码形式的公钥文本
   */
  @Override
  public String getPublicKey() {
    return new String(Util.armor(this.publicKey.getEncoded()));
  }

  /**
   * 获取私钥文本
   *
   * @return Base64编码形式的私钥文本
   */
  @Override
  public String getPrivateKey() {
    return new String(Util.armor(this.privateKey.getEncoded()));
  }

  /**
   * 生成随机密钥对
   */
  @Override
  public void generateKey(int keyLength) {
    KeyPair keyPair = Util.generateKeyPair(keyLength, algorithm, provider);
    this.publicKey = keyPair.getPublic();
    this.privateKey = keyPair.getPrivate();
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
          cipher.init(Cipher.ENCRYPT_MODE, this.publicKey, algorithmParameterSpec);
        } else {
          cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
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
          cipher.init(Cipher.DECRYPT_MODE, this.privateKey, algorithmParameterSpec);
        } else {
          cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
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

  /**
   * 数字签名
   *
   * @param input 输入缓冲区
   * @return 签名操作结果的签名字节
   */
  @Override
  public byte[] sign(byte[] input) {
    Signature signature = signatureThreadLocal.get();
    try {
      if (signature != null) {
        signature.initSign(privateKey);
        signature.update(input);

        return signature.sign();
      }
    } catch (InvalidKeyException e) {
      fail(e);
    } catch (SignatureException e) {
      fail(e);
    }
    return null;
  }

  /**
   * 签名校验
   *
   * @param input 输入缓冲区
   * @param sign 签名字节
   * @return 如果签名得到验证，则返回 true，否则将返回 false。
   */
  @Override
  public boolean verify(byte[] input, byte[] sign) {
    Signature signature = signatureThreadLocal.get();
    try {
      if (signature != null) {
        signature.initVerify(this.publicKey);
        signature.update(input);

        return signature.verify(sign);
      }
    } catch (InvalidKeyException e) {
      fail(e);
    } catch (SignatureException e) {
      fail(e);
    }
    return false;
  }

}
