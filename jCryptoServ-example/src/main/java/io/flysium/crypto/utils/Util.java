package io.flysium.crypto.utils;

import java.io.UnsupportedEncodingException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.net.ssl.KeyManagerFactory;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

/**
 * 密钥体系工具类
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class Util {


  Util() {
  }

  /**
   * 对称加密的算法<br/>
   * ------------------------------<br/>
   * 算法名称 密钥长 块长 速度 说明<br/>
   * ------------------------------<br/>
   * DES | 56 | 64 | 慢 | 不安全, 不要使用<br/>
   * 3DES | 112/168 | 64 | 很慢 | 中等安全, 适合加密较小的数据<br/>
   * AES | 128, 192, 256 | 128 | 快 安全<br/>
   * Blowfish | （4至56）*8 | 64 | 快 | 应该安全, 在安全界尚未被充分分析、论证<br/>
   * RC4 | 40-1024 | 64 | 很快 | 安全性不明确<br/>
   * 一般情况下，不要选择DES算法，推荐使用AES/3DES算法。<br/>
   *
   * 密钥长度选择<br/>
   *
   * 1、对于对称加密算法，128bits的密钥足够安全，条件许可请选择256bits,<br/>
   * 注意密钥长度大于128bits需单独下载并安装jurisdiction policy files；<br/>
   * 2、对于非对称加密算法，1024bits的密钥足够安全。<br/>
   * 3、如果需要长度超128bits的密钥，需单独从Oracle官网下载对应JDK版本的Java Cryptography Extension (JCE) <br/>
   * Unlimited Strength Jurisdiction Policy Files文件，<br/>
   * 例如JDK7对应的jurisdiction policy files。<br/>
   *
   * 最后，如选用基于口令的算法或在用户输入密码时，请尽量避免使用String来引用，<br/>
   * 使用char[]，用完立刻置空char[]，避免内存攻击，如heap dump分析等。<br/>
   */

  /**
   * 获取Cipher对象
   *
   * @param transforms 转换的名称，“算法名/算法模式/填充模式” <a>https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#Cipher</a></br>
   * @param provider 封装CipherSpi实现的提供者
   * @return Cipher对象
   */
  public static Cipher getCipher(final String transforms, final Provider provider) {
    Cipher cipher = null;
    /**
     * Cipher对象构成了 Java Cryptographic Extension (JCE) 框架的核心 <br/>
     * 1、Cipher在使用时需以参数方式指定transformation <br/>
     * 2、transformation的格式为algorithm/mode/padding（算法/模式/填充）， 其中algorithm（算法）为必输项，如:
     * DES/CBC/PKCS5Padding <br/>
     * 3、缺省的mode为ECB，缺省的padding为PKCS5Padding <br/>
     * 4、在block算法与流加密模式组合时, 需在mode后面指定每次处理的bit数, 如DES/CFB8/NoPadding, 如未指定则使用缺省值, SunJCE缺省值为64bits
     * <br/>
     * 5、Cipher有4种操作模式: ENCRYPT_MODE(加密), DECRYPT_MODE(解密), WRAP_MODE(导出Key),
     * UNWRAP_MODE(导入Key)，初始化时需指定某种操作模式（都是静态参数）。 <br/>
     */
    try {
      if (provider == null) {
        cipher = Cipher.getInstance(transforms);
      } else {
        cipher = Cipher.getInstance(transforms, provider);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    } catch (NoSuchPaddingException e) {
      throw new IllegalStateException(e);
    }
    return cipher;
  }

  /**
   * 获取MAC<br/>
   * MAC技术用于确认数据的完整性，Mac要求通讯双方共享一个secret key。<br/>
   *
   * @param algorithm 算法名
   * @param provider 封装实现的提供者
   * @return MAC
   */
  public static Mac getMac(final String algorithm, final Provider provider) {
    Mac mac = null; // MAC技术用于确认数据的完整性，Mac要求通讯双方共享一个secret key
    try {
      if (provider == null) {
        mac = Mac.getInstance(algorithm);
      } else {
        mac = Mac.getInstance(algorithm, provider);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    return mac;
  }


  /**
   * 获取信息摘要<br/>
   * MessageDigest（消息摘要类）定义了使用消息摘要算法的功能。<br/>
   *
   * @param algorithm 算法名
   * @param provider 封装实现的提供者
   * @return 信息摘要
   */
  public static MessageDigest getMessageDigest(final String algorithm, final Provider provider) {
    MessageDigest messageDigest = null; // 信息摘要是安全的单向哈希函数，它接收任意大小的数据，并输出固定长度的哈希值。
    try {
      if (provider == null) {
        messageDigest = MessageDigest.getInstance(algorithm);
      } else {
        messageDigest = MessageDigest.getInstance(algorithm, provider);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    return messageDigest;
  }

  /**
   * 获取数字签名<br/>
   * Signature（签名类）定义了使用数字签名算法的功能。<br/>
   *
   * @param algorithm 算法名
   * @param provider 封装CipherSpi实现的提供者
   * @return Signature
   */
  public static Signature getSignature(final String algorithm, final Provider provider) {
    Signature signature = null;// Signature对象用来为应用程序提供数字签名算法功能。数字签名用于确保数字数据的验证和完整性。
    try {
      if (provider == null) {
        signature = Signature.getInstance(algorithm);
      } else {
        signature = Signature.getInstance(algorithm, provider);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    return signature;
  }

  /**
   * 获取密钥成器实例<br/>
   * KeyFactory（密钥工厂类）定义了在不透明的加密密钥和密钥规范之间进行转换的功能。<br/>
   *
   * @param algorithm 算法名 <a>https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyGenerator</a></br>
   * @param provider 封装CipherSpi实现的提供者
   * @return 密钥生成器
   */
  public static KeyGenerator getKeyGenerator(final String algorithm, final Provider provider) {
    KeyGenerator keyGenerator = null;
    try {
      if (provider == null) {
        keyGenerator = KeyGenerator.getInstance(algorithm);
      } else {
        keyGenerator = KeyGenerator.getInstance(algorithm, provider);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    return keyGenerator;
  }

  /**
   * 获取密钥对生成器实例<br/>
   * KeyPairGeneator（密钥对生成器类）定义了生成指定算法的公私钥对的功能。<br/>
   *
   * @param algorithm 算法名 <a>https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyPairGenerator</a></br>
   * @param provider 封装CipherSpi实现的提供者
   * @return 密钥对生成器
   */
  public static KeyPairGenerator getKeyPairGenerator(final String algorithm,
      final Provider provider) {
    KeyPairGenerator keyPairGen = null;
    try {
      if (provider == null) {
        keyPairGen = KeyPairGenerator.getInstance(algorithm);
      } else {
        keyPairGen = KeyPairGenerator.getInstance(algorithm, provider);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    return keyPairGen;
  }

  /**
   * 获取密钥协商实例<br/>
   *
   * @param algorithm 算法名 <a>https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyAgreement</a></br>
   * @param provider 封装CipherSpi实现的提供者
   * @return 密钥协商实例
   */
  public static KeyAgreement getKeyAgreement(final String algorithm, final Provider provider) {
    KeyAgreement keyAgreement = null;
    try {
      if (provider == null) {
        keyAgreement = KeyAgreement.getInstance(algorithm);
      } else {
        keyAgreement = KeyAgreement.getInstance(algorithm, provider);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    return keyAgreement;
  }

  /**
   * 获取密钥管理器实例
   *
   * @param algorithm 算法名 <a>https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyManagerFactory</a></br>
   * @param provider 封装CipherSpi实现的提供者
   * @return 密钥管理器
   */
  public static KeyManagerFactory getKeyManagerFactory(final String algorithm,
      final Provider provider) {
    KeyManagerFactory keyManagerFactory = null;
    try {
      if (provider == null) {
        keyManagerFactory = KeyManagerFactory.getInstance(algorithm);
      } else {
        keyManagerFactory = KeyManagerFactory.getInstance(algorithm, provider);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    return keyManagerFactory;
  }

  /**
   * 获取密钥工厂实例
   *
   * @param algorithm 算法名 <a>https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#SecretKeyFactory</a></br>
   * @param provider 封装CipherSpi实现的提供者
   * @return 密钥工厂
   */
  public static SecretKeyFactory getSecretKeyFactory(final String algorithm,
      final Provider provider) {
    SecretKeyFactory keyFactory = null;
    try {
      if (provider == null) {
        keyFactory = SecretKeyFactory.getInstance(algorithm);
      } else {
        keyFactory = SecretKeyFactory.getInstance(algorithm, provider);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    return keyFactory;
  }

  /**
   * 获取密钥工厂实例
   *
   * @param algorithm 算法名 <a>https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyFactory</a></br>
   * @param provider 封装CipherSpi实现的提供者
   * @return 密钥工厂
   */
  public static KeyFactory getKeyFactory(final String algorithm, final Provider provider) {
    KeyFactory keyFactory = null;
    try {
      if (provider == null) {
        keyFactory = KeyFactory.getInstance(algorithm);
      } else {
        keyFactory = KeyFactory.getInstance(algorithm, provider);
      }
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
    return keyFactory;
  }

  /**
   * 生成随机密钥
   *
   * @param keyLength 密钥长度
   * @param algorithm 算法名 <a>https://docs.oracle.com/javase/7/docs/technotes/guides/security/StandardNames.html#KeyGenerator</a></br>
   * @param provider 封装CipherSpi实现的提供者
   */
  public static SecretKey generateKey(int keyLength, final String algorithm,
      final Provider provider) {
    /* RSA算法要求有一个可信任的随机数源 */
    SecureRandom secureRandom = new SecureRandom();
    /* 为RSA算法创建一个KeyPairGenerator对象 */
    KeyGenerator keyGenerator = Util.getKeyGenerator(algorithm, provider);
    /* 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
    keyGenerator.init(keyLength, secureRandom);
    /* 生成密钥 */
    return keyGenerator.generateKey();
  }

  /**
   * 随机生成密钥对
   *
   * @param keyLength 密钥长度
   * @param algorithm 算法名
   * @param provider 封装CipherSpi实现的提供者
   */
  public static KeyPair generateKeyPair(int keyLength, final String algorithm,
      final Provider provider) {
    KeyPair keyPair = null;
    try {
      /* RSA算法要求有一个可信任的随机数源 */
      SecureRandom secureRandom = new SecureRandom();
      /* 为RSA算法创建一个KeyPairGenerator对象 */
      KeyPairGenerator keyPairGen = Util.getKeyPairGenerator(algorithm, provider);
      /* 利用上面的随机数据源初始化这个KeyPairGenerator对象 */
      keyPairGen.initialize(keyLength, secureRandom);
      /* 生成密钥对 */
      keyPair = keyPairGen.generateKeyPair();
    } catch (Exception e) {
      throw new IllegalStateException(e);
    }
    return keyPair;
  }

  /**
   * Base64编码
   */
  public static byte[] armor(byte[] bytes) {
    return Base64.encodeBase64(bytes);
  }

  /**
   * Base64解码
   */
  public static byte[] unarmor(byte[] bytes) {
    return Base64.decodeBase64(bytes);
  }

  /**
   * Base64解码
   */
  public static byte[] unarmor(String str) {
    return unarmor(str.getBytes());
  }

  /**
   * Base64解码
   */
  public static byte[] unarmor(String str, String charsetName) {
    try {
      return unarmor(str.getBytes(charsetName));
    } catch (UnsupportedEncodingException e) {
      throw new IllegalStateException(e);
    }
  }

  /**
   * 字节数组转为16进制字符串
   */
  public static String hex(byte[] bytes) {
    return new String(Hex.encodeHex(bytes, true));
  }

  /**
   * 16进制字符串转为字节数组
   */
  public static byte[] unhex(String str) {
    try {
      return Hex.decodeHex(str.toCharArray());
    } catch (DecoderException e) {
      throw new IllegalStateException(e);
    }
  }

  private static final String randomTemplate = "abcdefghijklmnopqrstuvwxyz0123456789";

  /**
   * 随机字符串
   *
   * @param size 长度
   * @return 随机的固定长度的字符串
   */
  public static String randomStr(int size) {
    StringBuilder buffer = new StringBuilder();
    Random random = new Random();
    while (buffer.length() < size) {
      int index = random.nextInt(randomTemplate.length());
      char c = randomTemplate.charAt(index);
      buffer.append(c);
    }
    return buffer.toString();
  }

}
