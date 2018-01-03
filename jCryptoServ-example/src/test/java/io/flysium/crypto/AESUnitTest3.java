package io.flysium.crypto;

import io.flysium.crypto.impl.AES;
import io.flysium.crypto.impl.PBKDF2WithHmacSHA1;
import io.flysium.crypto.support.CryptoSpiUnitTest;
import io.flysium.crypto.utils.SpecUtil;
import io.flysium.crypto.utils.Util;
import org.apache.commons.lang.StringUtils;
import org.junit.Before;
import org.junit.Test;

/**
 * AES Test.
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class AESUnitTest3 extends CryptoSpiUnitTest {

  private final String transforms = "AES/CBC/PKCS5Padding";
  private final String KEY = "17851d5650c868de";

  @Test
  public void testEncryptJsAndDecryptJava() throws Exception {
    String plainText = "17851d5650c868de";
    String jsCiperTextB64 = "TT2abjuKRJjmsnGK4SgJT3Oh+RNsyWmB5GOQ0x483t8=";
    testEncryptJsAndDecryptJava(aes, plainText, jsCiperTextB64);
  }

  private ICryptoSpi aes;

  @Before
  public void before() {
    // aes = new AES();
    aes = new AES(transforms);
    //aes = new AES(new BouncyCastleProvider(), transforms);
    aesConfig(aes, KEY);
    System.out.println("-------密钥长度-------" + aes.getKeyLength());
  }

  private static ISecretSpi pbkdf2() {
    ISecretSpi secretSpi = new PBKDF2WithHmacSHA1(128);
    return secretSpi;
  }

  private static void aesConfig(ICryptoSpi spi, String AESEncryptionKey) {
    // 约定送过来的key为hex编码形式，不小于32位长度部前面补0
    String saltHex = StringUtils.leftPad(AESEncryptionKey, 32, '0');
    String ivHex = StringUtils.leftPad(AESEncryptionKey, 32, '0');

    byte[] salt = Util.unhex(saltHex);
    byte[] iv = Util.unhex(ivHex);

    ISecretSpi secretSpi = pbkdf2();
    secretSpi.setAlgorithmParameterSpec(SpecUtil.buildPBE(salt));
    String secretKeyHex = secretSpi.encryptStringHex(AESEncryptionKey);
    byte[] secretKey = Util.unhex(secretKeyHex);

    spi.setSecret(secretKey);
    spi.setAlgorithmParameterSpec(SpecUtil.buildIV(iv));
  }


}
