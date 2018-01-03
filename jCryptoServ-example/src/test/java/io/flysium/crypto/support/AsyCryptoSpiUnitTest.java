package io.flysium.crypto.support;

import io.flysium.crypto.IAsyCryptoSpi;
import io.flysium.crypto.impl.SHA256;
import io.flysium.crypto.utils.Util;
import org.junit.Assert;

/**
 * Unit Test
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class AsyCryptoSpiUnitTest {

  protected void testEncryptAndDecrypt(IAsyCryptoSpi spi, String plainText) {
    System.out.println("-------Java加密前明文-------" + plainText);
    String ciperTextB64 = spi.encryptStringB64(plainText);
    System.out.println("-------Java加密后密文-------" + ciperTextB64);
    String decryptedText = spi.decryptStringB64(ciperTextB64);
    System.out.println("-------Java解密后明文-------" + decryptedText);
    Assert.assertEquals(plainText, decryptedText);
  }

  protected void testSignAndVerify(IAsyCryptoSpi spi, String text) {
//    System.out.println("-------Java明文文本-------" + text);
//    byte[] textB64 = Util.armor(text.getBytes());
//    byte[] signText = spi.sign(textB64);
//    String signTextHex = Util.hex(signText);
//    System.out.println("-------Java签名文本(HEX)-------" + signTextHex);
//    System.out.println("-------Java签名文本(HEX)长度-------" + signTextHex.length());
//    boolean suc = spi.verify(textB64, signText);
//    Assert.assertTrue(suc);
    System.out.println("-------Java明文文本-------" + text);
    SHA256 sha256 = new SHA256();
    // 明文的信息摘要
    byte[] textHash = sha256.encrypt(text.getBytes());
    System.out.println("-------Java明文文本信息摘要(HEX)-------" + Util.hex(textHash));
    byte[] signText = spi.sign(textHash);
    String signTextHex = Util.hex(signText);
    System.out.println("-------Java签名文本(HEX)-------" + signTextHex);
    System.out.println("-------Java签名文本(HEX)长度-------" + signTextHex.length());
    boolean suc = spi.verify(textHash, signText);
    Assert.assertTrue(suc);
  }

  protected void testEncryptJsAndDecryptJava(IAsyCryptoSpi spi, String plainText,
      String jsCiperTextB64)
      throws Exception {
    System.out.println("-------JavaScript加密前明文-------" + plainText);
    System.out.println("-------JavaScript加密后密文-------" + jsCiperTextB64);
    String decryptedText = spi.decryptStringB64(jsCiperTextB64);
    System.out.println("-------Java解密后明文-------" + decryptedText);
    Assert.assertEquals(plainText, decryptedText);
  }


}
