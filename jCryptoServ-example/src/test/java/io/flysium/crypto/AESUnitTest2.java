package io.flysium.crypto;

import io.flysium.crypto.impl.AES;
import io.flysium.crypto.support.CryptoSpiUnitTest;
import org.junit.Before;
import org.junit.Test;

/**
 * AES Test.
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class AESUnitTest2 extends CryptoSpiUnitTest {

  // 前端JavaScript（CryptoJS 3.1.2）采用 CryptoJS.mode.ECB 、CryptoJS.pad.Pkcs7
  // PKCS#5和PKCS#7是一样的padding方式
  // 故此这里采用 转换名：AES/ECB/PKCS5Padding
  private final String transforms = "AES/ECB/PKCS5Padding";
  private final String KEY = "8252821eb785644d";

  @Test
  public void testEncryptJsAndDecryptJava() throws Exception {
    String plainText = "This is a test!";
    String jsCiperTextB64 = "vTKwzA5kbeef0HvfUeac5Q==";
    testEncryptJsAndDecryptJava(aes, plainText, jsCiperTextB64);
  }

  private ICryptoSpi aes;

  @Before
  public void before() {
    // aes = new AES();
    aes = new AES(transforms);
    aes.setSecret(KEY.getBytes());
    System.out.println("-------密钥长度-------" + (aes.getSecret().length * 8));
  }

}
