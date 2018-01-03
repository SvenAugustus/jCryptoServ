package io.flysium.crypto;

import io.flysium.crypto.impl.DES;
import io.flysium.crypto.support.CryptoSpiUnitTest;
import org.junit.Before;
import org.junit.Test;

/**
 * DES Test.
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class DESUnitTest2 extends CryptoSpiUnitTest {

  // 前端JavaScript（CryptoJS 3.1.2）采用 CryptoJS.mode.ECB 、CryptoJS.pad.Pkcs7
  // PKCS#5和PKCS#7是一样的padding方式
  // 故此这里采用 转换名：DES/ECB/PKCS5Padding
  private final String transforms = "DES/ECB/PKCS5Padding";
  private final String KEY = "0302b20";

  @Test
  public void test() throws Exception {
    String plainText = "This is a test!";
    String jsCiperTextB64 = "PDYGU9LKjj69X33rsdWjZA==";
    testEncryptJsAndDecryptJava(des, plainText, jsCiperTextB64);
  }

  private ICryptoSpi des;

  @Before
  public void before() {
    //des = new DES();
    des = new DES(transforms);
    des.setSecret(KEY.getBytes());
    System.out.println("-------密钥长度-------" + des.getKeyLength());
  }

}
