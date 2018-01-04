package io.flysium.crypto;

import io.flysium.crypto.impl.DESede;
import io.flysium.crypto.support.CryptoSpiUnitTest;
import org.junit.Before;
import org.junit.Test;

/**
 * DESede Test.
 *
 * @author Sven Augustus
 * @version 1.0
 * @since JDK 1.7
 */
public class DESedeUnitTest2 extends CryptoSpiUnitTest {

  // 前端JavaScript（CryptoJS 3.1.2）采用 CryptoJS.mode.ECB 、CryptoJS.pad.Pkcs7
  // PKCS#5和PKCS#7是一样的padding方式
  // 故此这里采用 转换名：DESede/ECB/PKCS5Padding
  private final String transforms = "DESede/ECB/PKCS5Padding";
  private final String KEY = "237aa171ee2aaa55";

  @Test
  public void test() throws Exception {
    String plainText = "This is a test!";
    String jsCiperTextB64 = "ncTFMRrPTFnV/+fmhHE/9w==";
    testEncryptJsAndDecryptJava(desede, plainText, jsCiperTextB64);
  }

  private ICryptoSpi desede;

  @Before
  public void before() {
    // des = new DESede();
    desede = new DESede(transforms);
    desede.setSecret(KEY.getBytes());
    System.out.println("-------密钥长度-------" + (desede.getSecret().length * 8));
  }

}
