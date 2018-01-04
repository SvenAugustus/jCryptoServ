package io.flysium.security.web;

import io.flysium.crypto.IAsyCryptoSpi;
import io.flysium.crypto.ICryptoSpi;
import io.flysium.crypto.ISecretSpi;
import io.flysium.crypto.utils.SpecUtil;
import io.flysium.crypto.utils.Util;
import io.flysium.crypto.impl.AES;
import io.flysium.crypto.impl.PBKDF2WithHmacSHA1;
import io.flysium.crypto.impl.RSA;
import java.io.IOException;
import java.security.Provider;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.lang.StringUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/**
 * 密钥安全服务</br>
 *
 * 客户端与服务器加密传输数据的处理机制：</br>
 * 1、客户端向服务端请求RSA公钥，服务端生成RSA密钥对，并存入session中，返回RSA公钥给客户端。</br>
 * 2、客户端随机生成一个AES密钥串，用取的RSA公钥，采用RSA算法，加密AES密钥串后送给服务端。</br>
 * 3、服务端接收到握手交换密钥的请求，使用RSA算法，使用session中的私钥解密，得到原始的AES密钥串，存入session中。</br>
 * 4、服务端使用AES加密算法，AES密钥串自旋加密（AES密钥串本身作为明文和AES密钥自我加密），返回给客户端。</br>
 * 5、客户端采用AES算法和自保留的AES密钥串解密，校验成功，则服务端是合法的服务器。</br>
 * 6、采用刚刚的AES密钥串，采用一定的参数拼接方式（建议ASCII+JSON）加密数据，送给服务端。</br>
 * 7、服务端采用session中的AES密钥串解密数据，得到原始的参数。</br>
 *
 * @author SvenAugustus
 * @since JDK 1.7
 */
public class CryptoServlet extends HttpServlet {

  private static final long serialVersionUID = -1874324382371696622L;

  private static volatile boolean enable = false;

  @Override
  public void init() throws ServletException {
    super.init();
    enable = true;
  }

  @Override
  public void destroy() {
    super.destroy();
    enable = false;
  }

  public static boolean isEnable() {
    return enable;
  }

  @Override
  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    this.doPost(req, resp);
  }

  @Override
  protected void doPost(HttpServletRequest req, HttpServletResponse resp)
      throws ServletException, IOException {
    if (!CryptoServlet.isEnable()) {
      return;
    }
    StringBuffer out = new StringBuffer();
    try {
      /** Generates key pair */
      /**
       * 1、客户端向服务端请com.ztesoft.iot.core.security.utils.aes求RSA公钥，服务端生成RSA密钥对，并存入session中，返回RSA公钥给客户端。
       */
      if (req.getParameter("generateKeyPair") != null) {
        IAsyCryptoSpi asySpi = rsaFetchFromSession(req.getSession());

        out.append("{\"publickey\":\"");
        out.append(asySpi.getPublicKey());
        out.append("\"}");
      }
      /** Handshakes */
      // 2、客户端随机生成一个AES密钥串，用取的RSA公钥，采用RSA算法，加密AES密钥串后送给服务端。
      /** 3、服务端接收到握手交换密钥的请求，使用RSA算法，使用session中的私钥解密，得到原始的AES密钥串，存入session中。 */
      if (req.getParameter("handshakes") != null && req.getParameter("key") != null) {
        String encryptedKey = req.getParameter("key");

        IAsyCryptoSpi asySpi = rsaFetchFromSession(req.getSession());
        String AESEncryptionKey = asySpi.decryptStringB64(encryptedKey);

        /** 4、服务端使用AES加密算法，AES密钥串自旋加密（AES密钥串本身作为明文和AES密钥自我加密），返回给客户端。 */
        ICryptoSpi spi = aesFetchToSession(req.getSession(), AESEncryptionKey);
        String challenge = spi.encryptStringB64(AESEncryptionKey);

        out.append("{\"challenge\":\"");
        out.append(challenge);
        out.append("\"}");
      }
      // 5、客户端采用AES算法和自保留的AES密钥串解密，校验成功，则服务端是合法的服务器。
      // 6、采用刚刚的AES密钥串，采用一定的参数拼接方式（建议ASCII+JSON）加密数据，送给服务端。
      /** 7、服务端采用session中的AES密钥串解密数据，得到原始的参数。 */
    } catch (Exception e) {
      e.printStackTrace();
    } finally {
      resp.setContentType("application/json;charset=UTF-8");
      resp.setCharacterEncoding("UTF-8");
      resp.getWriter().print(out.toString());
    }
  }

  private static final Provider PROVIDER = new BouncyCastleProvider();

  private static IAsyCryptoSpi rsa() {
    /**
     * RSA工具 <br/>
     * 前端JavaScript（JSEncrypt 2.3.1）采用PKCS #1，<br/>
     * 故此这里采用 转换名：RSA/NONE/PKCS1Padding <br/>
     */
    // 以下两种皆适用
    // IAsyCryptoSpi spi = new RSA();
    IAsyCryptoSpi spi = new RSA(PROVIDER, "RSA/NONE/PKCS1Padding");
    return spi;
  }

  private static ISecretSpi pbkdf2() {
    /**
     * 采用128 Bits生成AES密钥 <br/>
     * 避免JCE 限制（the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy.）<br/>
     */
    ISecretSpi secretSpi = new PBKDF2WithHmacSHA1(128);
    return secretSpi;
  }

  private static ICryptoSpi aes() {
    /**
     * AES工具 <br/>
     * 前端JavaScript（CryptoJS 3.1.2）采用 CryptoJS.mode.ECB 、CryptoJS.pad.Pkcs7，<br/>
     * 故此这里采用 转换名：AES/ECB/PKCS5Padding <br/>
     */
    // PKCS5Padding和PKCS7Padding是一样的
    // 以下两种皆适用
    // ICryptoSpi spi = new AES("AES/CBC/PKCS5Padding");
    ICryptoSpi spi = new AES(PROVIDER, "AES/CBC/PKCS5Padding");
    return spi;
  }

  private static final String SESSIONATTR_CRYPTO_RSA_PUBLIC = "io.flusium.crypto.rsa.public";
  private static final String SESSIONATTR_CRYPTO_RSA_PRIVATE = "io.flusium.crypto.rsa.private";
  private static final String SESSIONATTR_CRYPTO_KEY = "io.flusium.crypto.key";

  private static IAsyCryptoSpi rsaFetchFromSession(HttpSession session) {
    IAsyCryptoSpi spi = rsa();
    String publicKeyStr = (String) session.getAttribute(SESSIONATTR_CRYPTO_RSA_PUBLIC);
    String privateKeyStr = (String) session.getAttribute(SESSIONATTR_CRYPTO_RSA_PRIVATE);

    if (StringUtils.isEmpty(publicKeyStr) || StringUtils.isEmpty(privateKeyStr)) {
      spi.generateKey();
      publicKeyStr = spi.getPublicKey();
      privateKeyStr = spi.getPrivateKey();
      session.setAttribute(SESSIONATTR_CRYPTO_RSA_PUBLIC, publicKeyStr);
      session.setAttribute(SESSIONATTR_CRYPTO_RSA_PRIVATE, privateKeyStr);
    } else {
      spi.setPublicKey(publicKeyStr);
      spi.setPrivateKey(privateKeyStr);
    }
    return spi;
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

  private ICryptoSpi aesFetchToSession(HttpSession session, String AESEncryptionKey) {
    ICryptoSpi spi = aes();
    session.setAttribute(SESSIONATTR_CRYPTO_KEY, AESEncryptionKey);
    aesConfig(spi, AESEncryptionKey);
    return spi;
  }

  public static ICryptoSpi aesFetchFromSession(HttpSession session) {
    ICryptoSpi spi = aes();
    String AESEncryptionKeyInSession = (String) session.getAttribute(SESSIONATTR_CRYPTO_KEY);
    aesConfig(spi, AESEncryptionKeyInSession);
    return spi;
  }

}
