# jCryptoServ
An OpenSSL RSA/AES Encryption/Decryption Library of perfect interaction between Java and Javascript.
-------------------------- 
#### 依赖(Dependency)：
* 1、JQuery
* 2、CryptoJS v3.1.2  rollups/aes.js、rollups/pbkdf2.js
* 3、JSEncrypt v2.3.1
-------------------------- 
#### 用法(Usage)：
* 1、web.xml中引入CryptoServlet，如：

    	<servlet>
    		<servlet-name>CryptoServlet</servlet-name>
    		<servlet-class>io.flysium.security.web.CryptoServlet</servlet-class>
    	</servlet>
    	<servlet-mapping>
    		<servlet-name>CryptoServlet</servlet-name>
    		<url-pattern>/crypto</url-pattern>
    	</servlet-mapping>


* 2、ajax调用后台：
    
      var context_path;
      var params;
      /// todo.....
    
    	try{
    		params = typeof(params) !== "string" ? JSON.stringify(params) : params;
    	}
    	catch(e){}
    	
    	if ( jCryptoServ && jCryptoServ.authenticateOnway ) {
          jCryptoServ.authenticateOnway(function(AESEncryptionKey) {
            
            var encryptedParamString = jCryptoServ.encrypt(params, AESEncryptionKey);
            /// todo.....
    			
          }, function() {
              // Authentication with AES Failed ... sending form without protection
              confirm("Authentication with Server failed, are you sure you want to submit it unencrypted?", function() {
                /// todo.....
              });
          }, {
            keyPreRequestEnabled: false,
            getKeysURL : context_path + "/crypto?generateKeyPair=true",
            handshakeURL : context_path + "/crypto?handshakes=true"
          });
    	} else {
    		/// todo.....
    	}
    
#### 联系(Contract)
* Email: SvenAugustus@outlook.com
* GitHub: https://github.com/SvenAugustus
* 开源中国: http://my.oschina.net/langxSpirit
* 开源码云: https://git.oschina.net/svenaugustus
