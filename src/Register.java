


import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.protocol.HTTP;
import org.apache.http.util.EntityUtils;

import sun.misc.BASE64Encoder;


public class Register{

	/**
	 * ask the server to register a new agent - and get the certificate from the server
	 * to create trust connection 
	 * 
	 * @param newCsr - a certificate request
	 * @param conf - configuration for install 
	 * @return in fail null , in success the certificate in from server in string 
	 * @throws Exception
	 */
	public static String register(String newCsr,InstallConf conf) throws Exception {
		

		//use apache httpclient to contact the server
        DefaultHttpClient httpclient = new DefaultHttpClient();
        HttpPost postRequest = new HttpPost(conf.getServerRegAgentPath()); 
        Scheme sch=getScheme(conf);
        httpclient.getConnectionManager().getSchemeRegistry().register(sch);
              
    	//build the content of the request 
    	List <NameValuePair> nvps = new ArrayList <NameValuePair>();
    	  nvps.add(new BasicNameValuePair("csr", newCsr));
          nvps.add(new BasicNameValuePair("name", conf.getAgentName()));
          nvps.add(new BasicNameValuePair("implementors", getImplmentors(conf)));
          nvps.add(new BasicNameValuePair("instName" ,conf.getInstName()));
          nvps.add(new BasicNameValuePair("instPassword" ,conf.getInstPassword()));
          
          

        //add the content to the request 
        postRequest.setEntity(new UrlEncodedFormEntity(nvps, HTTP.UTF_8));     	
    	
        //Execute it 
    	String postStr=postRequest.getMethod(); 
        HttpResponse response = httpclient.execute(postRequest);
    	
        String cert;
        //read the reponse 
        try{
        	cert=readCert(response);   	 	            
        }
        catch (Exception e) {
        	return null; 
		} 
    	//close connection 
     	httpclient.getConnectionManager().shutdown();
 		
		return cert;

	}
	
	/**
	 *  get the scheme for creating the ssl connection 
	 * @param conf
	 * @return
	 * @throws Exception
	 */
	private static Scheme getScheme(InstallConf conf) throws Exception {
	  	try {
    		//get the path of the keystore 
	  		String ksPath=conf.getKsPath();
	  		String tsPath=conf.getTrustStorePath(); 
	  		
    		//load the key store and the truststure 
            KeyStore trustStore  = KeyStore.getInstance(KeyStore.getDefaultType());
            KeyStore keyStore  = 	KeyStore.getInstance(KeyStore.getDefaultType());
           
            FileInputStream instreamKeyStore = new FileInputStream(new File(ksPath));
            FileInputStream instreamTrustStore = new FileInputStream(new File(tsPath));
            
            try {													  
                try {
					trustStore.load(instreamTrustStore, "a10097".toCharArray());
					keyStore.load(instreamKeyStore,"a10097".toCharArray()); 
					} 
                catch (Exception e){
					throw new Exception("can't load the key store",e); 
				}
            } finally {
                try { instreamKeyStore.close();
                	  instreamTrustStore.close(); 
                } 
                catch (Exception ignore) {
                	return null;  
                }
            }
            //get the socket factory 
            SSLSocketFactory socketFactory = new SSLSocketFactory(keyStore,"a10097",trustStore);
            Scheme sch = new Scheme("https", 443, socketFactory);
            return sch; 
	  	}
        catch (Exception e) {
			throw new Exception("problem to load the keystores",e);
		}                
	}

	/**
	 * get the certificate from the response of the server 
	 * @param response
	 * @return
	 * @throws Exception
	 */
	private static String readCert(HttpResponse response) throws Exception {
            
			//Extract the output as string from response 
			HttpEntity entity = response.getEntity();
            ByteArrayOutputStream baos=new ByteArrayOutputStream();
            entity.writeTo(baos);
            byte[] arr=baos.toByteArray();
            String output = new String(arr);
          
            //Extract the  certificate from the response 
            int i=output.indexOf("-----");
            int j=output.indexOf("END CERTIFICATE-----");
            
            //error handling - (if the register fail the server will not return certificate
            if(j==-1){
            	System.out.println("----------------------");
            	if( output.contains("agent name is not free"))
            		System.out.println("agent name is not free - can't register");
            	
            	else {
            		if(output.contains("name or password incorrect")) 
            	            System.out.println("name or password incorrect -can't register");
            		else 
            			System.out.println("unexpeted problem can't register this agent"); 
            	}
            	
            	throw new Exception(); 
            }
           
            
            String certStr=output.substring(i,j+"END CERTIFICATE-----".length());
                                
        	EntityUtils.consume(entity); 
        	
        	//return the certificate 
        	return certStr; 
            
	}

	/**
	 * get the implementors of this agent 
	 * @param conf - configuration for install 
	 * @return the string of the implementors (imp1,imp2 ... )  
	 */
	private static String getImplmentors(InstallConf conf) {
		String propStr;
		try {
			//load the properties string from the encrypted file 
			propStr=getPropStr(conf);
		} catch (Exception e){
			return ""; 
		}
		int nextProp=propStr.indexOf("----")+"----".length(); 
		StringBuilder stringBuilder=new StringBuilder(); 
	
		//get all the properties to string that build like that 
		//prop1,prop2,prop3 .. 
		while(nextProp>4){
			String next=propStr.substring(nextProp);
			String toAdd=next.substring(0,next.indexOf("\n")); 
			stringBuilder.append(toAdd);
			propStr=next;
			nextProp=propStr.indexOf("----")+"----".length();
			//the last implemtor
			if(nextProp>5){
				stringBuilder.append(','); 
			}
		}					
		
		return stringBuilder.toString(); 
	}
	
	/**
	 * encrypte the prop file to get the agent names
	 * @param conf
	 * @return
	 * @throws Exception
	 */
	private static String getPropStr(InstallConf conf) 
			throws Exception {
		
		//get the path of the file 
		String filePath=conf.getAgentSerivcePath()+conf.getSlesh()+"plugins"+conf.getSlesh()+"CA.ico"; 
		
		//read the bytes of key file
		File keyFile=new File(filePath); 
		byte[] keyBytes=new byte[(int)keyFile.length()]; 
		FileInputStream in=new FileInputStream(keyFile); 
		in.read(keyBytes); 
		in.close(); 
		
		//generate the seceret key 
		SecretKeySpec keySpec=new SecretKeySpec(keyBytes,"AES"); 
		
		
		//generate the cipher 
		 Cipher c = Cipher.getInstance("AES");
		 c.init(Cipher.DECRYPT_MODE, keySpec);
		 
		 //read the bytes from the file 
		 File file=new File(conf.getAgentSerivcePath()+conf.getSlesh()+"prop"); 
		 byte[] arr=new byte[(int)file.length()];
		 FileInputStream fr=new FileInputStream(file); 
		 fr.read(arr); 
		 
		 //get the encrypted data 
		 byte[] encData=c.doFinal(arr);
		 String ans=new String(encData); 
		 return ans;
		    
	}
	
	/**
	 * bulid the message body with the name and the password 
	 * @param name
	 * @param password
	 * @param csr
	 * @param agentName
	 * @return
	 */
	private static String buildMassegeBody(String name, String password,String csr,String agentName) {
		
		StringBuilder str=new StringBuilder();
		
		str.append("{");
		str.append("\"name\":\""+name+"\","); 
		str.append("\"password\":\""+password+"\"");
		str.append("}");
		
		String  jasonBody=str.toString(); 
		return jasonBody; 
	}

}
