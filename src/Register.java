


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
import java.io.UnsupportedEncodingException;
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
	public static String register(String newCsr,InstallConf conf) throws AgentInstallException {
		

		//use apache httpclient to contact the server
        DefaultHttpClient httpclient = new DefaultHttpClient();
        HttpPost postRequest = new HttpPost(conf.getServerRegAgentPath()); 
        Scheme sch;
		try {
			sch = getScheme(conf);
		} catch (AgentInstallException e) {
			throw new AgentInstallException("can't get the ssl scheme", e); 
		}
        httpclient.getConnectionManager().getSchemeRegistry().register(sch);
              
    	//build the content of the request 
    	List <NameValuePair> nvps = new ArrayList <NameValuePair>();
    	  nvps.add(new BasicNameValuePair("csr", newCsr));
          nvps.add(new BasicNameValuePair("name", conf.getAgentName()));
          nvps.add(new BasicNameValuePair("implementors", getImplmentors(conf)));
          nvps.add(new BasicNameValuePair("instName" ,conf.getInstName()));
          nvps.add(new BasicNameValuePair("instPassword" ,conf.getInstPassword()));
          
          

        //add the content to the request 
        try {
			postRequest.setEntity(new UrlEncodedFormEntity(nvps, HTTP.UTF_8));
		} catch (UnsupportedEncodingException e) {
			throw new AgentInstallException("can't add the content to request", e); 
		}     	
    	
        //Execute it 
    	String postStr=postRequest.getMethod(); 
        HttpResponse response;
		try {
			response = httpclient.execute(postRequest);
		} catch (Exception e){
			throw new AgentInstallException("problem occured while excuting post method", e);  
		}
    	
        String cert;
        //read the reponse 
        try{
        	cert=readCert(response);   	 	            
        }
        catch (Exception e) {
        	throw new AgentInstallException("can't get certificate form server response", e);  
		} 
    	//close connection 
     	httpclient.getConnectionManager().shutdown();
 		
		return cert;

	}
	
	/**
	 *  get the scheme for creating the ssl connection 
	 * @param conf
	 * @return
	 * @throws AgentInstallException 
	 * @throws Exception
	 */
	private static Scheme getScheme(InstallConf conf) throws AgentInstallException {
		
		 	KeyStore trustStore ;
		 	KeyStore keyStore ;
	  	
    		//get the path of the keystore 
	  		String ksPath=conf.getKsPath();
	  		String tsPath=conf.getTrustStorePath(); 
	  		
	  		
    		
	  		//load the key store and the trust store
	  		String keyStoreType=KeyStore.getDefaultType();
	  		try{
	            trustStore  = KeyStore.getInstance(keyStoreType);
	            keyStore  =  KeyStore.getInstance(keyStoreType);
	  		}
	  		catch (KeyStoreException e) {
				throw new AgentInstallException("can't create instance of key store type " + keyStoreType , e); 
			}
           
	  		//load key store file
            FileInputStream instreamKeyStore;
			try {
				instreamKeyStore = new FileInputStream(new File(ksPath));
			} catch (FileNotFoundException e) {
				throw new AgentInstallException("can't open file  "+ ksPath + "for keystore" , e);
			}
			
			//load trust store file 
            FileInputStream instreamTrustStore;
			try {
				instreamTrustStore = new FileInputStream(new File(tsPath));
			} catch (FileNotFoundException e) {
				throw new AgentInstallException("can't open file  "+ tsPath + "for truststore" , e);
			}
            
            try {													  
                try {
					trustStore.load(instreamTrustStore, "a10097".toCharArray());
					keyStore.load(instreamKeyStore,"a10097".toCharArray()); 
					} 
                catch (Exception e){
					throw new AgentInstallException("can't load the key store",e); 
				}
            } finally {
                try { instreamKeyStore.close();
                	  instreamTrustStore.close(); 
                } 
                catch (Exception ignore) {              	     }
            }
            //get the socket factory 
            SSLSocketFactory socketFactory;
			try {
				socketFactory = new SSLSocketFactory(keyStore,"a10097",trustStore);
			} catch (Exception e){
				throw new AgentInstallException("can't create ssl socket factory" , e);
			}
            Scheme sch = new Scheme("https", 443, socketFactory);
            return sch; 
	  	
                     
	}

	/**
	 * get the certificate from the response of the server 
	 * @param response
	 * @return
	 * @throws Exception
	 */
	private static String readCert(HttpResponse response) throws AgentInstallException  {
            
			//Extract the output as string from response 
			HttpEntity entity = response.getEntity();
            ByteArrayOutputStream baos=new ByteArrayOutputStream();
            
            try {
				entity.writeTo(baos);
			} catch (IOException e) {
				throw new AgentInstallException("can't write entity to byte output stream", e);
			}
            
            
            byte[] arr=baos.toByteArray();
            String output = new String(arr);
          
            //Extract the  certificate from the response 
            int i=output.indexOf("-----");
            int j=output.indexOf("END CERTIFICATE-----");
            
            //error handling - (if the register fail the server will not return certificate
            if(j==-1){
            	
            	if( output.contains("agent name is not free"))
            		throw new AgentInstallException("agent name  is not free - can't register");
            	
            	else {
            		if(output.contains("name or password incorrect")) 
            			throw new AgentInstallException("name or password incorrect -can't register");
            		else 
            			throw new AgentInstallException("unexpeted problem can't register this agent"); 
            	}  
            }
           
            
            String certStr=output.substring(i,j+"END CERTIFICATE-----".length());
                                
        	try {
				EntityUtils.consume(entity);
			} catch (IOException e) {/*not really problem because the process will terminate in 1 minute or lee*/ } 
        	
        	//return the certificate 
        	return certStr; 
            
	}

	/**
	 * get the implementors of this agent 
	 * @param conf - configuration for install 
	 * @return the string of the implementors (imp1,imp2 ... )  
	 */
	private static String getImplmentors(InstallConf conf)  {
		String propStr;
		try {
			//load the properties string from the encrypted file 
			propStr=getPropStr(conf);
		} 
		catch (AgentInstallException e){
			System.out.println("can't load the propethis file");
			
			//print all exception messages in the tree 
			Throwable e1=e; 
			while(e1!=null){
				System.out.println(e.getMessage());
				e1=e1.getCause(); 
			}
				
			System.out.println("return an emprty implemnor string");
			return ""; 
		}//end of catch 
		
		//the next instance of properties block start with ----
		//(Properties block structure ("----Implementor name \n jsonPropertiesString") )
		int nextProp=propStr.indexOf("----")+"----".length(); 
		StringBuilder stringBuilder=new StringBuilder(); 
	
		//get all the properties to string that build like that 
		//prop1,prop2,prop3 .. 
		while(nextProp>=4){
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
	private static String getPropStr(InstallConf conf) throws AgentInstallException {
		
		//get the path of the file 
		String filePath=conf.getAgentSerivcePath()+conf.getSlesh()+"plugins"+conf.getSlesh()+"CA.ico"; 
		
		//read the bytes of key file
		File keyFile=new File(filePath); 
		byte[] keyBytes=new byte[(int)keyFile.length()]; 
		
		//load key file 
		FileInputStream in;
		try {
			in = new FileInputStream(keyFile);
		} catch (FileNotFoundException e) {
			throw new AgentInstallException("problem while load keyfile "+ filePath, e); 
		} 
		
		try {
			in.read(keyBytes);
		} catch (IOException e) {
			throw new AgentInstallException("problem to read from key file "+ filePath, e); 
		} 
		
		try {in.close(); } catch (IOException e) {} 
		
		//generate the seceret key 
		SecretKeySpec keySpec=new SecretKeySpec(keyBytes,"AES"); 
		
		
		//generate the cipher 
		 Cipher c;
		try {
			c = Cipher.getInstance("AES");
		} catch (Exception e) {
			throw new AgentInstallException("can't genrate AES chiper" ,e); 
		}
		
		//init the cipher 
		 try {
			c.init(Cipher.DECRYPT_MODE, keySpec);
		} catch (InvalidKeyException e) {
			throw new AgentInstallException("can't init the cipher with the key" ,e); 
		}
		 
		 //read the bytes from the file 
		 File file=new File(conf.getAgentSerivcePath()+conf.getSlesh()+"prop"); 
		 byte[] arr=new byte[(int)file.length()];
		
		//load the propeties file
		FileInputStream fr;
		try {
			fr = new FileInputStream(file);
		} catch (FileNotFoundException e) {
			throw new AgentInstallException("can't lod the propeties file " ,e); 
		} 
		
		//read the encrypted bytes 
		 try {
			fr.read(arr);
		} catch (IOException e) {
			throw new AgentInstallException("can't read from the encrypted propeties file " ,e); 
		} 
		 
		 //get the encrypted data 
		 byte[] encData;
		try {
			encData = c.doFinal(arr);
		} catch (Exception e){
			throw new AgentInstallException("can't encrypte the data " ,e); 
		}
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
