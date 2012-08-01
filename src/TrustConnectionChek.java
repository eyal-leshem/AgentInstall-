import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.util.EntityUtils;
import org.xml.sax.InputSource;

import com.sun.xml.internal.messaging.saaj.util.ByteOutputStream;


public class TrustConnectionChek {
	/**
	 * test connecting to the server with client authentcation 
	 * @param conf
	 * @throws TrustConnectionCheckException 
	 * @throws Exception
	 */
    public final static void connect(InstallConf conf) throws TrustConnectionCheckException  {
    	  DefaultHttpClient httpclient = new DefaultHttpClient();
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
					throw new TrustConnectionCheckException("can't load the key store for creating trust connction",e); 
				}
            }
            
            finally {
                try { 
                	instreamKeyStore.close();
                	 instreamTrustStore.close(); 
                } 
                catch (Exception ignore) {}
            }
            
            //for create ssl connection with client authentication                         
            SSLSocketFactory socketFactory;
			try {
				socketFactory = new SSLSocketFactory(keyStore,"a10097",trustStore);
			} catch (Exception e){
				throw new TrustConnectionCheckException("can't create ssl socket factory form ks="+ksPath+ " and truststore= "+tsPath,e); 
			}
            Scheme sch = new Scheme("https", 443, socketFactory);
            httpclient.getConnectionManager().getSchemeRegistry().register(sch);

            //Execute the method 
            HttpGet httpget = new HttpGet(conf.getServerChekTrustConectionPath()+"?name="+conf.getAgentName());         										
            HttpResponse response;
			try {
				response = httpclient.execute(httpget);
			} catch (Exception e){
				throw new TrustConnectionCheckException("can't excute the http method of check"); 
			}
            HttpEntity entity = response.getEntity();
            
            InputStream in=entity.getContent(); 
            byte[] arr=new byte[(int)entity.getContentLength()]; 
            in.read(arr); 
            String ans=new String(arr); 

            System.out.println(ans);
            //check success 
            System.out.println("----------------------------------------");
            if(ans.indexOf("walla")>=0){
            	System.out.println("install complet in sucsses"); 
            }
            else {
            	String res=""; 
            	try{
            		byte[] msgChars=new byte[(int) entity.getContentLength()]; 
            		entity.getContent().read(msgChars); 
            		res=new String(msgChars); 
            	}catch (Exception e) {}
            	
            	
            	throw new TrustConnectionCheckException("unexcpet fail occure while chek mad from server is "+ res); 
            }
        }
    	catch (Exception e) {
    		throw new TrustConnectionCheckException("unexcpet fail occure while trying to establish trust connection"); 
		}
    	finally {
            // When HttpClient instance is no longer needed,
            // shut down the connection manager to ensure
            // immediate deallocation of all system resources
            httpclient.getConnectionManager().shutdown();
        }
    }


}
