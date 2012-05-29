import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.util.EntityUtils;


public class TrustConnectionChek {
	/**
	 * test connecting to the server with client authentcation 
	 * @param conf
	 * @throws Exception
	 */
    public final static void connect(InstallConf conf) throws Exception {
    	  DefaultHttpClient httpclient = new DefaultHttpClient();
    	try {
      		//get the path of the keystore 
	  		String ksPath=conf.getKsPath(); 
	  		
    		//load the key store and the truststure 
            KeyStore trustStore  = KeyStore.getInstance(KeyStore.getDefaultType());
            KeyStore keyStore  = 	KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream instream = new FileInputStream(new File(ksPath));
            FileInputStream instream2 = new FileInputStream(new File(ksPath));
            try {													  
                try {
					trustStore.load(instream, "a10097".toCharArray());
					keyStore.load(instream2,"a10097".toCharArray()); 
					} 
                catch (Exception e){
					throw new Exception("can't load the key store",e); 
				}
            } finally {
                try { instream.close();
                	  instream2.close(); 
                } 
                catch (Exception ignore) {
                	
                }
            }
            //for create ssl connection with client authentication                         
            SSLSocketFactory socketFactory = new SSLSocketFactory(keyStore,"a10097",trustStore);
            Scheme sch = new Scheme("https", 443, socketFactory);
            httpclient.getConnectionManager().getSchemeRegistry().register(sch);

            //Execute the method 
            HttpGet httpget = new HttpGet(conf.getServerChekTrustConectionPath());         										
            HttpResponse response = httpclient.execute(httpget);
            HttpEntity entity = response.getEntity();

            //check success 
            System.out.println("----------------------------------------");
            if(entity.getContentLength()==5){
            	System.out.println("install complet in sucsses"); 
            }
            else {
        		System.out.println("register- but cann't establish trust  "); 
            	System.out.println(" some un expected  error occurred") ; 
                System.out.println("chek details with the system admin");                
            }

        } finally {
            // When HttpClient instance is no longer needed,
            // shut down the connection manager to ensure
            // immediate deallocation of all system resources
            httpclient.getConnectionManager().shutdown();
        }
    }


}
