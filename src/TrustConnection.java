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
import org.apache.http.util.EntityUtils;


public class TrustConnection {
	
    public final static void connect() throws Exception {
    	  DefaultHttpClient httpclient = new DefaultHttpClient();
    	try {
    		
              KeyStore trustStore  = KeyStore.getInstance(KeyStore.getDefaultType());
              FileInputStream instream = new FileInputStream(new File("my.keystore"));
              try {													  
                  try {
  					trustStore.load(instream, "a10097".toCharArray());
  				} catch (NoSuchAlgorithmException e) {
  					// TODO Auto-generated catch block
  					e.printStackTrace();
  				} catch (CertificateException e) {
  					// TODO Auto-generated catch block
  					e.printStackTrace();
  				} catch (IOException e) {
  					// TODO Auto-generated catch block
  					e.printStackTrace();
  				}
              } finally {
                  try { instream.close(); } catch (Exception ignore) {}
              }
              
              
              KeyStore keyStore  = KeyStore.getInstance(KeyStore.getDefaultType());
              instream = new FileInputStream(new File("my.keystore"));
              try {
                  try {
  					keyStore.load(instream, "a10097".toCharArray());
  				} catch (NoSuchAlgorithmException e) {
  					// TODO Auto-generated catch block
  					e.printStackTrace();
  				} catch (CertificateException e) {
  					// TODO Auto-generated catch block
  					e.printStackTrace();
  				} catch (IOException e) {
  					// TODO Auto-generated catch block
  					e.printStackTrace();
  				}
              } finally {
                  try { instream.close(); } catch (Exception ignore) {}
              }
              
            
              
            SSLSocketFactory socketFactory = new SSLSocketFactory(keyStore,"a10097",trustStore);
            Scheme sch = new Scheme("https", 443, socketFactory);
            httpclient.getConnectionManager().getSchemeRegistry().register(sch);

            HttpGet httpget = new HttpGet("https://localhost/OK/a.php");
            												

            System.out.println("executing request" + httpget.getRequestLine());

            HttpResponse response = httpclient.execute(httpget);
            HttpEntity entity = response.getEntity();

            System.out.println("----------------------------------------");
            System.out.println(response.getStatusLine());
            if (entity != null) {
                System.out.println("Response content length: " + entity.getContentLength());
            }
            EntityUtils.consume(entity);

        } finally {
            // When HttpClient instance is no longer needed,
            // shut down the connection manager to ensure
            // immediate deallocation of all system resources
            httpclient.getConnectionManager().shutdown();
        }
    }


}
