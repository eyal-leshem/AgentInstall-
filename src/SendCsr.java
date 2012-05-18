


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
import java.security.KeyFactory;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.EncryptedPrivateKeyInfo;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;


public class SendCsr {

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void sendCsr(String agentName) throws Exception {
		//walla
        DefaultHttpClient httpclient = new DefaultHttpClient();

        HttpPost postRequest = new HttpPost("http://localhost/CA/a.php?XDEBUG_SESSION_START=ECLIPSE_DBGP&KEY=13372502389631"); 
     //   Runtime.getRuntime().exec("cmd /c start a.bat");
     //  	Thread.sleep(3000);//while the batch run   
        String newCsr; 
        FileReader fr=new FileReader(new File("a.csr"));
        char[]  charArr=new char[2000]; 		
        int end=fr.read(charArr); 
        fr.close(); 
        newCsr=new String(charArr); 
          
       newCsr=newCsr.substring(0, end);

        StringEntity input = new StringEntity(buildMassegeBody("yosi","a10097",newCsr,agentName));
    	input.setContentType("application/json");
    	postRequest.setEntity(input);
    	  	
    	String postStr=postRequest.getMethod(); 
     
    	HttpResponse response = httpclient.execute(postRequest);
    		
    	readCert(response);       
    	
    	//updatekeyStore(); 
    	
    	//TrustConnection.connect(); 
            
    
    	
 		//httpclient.getConnectionManager().shutdown();

	}
	
		
	










	private static void readCert(HttpResponse response) throws Exception {
            HttpEntity entity = response.getEntity();
          
            ByteArrayOutputStream baos=new ByteArrayOutputStream();
            
            entity.writeTo(baos);
            
            byte[] arr=baos.toByteArray();
            
            String output = new String(arr);
          
            int i=output.indexOf("-----");
            int j=output.indexOf("END CERTIFICATE-----");
            
            String certStr=output.substring(i,j+"END CERTIFICATE-----".length());
           
            File f=new File("a.crt"); 
            if(!f.exists()){
            	f.createNewFile(); 
            }
            FileWriter fw=new FileWriter(f);
            fw.write(certStr); 
            fw.flush(); 
            fw.close(); 
            
        	EntityUtils.consume(entity);   
            
	}


	private static String buildMassegeBody(String name, String password,
			String csr,String agentName) {
		StringBuilder str=new StringBuilder(); 
		String imp=getImplmentors(); 
		
		
		csr=csr.replace('\n', '#');
		csr=csr.replace('\r', '*');
		
		str.append("{");
		str.append("\"name\":\""+name+"\","); 
		str.append("\"password\":\""+password+"\",");
		str.append("\"implementors\":\""+imp+"\",");
		str.append("\"agentName\":\""+agentName+"\","); 
		str.append("\"csr\":\""+csr+"\"");
		str.append("}");
		String  jasonBody=str.toString(); 
		
		return jasonBody; 
	}













	private static String getImplmentors() {
		try{
			File file=new File("imp");
			FileReader fr=new FileReader(file);
		    long len=file.length();
		    char[] charArrImp=new char[(int) len];
			fr.read(charArrImp);
			return new String(charArrImp);
		}
		catch (Exception e) {
			return ""; 
		}
	}

}
