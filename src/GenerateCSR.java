


import java.io.ByteArrayInputStream;
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
import java.io.OutputStreamWriter;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Vector;


import javax.security.auth.x500.X500Principal;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.jce.*;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.pkcs.*;
import org.bouncycastle.openssl.*;
import org.json.JSONException;
import org.json.JSONObject;

import sun.security.x509.*;
import sun.security.tools.KeyTool;
import sun.security.pkcs.PKCS10;
import sun.security.pkcs.PKCS10Attribute;


import MykeyTool.*;
	 
	/**
	 * This class generates PKCS10 certificate signing request
	 *
	 * @author Pankaj@JournalDev.com
	 * @version 1.0
	 */
	public class GenerateCSR {
		
		static InstallConf conf; 
		
		
	
	public static void main(String[] argv) throws Exception{
		
		  getConf(); 
		
		  String ksPath=conf.getKsPath();
		  String tsPath=conf.getTrustStorePath(); 
		   
		
		  //make an empty truststore  
		  File trustStoreFile=new File(tsPath); 
		  if(trustStoreFile.exists()) 
			  trustStoreFile.delete(); 
		  
		  //make an empty keystore
		  File keyStoreFile=new File(ksPath); 
		  if(keyStoreFile.exists()) 
			  keyStoreFile.delete(); 
		  
		  //Generate empty-truststroe 
		  MyKeyTool ktTrustStore=new MyKeyTool(new MyKeyToolConf(tsPath,"a10097")); 
		  ktTrustStore.createNewKs();
		  
		  //Generate empty-keystore 
		  MyKeyTool ktKeyStore=new MyKeyTool(new MyKeyToolConf(ksPath,"a10097")); 
		  ktKeyStore.createNewKs();
		  
		  
		
		  //add the ca certificate to the new keystore  
		  try{
			  InputStream caCertStream=new FileInputStream(new File(conf.getServerCaPath()));	  
			  ktTrustStore.addTrustCert( caCertStream, "myCa");
			  caCertStream.close(); 
		  }catch (Exception e) {
			throw new Exception("can't add the certificate of the ca of the server", e); 
		  }
		  
		  //add the ca certificate to the new keystore  
		  try{
			  InputStream caCertStream=new FileInputStream(new File(conf.getServerCaPath()));	  
			  ktKeyStore.addTrustCert( caCertStream, "myCa");
			  caCertStream.close(); 
		  }catch (Exception e) {
			throw new Exception("can't add the certificate of the ca of the server", e); 
		  }
		  
		  //Generate certificate request and write it to string 
	      OutputStream out =new ByteArrayOutputStream(); 	  
		  ktKeyStore.genartePrivatekey("my key", "cn=a,ou=a,o=a,l=a,s=a,c=a");
		  ktKeyStore.genrateCsr("my key",out);
		  String csr=out.toString(); 
	
		  //register and get certificate sign by the Ca 
		  String cert=Register.register(csr,conf); 
		  if(cert==null){
			  return; 
		  }

		  //install the replay and chek the trust connection can establish 
		  ktKeyStore.installReply("my key", new ByteArrayInputStream(cert.getBytes()));
		  TrustConnectionChek.connect(conf);
		  
	
		  
		   
		  
		  
		
	}
	
	private static void getConf() throws Exception{
		try{
			getConf("conf.cnf"); 
		}
		catch (FileNotFoundException e) {
			throw new Exception("conf file conf.cnf don't exsit"); 
		}
		
		
		
	}
	private static void getConf(String path) throws IOException{
		
		//read the json string that contain the properties from the file 
		File confFile=new File(path); 
		FileReader fr=new FileReader(confFile);
		char[] buffer=new  char[(int)confFile.length()];
		fr.read(buffer);
		String jsonConfStr=new String(buffer); 
		
		//and use the json conf contractor 
	   conf= new InstallConf(jsonConfStr);  
	   
	   
		
		
	}
	
	


	
	

 
}

 
