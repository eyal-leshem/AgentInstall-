


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
		
		
	
	public static void main(String[] argv)  {
		
		MyKeyTool ktTrustStore=null;
		MyKeyTool ktKeyStore=null;
		String cert = null;
		
		try{
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
		  ktTrustStore=new MyKeyTool(new MyKeyToolConf(tsPath,"a10097")); 
		  try {
			ktTrustStore.createNewKs();
		  } catch (MyKeyToolBaseExctpion e){
			throw new AgentInstallException("can't create new keystore at path: "+ tsPath); 
		  }
		  
		  //Generate empty-keystore 
		  ktKeyStore=new MyKeyTool(new MyKeyToolConf(ksPath,"a10097")); 
		  try {
			  ktKeyStore.createNewKs();
		  } catch (MyKeyToolBaseExctpion e){
			throw new AgentInstallException("can't create new keystore at path: "+ ksPath);
		  }
		  
		
		  //add the ca certificate to the new keystore  
		  InputStream caCertStream;
		  try{
			
			caCertStream=new FileInputStream(new File(conf.getServerCaPath()));	  
			ktTrustStore.addTrustCert( caCertStream, "myCa");
			caCertStream.close();
			
		  }
		  catch (Exception e) {
			throw new AgentInstallException("can't add the ca certificate to truststore", e);
		  }
		 
		  try{
			//add the ca certificate to the new keystore  
			caCertStream=new FileInputStream(new File(conf.getServerCaPath()));	  
			ktKeyStore.addTrustCert( caCertStream, "myCa");
			caCertStream.close();
		  }
		  catch (Exception e) {
			  throw new AgentInstallException("can't add the ca certificate to keystorw", e);
		  }
		 
		  
		  //Generate certificate request and write it to string 
		  OutputStream out =new ByteArrayOutputStream(); 	
		  try{
			  ktKeyStore.genartePrivatekey("my key", "cn=a,ou=a,o=a,l=a,s=a,c=a");
		  }
		  catch (MyKeyToolBaseExctpion e) {
			throw new AgentInstallException("prolebm to genarte a privte key with name: my key and dname: cn=a,ou=a,o=a,l=a,s=a,c=a ",e ); 
		  }
	    
		  try{
	    	ktKeyStore.genrateCsr("my key",out);
		  }
		  catch (MyKeyToolBaseExctpion e) {
			throw new AgentInstallException("can't genrate csr from the key: my key", e); 
		  }
	    
		  //make string from the csr 
		  String csr=out.toString(); 
	
		  //register and get certificate sign by the Ca 
		  cert=Register.register(csr,conf);
		 
		}
		catch (AgentInstallException e) {
			installFail(e); 
		}
		

		//install the replay and chek the trust connection can establish 
		try {
			ktKeyStore.installReply("my key", new ByteArrayInputStream(cert.getBytes()));
		} catch (MyKeyToolBaseExctpion e){
			failToImportTheAnswer(e); 
		}
		
		try{
			TrustConnectionChek.connect(conf);
		}
		catch (TrustConnectionCheckException e) {
			failToCreateTrustConnection(e); 
		}
		  
	
		  
		   
		  
		  
		
	}
	
	private static void failToCreateTrustConnection(
			TrustConnectionCheckException e) {
		System.out.println("After successful registration process");
		System.out.println("can't create trust connection with server");
		System.out.println("the problem is: "+ e.getMessage());
		System.out.println("full exception is: "); 
		e.printStackTrace(); 
		System.exit(0);
		
	}

	private static void failToImportTheAnswer(MyKeyToolBaseExctpion e) {
		System.out.println("After successful registration process");
		System.out.println("can't install the server certifcate in the agent");
		System.out.println("the problem is: "+ e.getMessage());
		System.out.println("full exception is: "); 
		e.printStackTrace(); 
		System.exit(0); 
		
	}

	private static void installFail(AgentInstallException e) {
		System.out.println("can't install the agnet");
		System.out.println("the problem is: "+ e.getMessage());
		System.out.println("------------------------------");
		System.out.println("full exception is: "); 
		e.printStackTrace();
		System.exit(0);
		
		
	}

	private static void getConf() throws AgentInstallException{
		try{
			getConf("conf.cnf"); 
		}
		catch (AgentInstallException e) {
			throw new AgentInstallException("can't genarte configutationn from file conf.cnf"); 
		}
		
		
		
	}
	private static void getConf(String path) throws AgentInstallException{
		
		String jsonConfStr;
		
		//read the json string that contain the properties from the file 
		File confFile=new File(path); 
		try{
			FileReader fr=new FileReader(confFile);
			char[] buffer=new  char[(int)confFile.length()];
			fr.read(buffer);
			jsonConfStr=new String(buffer); 
		}
		
		catch (IOException e) {
			throw new AgentInstallException("can't read fron cof file in Path "+ path, e); 
		}
		
		//and use the json conf contractor 
	   	conf= new InstallConf(jsonConfStr);

	   
	   
		
		
	}
	
	


	
	

 
}

 
