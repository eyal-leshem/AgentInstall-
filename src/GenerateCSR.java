


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
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
import sun.security.x509.*;
import sun.security.tools.KeyTool;
import sun.security.pkcs.PKCS10;
import sun.security.pkcs.PKCS10Attribute;
	 
	/**
	 * This class generates PKCS10 certificate signing request
	 *
	 * @author Pankaj@JournalDev.com
	 * @version 1.0
	 */
	public class GenerateCSR {
		
	
	public static void main(String[] argv) throws Exception{

	
/*		  KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC"); 
		  SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
		  keyGen.initialize(1024, random);
		  KeyPair keyPair = keyGen.generateKeyPair();				  		  
		  
		  X500Principal subjectName = new X500Principal("cn=a,ou=US,o=Cafesoft LLC,l=San Diego,s=CA,c=US");

		  PKCS10CertificationRequest kpGen = new PKCS10CertificationRequest(
		                                                        "SHA1withRSA",
		                                                         subjectName,
		                                                        keyPair.getPublic(),
		                                                        null,
		                                                        keyPair.getPrivate());
		 
		  PEMWriter pemWrt = new PEMWriter(new FileWriter("a.csr"));
		  pemWrt.writeObject(kpGen);
		  pemWrt.close();
		   
		  byte[] privatekey= keyPair.getPrivate().getEncoded();
		  byte[] publicKey=keyPair.getPublic().getEncoded(); 
		  
		  File privateKeyFile=new File("a.key"); 
		  if(!privateKeyFile.exists()){
			  privateKeyFile.createNewFile(); 
		  }
		  FileOutputStream fos=new FileOutputStream(privateKeyFile); 
		  
		  fos.write(privatekey); 
		  fos.flush(); 
		  fos.close();
		  
		  File publicKeyFile=new File("a.pub"); 
		  if(!publicKeyFile.exists()){
			  publicKeyFile.createNewFile(); 
		  }
		  fos=new FileOutputStream(publicKeyFile); 
		  
		  fos.write(publicKey); 
		  fos.flush(); 
		  fos.close();
	 
		 // SendCsr.sendCsr(); 
		  
		  
		  KeyStore ks=loadKeyStore(); 
		  CertAndKeyGen keypair =new CertAndKeyGen("RSA", "SHA1withRSA","BC");
		  X500Name x500Name;
		  x500Name = new X500Name("cn=a,ou=US,o=Cafesoft LLC,l=San Diego,s=CA,c=US");
		  keypair.generate(1024);
		  PrivateKey privKey = keypair.getPrivateKey();
		  X509Certificate[] chain = new X509Certificate[1];
		  chain[0] = keypair.getSelfCertificate(x500Name, new Date(), 360*24L*60L*60L);
		  ks.setKeyEntry("my key store", privKey, "a10097".toCharArray(), chain);
		  storeKeyStore(ks); 
		  
		  
		  ks=loadKeyStore();
		  Key key = null;
		  key = ks.getKey("my key store","a10097".toCharArray());
		  char[] password="a10097".toCharArray();
		  Certificate cert = ks.getCertificate("my key store");
		  PKCS10 request = new PKCS10(cert.getPublicKey()); 
		  Signature signature = Signature.getInstance("SHA1withRSA");
		  signature.initSign(privKey);
		  X500Name subject= new X500Name(((X509Certificate)cert).getSubjectDN().toString()); 
		  
		  
		  request.encodeAndSign(new X500Signer(signature,subject)); 
          request.print(System.out);*/
		
		
		
		  File keyStroeFile=new File("my.keystore"); 
		  if(keyStroeFile.exists()) 
			  keyStroeFile.delete(); 
		
		  InputStream caCertStream=new FileInputStream(new File("cafesoftCa.crt"));
		  InputStream serverCertStream=new FileInputStream(new File("linus.cafenet.com.crt"));
		  
	      OutputStream out =new FileOutputStream(new File("a.csr")); 
		  MyKeyTool kt=new MyKeyTool("my.keyStore","a10097"); 
		  kt.createNewKs();
		  kt.AddTrustCert( caCertStream, "myCa");
		  kt.AddTrustCert( serverCertStream, "my server");
		  kt.genartePrivatekey("my key", "cn=a,ou=a,o=a,l=a,s=a,c=a");
		  kt.genrateCsr("my key",out);
	 
		  SendCsr.sendCsr("agent1"); 

		  kt.installReply("my key", new FileInputStream("a.crt"));
		  TrustConnection.connect(); 
		  
		  
		  
		  
		  
		  
		  
		
	}
	
	private static KeyStore loadKeyStore() throws KeyStoreException, FileNotFoundException {
		KeyStore keyStore  = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream  instream = new FileInputStream(new File("my.keystore"));
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
           return keyStore; 
	}
	
	private static void storeKeyStore(KeyStore ks) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		OutputStream os=new FileOutputStream("my.keystore"); 
		ks.store(os, "a10097".toCharArray());	
	}
	
	


	 
	 
}

 
