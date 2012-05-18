import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.Vector;

import javax.security.auth.x500.X500Principal;

import sun.security.pkcs.PKCS10;
import org.bouncycastle.x509.*;
import org.bouncycastle.asn1.x509.*; 
import org.bouncycastle.x509.extension.*;

import sun.security.x509.*;
import sun.security.tools.KeyTool;

public class MyKeyTool {
	String ksPath; 
	String ksPassword; 
	String keyStoreType=new String("jks"); 
	String sigAlg=new String("SHA1withRSA"); 
	String keyPairAlg=new String("RSA");
	String provider=new String("BC"); 
	
	public MyKeyTool(String ksPath,String ksPaswword) {
		this.ksPath=ksPath;
		this.ksPassword=ksPaswword;
		
	}
	
	public MyKeyTool(String ksPath,String ksPaswword,String keyStoreType){
	  this(ksPath,ksPaswword); 
	  this.keyStoreType=keyStoreType;
	  
	}
	
	public MyKeyTool(String ksPath,String ksPaswword,String keyStoreType,String sigAlg,String keyPairAlg){
		  this(ksPath,ksPaswword,keyStoreType); 
		  this.sigAlg=sigAlg; 
		  this.keyPairAlg=keyPairAlg; 		  
	 }
	
	public MyKeyTool(String ksPath,String ksPaswword,String keyStoreType,String sigAlg,String keyPairAlg,String provider){
		this(ksPath,ksPaswword,keyStoreType,sigAlg,keyPairAlg);
		this.provider=provider;
	}
	
	
	

	public  void AddTrustCert(InputStream certStream,String alias) 
				throws Exception{
		
			
		KeyStore ks=loadKeyStore(ksPath,ksPassword);
		CertificateFactory cf =CertificateFactory.getInstance("X.509");
		Certificate cert= cf.generateCertificate(certStream);
		ks.setCertificateEntry(alias, cert);
		storeKeyStore(ks); 
		
		
	}
	
	public void createNewKs() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		  KeyStore ks = KeyStore.getInstance("jks");
		  ks.load(null, ksPassword.toCharArray());
		  storeKeyStore(ks); 
	 }
	
	
	public boolean installReply(String alias, InputStream in) 
			 throws Exception{
		
		 KeyStore ks=loadKeyStore(ksPath, ksPassword);
		 PrivateKey privKey = (PrivateKey)ks.getKey(alias, ksPassword.toCharArray());
		 Certificate userCert = ks.getCertificate(alias);
		 CertificateFactory cf =CertificateFactory.getInstance("X.509");
		 Collection<? extends Certificate> c = cf.generateCertificates(in);
         Certificate[] replyCerts = c.toArray(new Certificate[c.size()]);
         Certificate[] newChain;
         newChain= establishCertChain(userCert, replyCerts[0],ks);
         if (newChain != null) {
             ks.setKeyEntry(alias, privKey,ksPassword.toCharArray(),newChain); 
             storeKeyStore(ks); 
             in.close();
             return true;
         } else {
        	 in.close(); 
             return false;
         }
		 
	
	 }
	
	private Certificate[] establishCertChain(Certificate userCert,Certificate certToVerify,KeyStore ks) throws Exception {
	    PublicKey origPubKey = userCert.getPublicKey();
        PublicKey replyPubKey = certToVerify.getPublicKey();
        if (!origPubKey.equals(replyPubKey)) {
            throw new Exception("Public.keys.in.reply.and.keystore.don.t.match");
        }
      
        if (certToVerify.equals(userCert)) {
            throw new Exception("Certificate.reply.and.certificate.in.keystore.are.identical");
        }
        Hashtable<Principal, Vector<Certificate>> certs = null;
        certs = new Hashtable<Principal, Vector<Certificate>>(11);
        keystorecerts2Hashtable(ks, certs);
        Vector<Certificate> chain = new Vector<Certificate>(2);
        if (buildChain((X509Certificate)certToVerify, chain, certs)) {
            Certificate[] newChain = new Certificate[chain.size()];
            // buildChain() returns chain with self-signed root-cert first and
            // user-cert last, so we need to invert the chain before we store
            // it
            int j=0;
            for (int i=chain.size()-1; i>=0; i--) {
                newChain[j] = chain.elementAt(i);
                j++;
            }
            return newChain;
        } else {
            throw new Exception("Failed.to.establish.chain.from.reply");
        }        
     
        
	
		
	}

	public void   genrateCsr(String alias,OutputStream out) 
			throws SignatureException, IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException,
			InvalidKeyException, CertificateException, NoSuchProviderException{
		  KeyStore ks=loadKeyStore(ksPath,ksPassword);
		  Key key = null;
		  key = ks.getKey(alias,ksPassword.toCharArray());
		  Certificate cert = ks.getCertificate(alias);
		  PKCS10 request = new PKCS10(cert.getPublicKey()); 
		  Signature signature = Signature.getInstance(sigAlg,provider);
		  signature.initSign((PrivateKey) key);
		  X500Name subject= new X500Name(((X509Certificate)cert).getSubjectDN().toString()); 		   
		  request.encodeAndSign(new X500Signer(signature,subject)); 
          request.print(new PrintStream(out));
	}

	public  void genartePrivatekey(String alias,String dName) 
			throws 	KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException,
					CertificateException, SignatureException, UnrecoverableKeyException{
		  KeyStore ks=loadKeyStore(ksPath,ksPassword); 
		  CertAndKeyGen keypair =new CertAndKeyGen(keyPairAlg, sigAlg,provider);
		  X500Name x500Name;
		  x500Name = new X500Name(dName);
		  keypair.generate(1024);
		  PrivateKey privKey = keypair.getPrivateKey();
		  X509Certificate[] chain = new X509Certificate[1];
		  chain[0] = keypair.getSelfCertificate(x500Name, new Date(), 360*24L*60L*60L);
		  ks.setKeyEntry(alias, privKey, ksPassword.toCharArray(), chain);
		  doSelfCert(alias, dName, ks, ksPassword, new KeyPair(keypair.getPublicKey(), keypair.getPrivateKey())); 
		  storeKeyStore(ks); 
		  
	}
		
    private boolean isSelfSigned(X509Certificate cert) {
        return signedBy(cert, cert);
    }

    private boolean signedBy(X509Certificate end, X509Certificate ca) {
        if (!ca.getSubjectDN().equals(end.getIssuerDN())) {
            return false;
        }
        try {
            end.verify(ca.getPublicKey());
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
	private static KeyStore loadKeyStore(String path,String password) throws KeyStoreException, FileNotFoundException {
		KeyStore keyStore  = KeyStore.getInstance(KeyStore.getDefaultType());
        InputStream  instream = new FileInputStream(new File(path));
           try {
               try {
					keyStore.load(instream, password.toCharArray());
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
               try { instream.close(); } catch (Exception ignore) {  }
           }
           return keyStore; 
	}
	
	private  void storeKeyStore(KeyStore ks) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
		
		File file=new File(ksPath); 
		if(!file.exists()){
			file.createNewFile();
		}
		OutputStream os=new FileOutputStream(file); 
		ks.store(os, ksPassword.toCharArray());	
	}
	
    private void keystorecerts2Hashtable(KeyStore ks, Hashtable<Principal, Vector<Certificate>> hash)    throws Exception {

    for (Enumeration<String> aliases = ks.aliases();
                                    aliases.hasMoreElements(); ) {
        String alias = aliases.nextElement();
        Certificate cert = ks.getCertificate(alias);
        if (cert != null) {
            Principal subjectDN = ((X509Certificate)cert).getSubjectDN();
            Vector<Certificate> vec = hash.get(subjectDN);
            if (vec == null) {
                vec = new Vector<Certificate>();
                vec.addElement(cert);
            } else {
                if (!vec.contains(cert)) {
                    vec.addElement(cert);
                }
            }
            hash.put(subjectDN, vec);
        }
    }
}

    private boolean buildChain(X509Certificate certToVerify,Vector<Certificate> chain,Hashtable<Principal, Vector<Certificate>> certs) {
    		
    		Principal issuer = certToVerify.getIssuerDN();
    		if (isSelfSigned(certToVerify)) {
    			// reached self-signed root cert;
    			// no verification needed because it's trusted.
    			chain.addElement(certToVerify);
    			return true;
    		}

			// Get the issuer's certificate(s)
    		Vector<Certificate> vec = certs.get(issuer);
			if (vec == null) {
				return false;
			}
			
			// Try out each certificate in the vector, until we find one
			// whose public key verifies the signature of the certificate
			// in question.
			for (Enumeration<Certificate> issuerCerts = vec.elements();	issuerCerts.hasMoreElements(); ) {
				X509Certificate issuerCert= (X509Certificate)issuerCerts.nextElement();
				PublicKey issuerPubKey = issuerCert.getPublicKey();
				try {
					certToVerify.verify(issuerPubKey);
				} catch (Exception e) {
			    	continue;
				}
				if (buildChain(issuerCert, chain, certs)) {
					chain.addElement(certToVerify);
					return true;
				}
			}
			return false;
		}

    private void doSelfCert(String alias, String dname,KeyStore ks,String ksPassword,KeyPair kp) 
    		throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, InvalidKeyException, NoSuchProviderException, SignatureException{
    	
    
    	Date startDate = new Date();                // time from which certificate is valid
    	Date expiryDate = new Date(startDate.getYear()+1,startDate.getMonth(),startDate.getDay());               
    	BigInteger serialNumber = BigInteger.ONE;       // serial number for certificate
    	PrivateKey caKey = (PrivateKey) ks.getKey(alias, ksPassword.toCharArray());              
    	X509Certificate caCert =(X509Certificate) ks.getCertificate(alias);;        // public key certificate of the certifying authority
    	KeyPair keyPair =kp ;               // public/private key pair that we are creating certificate for

    	X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
    	X500Principal              subjectName = new X500Principal(dname);

    	certGen.setSerialNumber(serialNumber);
    	certGen.setIssuerDN(caCert.getSubjectX500Principal());
    	certGen.setNotBefore(startDate);
    	certGen.setNotAfter(expiryDate);
    	certGen.setSubjectDN(subjectName);
    	certGen.setPublicKey(caCert.getPublicKey());
    	certGen.setSignatureAlgorithm(sigAlg);

    	certGen.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
    	                        new AuthorityKeyIdentifierStructure(caCert));
    	certGen.addExtension(X509Extensions.SubjectKeyIdentifier, false,
    	                        new SubjectKeyIdentifierStructure(caCert.getPublicKey()));

    	X509Certificate cert = certGen.generate(caKey, "BC");
    	Certificate[] certs= new Certificate[1]; 
    	certs[0]=cert;
    	ks.setKeyEntry(alias, kp.getPrivate(), ksPassword.toCharArray(),certs); 
        
    	
    	
    	
    }
}
