package MykeyTool;

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

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.security.auth.x500.X500Principal;


import com.sun.crypto.provider.AESKeyGenerator;

import sun.security.pkcs.PKCS10;


import sun.security.x509.*;
import sun.security.tools.KeyTool;

public class MyKeyTool {

	MyKeyToolConf conf; 
	
	public MyKeyTool(MyKeyToolConf cnf) {
		conf=cnf; 
	}
	
	

	/**
	 * add trusted cert fom input steam 
	 * @param cert
	 * @param alias
	 * @throws MyKeyToolException
	 * @throws MykeyToolIoException
	 */
	public  void addTrustCert(InputStream certStream,String alias) 
				throws Exception{
			
		
		CertificateFactory cf =CertificateFactory.getInstance("X.509");
		Certificate cert= cf.generateCertificate(certStream);
		addTrustCert(cert, alias);
		
		
	}
	/**
	 * add new certificate to the keystore 
	 * @param cert
	 * @param alias
	 * @throws MyKeyToolException
	 * @throws MykeyToolIoException
	 */
	public  void addTrustCert(Certificate cert,String alias) 
			throws MyKeyToolException, MykeyToolIoException{
		
		KeyStore ks=loadKeyStore();
		try {
			ks.setCertificateEntry(alias, cert);
		} catch (KeyStoreException e) {
				throw new MyKeyToolException("cann't and this certificate to key store ", e); 
		}
		storeKeyStore(ks); 	
	
	}
	
	public void createNewKs() throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, MykeyToolIoException, MyKeyToolException {
		  KeyStore ks = KeyStore.getInstance(conf.getKeyStoreType());
		  ks.load(null, conf.getKsPassword().toCharArray());
		  storeKeyStore(ks); 
		  
	 }
	/**
	 * create new secret key and save him into the keystore 
	 * @param alias
	 * @return
	 * @throws Exception
	 */
	public SecretKey genrateSecretKey(String alias,String alg)  throws MyKeyToolException, MykeyToolIoException{
		KeyGenerator keyGen;
		try {
			keyGen = KeyGenerator.getInstance(alg);
		} catch (NoSuchAlgorithmException e) {
			throw new MyKeyToolException("cann't ganerate private key",e);
		} 
		SecretKey 	 key=keyGen.generateKey();
		KeyStore 	 ks=loadKeyStore(); 
		try {
			ks.setKeyEntry(alias, key.getEncoded(), null);
		} catch (KeyStoreException e) {
			throw new MyKeyToolException("cann't save the secret key in keystore, does the keystore support private keys?",e);
		}
		storeKeyStore(ks); 
							
		return null;
	}
	/**
	 * install replay from the ca in out keystore 
	 * @param alias
	 * @param in
	 * @return
	 * @throws MyKeyToolException
	 * @throws MykeyToolIoException
	 */
	public boolean installReply(String alias, InputStream in) throws MyKeyToolException, MykeyToolIoException{
		
		 KeyStore ks=loadKeyStore();
		 
		 PrivateKey privKey;
		try {
			privKey = (PrivateKey)ks.getKey(alias, conf.getKsPassword().toCharArray());
		} catch (Exception e){
			throw new MyKeyToolException("problem to load key from key store",e); 
		}
		
		 Certificate userCert;
		try {
			userCert = ks.getCertificate(alias);
		} catch (KeyStoreException e) {
			throw new MyKeyToolException("problem to get certificate from key store",e); 
		}
		 CertificateFactory cf;
		try {
			cf = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new MyKeyToolException("problem to get instace of certificate factory ",e); 
		}
		 Collection<? extends Certificate> c;
		try {
			c = cf.generateCertificates(in);
		} catch (CertificateException e) {
			throw new MyKeyToolException("problem to generate certificate form input stream",e); 
		}
         Certificate[] replyCerts = c.toArray(new Certificate[c.size()]);
         Certificate[] newChain;
         newChain= establishCertChain(userCert, replyCerts[0],ks);
         try{
         if (newChain != null) {
             try {
				ks.setKeyEntry(alias, privKey,conf.getKsPassword().toCharArray(),newChain);
			} catch (KeyStoreException e) {
				throw new MyKeyToolException("problem to install the replay into the key store back",e); 
			} 
             storeKeyStore(ks); 
             in.close();
             return true;
         } else {
        	 in.close(); 
             return false;
         }
         }catch (Exception e) {
        	 throw new MyKeyToolException("problem with the input stream ",e); 
		}
		 
	
	 }
	

	/**
	 * generate a certificate request form existing private key 
	 * @param alias
	 * @param out
	 * @throws MyKeyToolException
	 * @throws MykeyToolIoException
	 */
	public void   genrateCsr(String alias,OutputStream out) throws MyKeyToolException, MykeyToolIoException	{
		  KeyStore ks=loadKeyStore();
		  Key key = null;
		  try {
			key = ks.getKey(alias,conf.getKsPassword().toCharArray());
		  } catch (Exception e){
			throw new MyKeyToolException("problem to load the key prom key store",e); 
		  }
		  
		  Certificate cert;
		  try {
			  cert = ks.getCertificate(alias);
		  } 
		  catch (KeyStoreException e) {
			throw new MyKeyToolException("problem to load certicate from keystore ",e); 
		  }
		  //pkcs10 standard for certificate request 
		  PKCS10 request = new PKCS10(cert.getPublicKey()); 
		  Signature signature = null;
		  try{
			signature = Signature.getInstance(conf.getSigAlg());
			signature.initSign((PrivateKey) key);
		  }
		  catch (Exception e) {
			  throw new MyKeyToolException("problem to sign the csr ",e); 
		  }		  
		  
		  X500Name subject;
		  try {
			subject = new X500Name(((X509Certificate)cert).getSubjectDN().toString());
		  } catch (IOException e) {
		    throw new MykeyToolIoException("problem to generate the x500 name", e); 
		  } 
		  
		  try {
			request.encodeAndSign(new X500Signer(signature,subject));
		  } catch (Exception e){
			  throw new MyKeyToolException("problem to sign the csr ",e); 
		}
		  
          try {
			request.print(new PrintStream(out));
		} catch (SignatureException e) {
			 throw new MyKeyToolException("problem to sign the csr ",e); 
		} catch (IOException e) {
			throw new MykeyToolIoException("problem to write the csr to the output stream", e);
		}
	}

	/**
	 * Generate a pair of private key and certificate that contain the public key
	 * @param alias
	 * @param dName
	 * @return the new certificate that generated
	 * @throws MyKeyToolException
	 * @throws MykeyToolIoException
	 */
	public  Certificate genartePrivatekey(String alias,String dName) throws MyKeyToolException, MykeyToolIoException{
			 
		  KeyStore ks=loadKeyStore(); 
		  CertAndKeyGen keypair;
		  try {
			 keypair = new CertAndKeyGen(conf.getKeyPairAlg(),conf.getSigAlg(),conf.getProvider());
		  } catch (Exception e) {
				throw new MyKeyToolException("porblem while trying to create object of key pair", e); 
		  }
		
		  X500Name x500Name;
		  try {
			x500Name = new X500Name(dName);
		  } catch (IOException e) {
			  throw new MykeyToolIoException("problem to producde X500 Name",e);
		  }
		  try {
			keypair.generate(1024);
		  } catch (InvalidKeyException e) {
			throw new MyKeyToolException("porblem while trying to genrate key pair", e); 
		  }
		  PrivateKey privKey = keypair.getPrivateKey();
		  X509Certificate[] chain = new X509Certificate[1];
		  
		  try {
			chain[0] = keypair.getSelfCertificate(x500Name, new Date(), 360*24L*60L*60L);
		  } 
		  catch (Exception e){
		  	throw new MyKeyToolException("problem to get self certificate form keypair",e);
		  }
		  try {
			ks.setKeyEntry(alias, privKey, conf.getKsPassword().toCharArray(), chain);
		  } catch (KeyStoreException e) {
			  throw new MyKeyToolException("problem add the certificate to the key store",e);
		  }
		  storeKeyStore(ks);
		  return chain[0]; 
		  
		  
	}
    /**
     * Returns true if the certificate is self-signed, false otherwise.
     */	
    private boolean isSelfSigned(X509Certificate cert) {
        return signedBy(cert, cert);
    }
    /**
     * check if the end certificate sign by the ca cetifcate 
     * @param end
     * @param ca
     * @return
     */
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
    /**
     * load new key store from file 
     * 
     * @return the keyStore instance 
     * @throws MyKeyToolException
     * @throws MykeyToolIoException
     */
	private KeyStore loadKeyStore() throws  MyKeyToolException, MykeyToolIoException {
		
		KeyStore keyStore;
		try {
			keyStore = KeyStore.getInstance(conf.getKeyStoreType());
		} catch (KeyStoreException e) {
			throw new MyKeyToolException("problem to get instance of keystore \n",e); 
			
		}
        InputStream instream;
		try {
			instream = new FileInputStream(new File(conf.getKsPath()));
		} catch (FileNotFoundException e1) {
			throw new MykeyToolIoException("problem to open the file"+conf.getKsPath() , e1);
		}
           try {
               try {
					keyStore.load(instream, conf.getKsPassword().toCharArray());
				} 
               catch (NoSuchAlgorithmException e) {
						throw new MyKeyToolException("error occur while key store loaded \n",e); 
				} 
               catch (CertificateException e) {
					throw new MyKeyToolException("error occur while key store loaded \n",e); 
				} 
               catch (IOException e) {
					throw new MykeyToolIoException("problem to open the file"+conf.getKsPath() , e);
					
				}
           } finally {
               try { instream.close(); } catch (Exception ignore) {  }
           }
           return keyStore; 
	}
	
	/**
	 * store the key store back to the file 
	 * @param ks- the key store object to save
	 * @throws MykeyToolIoException 
	 * @throws MyKeyToolException 
	 */
	private  void storeKeyStore(KeyStore ks) throws MykeyToolIoException, MyKeyToolException {
		OutputStream os; 
		try{
		File file=new File(conf.getKsPath()); 
		if(!file.exists()){
			file.createNewFile();
		}
		 os=new FileOutputStream(file); 
		} catch (Exception e) {
			throw new MykeyToolIoException("problem while trying to save te file", e); 
		}
		
		try {
			ks.store(os, conf.getKsPassword().toCharArray());
		} 
		catch (KeyStoreException e) {
				throw new MyKeyToolException("problem to save the keyStore", e); 	
		} 
		catch (NoSuchAlgorithmException e) {
			throw new MyKeyToolException("problem to save the keyStore", e); 
		}
		catch (CertificateException e) {
			throw new MyKeyToolException("problem to save the keyStore", e); 
		} 
		catch (IOException e) {
			throw new MykeyToolIoException("problem while trying to save te file", e);			
		}	
		try {
			os.close();
		} catch (IOException e) {
			throw new MykeyToolIoException("problem while trying to save te file", e); 
		} 
	}
	/**
	 * put all the certificate from ke y store int a hash tablr
	 * @param ks
	 * @param hash
	 * @throws MyKeyToolException
	 */
    private void keystorecerts2Hashtable(KeyStore ks, Hashtable<Principal, Vector<Certificate>> hash) throws MyKeyToolException   {

    try{	
     //for each alias in the keystore 
    for (Enumeration<String> aliases = ks.aliases();
                                    aliases.hasMoreElements(); ) {
        String alias = aliases.nextElement();
        Certificate cert;
        
		cert = ks.getCertificate(alias);
		//add him to the hash map 
        if (cert != null) {
            Principal subjectDN = ((X509Certificate)cert).getSubjectDN();
            Vector<Certificate> vec = hash.get(subjectDN);
           
            if (vec == null) {
                vec = new Vector<Certificate>();
                vec.addElement(cert);
            } 
            else {
                if (!vec.contains(cert)) {
                    vec.addElement(cert);
                }
            }
            hash.put(subjectDN, vec);
        }
    }
    }catch (KeyStoreException e) {
    	throw new MyKeyToolException("can't read the certifcate for key store to hash table", e); 
		
	}
}
    /**
     * verify that this certificate chain id ok 
     * and return in the chain Variable new chain with this cert 
     * @param certToVerify
     * @param chain
     * @param certs
     * @return true  if the chain is ok 
     */
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

	private Certificate[] establishCertChain(Certificate userCert,Certificate certToVerify,KeyStore ks) throws MyKeyToolException  {
	    PublicKey origPubKey = userCert.getPublicKey();
        PublicKey replyPubKey = certToVerify.getPublicKey();
        if (!origPubKey.equals(replyPubKey)) {
            throw new MyKeyToolException("Public.keys.in.reply.and.keystore.don.t.match");
        }
      
        if (certToVerify.equals(userCert)) {
            throw new MyKeyToolException("Certificate.reply.and.certificate.in.keystore.are.identical");
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
            throw new MyKeyToolException("Failed.to.establish.chain.from.reply");
        }        
     
        
	
		
	}
    
}
