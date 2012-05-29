package MykeyTool;

public class MyKeyToolConf {
	
	
	public final String defaultKs="jks";
	public final String defaultSig="SHA1withRSA";
	public final String defaultKpa="RSA"; 
	public final String defaultProvider="BC"; 
	
	String ksPath; 
	String ksPassword; 
	String keyStoreType=defaultKs;
	String sigAlg=defaultSig;  
	String keyPairAlg=defaultKpa; 
	String provider=defaultProvider; 
	
	public MyKeyToolConf(String ksPath,String ksPaswword) {
		this.ksPath=ksPath;
		this.ksPassword=ksPaswword;
		
	}
	
	public MyKeyToolConf(String ksPath,String ksPaswword,String keyStoreType){
	  this(ksPath,ksPaswword); 
	  this.keyStoreType=keyStoreType;
	  
	}
	
	public MyKeyToolConf(String ksPath,String ksPaswword,String keyStoreType,String sigAlg,String keyPairAlg){
		  this(ksPath,ksPaswword,keyStoreType); 
		  this.sigAlg=sigAlg; 
		  this.keyPairAlg=keyPairAlg; 		  
	 }
	
	public MyKeyToolConf(String ksPath,String ksPaswword,String keyStoreType,String sigAlg,String keyPairAlg,String provider){
		this(ksPath,ksPaswword,keyStoreType,sigAlg,keyPairAlg);
		this.provider=provider;
	}

	public String getKsPath() {
		return ksPath;
	}

	public void setKsPath(String ksPath) {
		this.ksPath = ksPath;
	}

	public String getKsPassword() {
		return ksPassword;
	}

	public void setKsPassword(String ksPassword) {
		this.ksPassword = ksPassword;
	}

	public String getKeyStoreType() {
		return keyStoreType;
	}

	public void setKeyStoreType(String keyStoreType) {
		this.keyStoreType = keyStoreType;
	}

	public String getSigAlg() {
		return sigAlg;
	}

	public void setSigAlg(String sigAlg) {
		this.sigAlg = sigAlg;
	}

	public String getKeyPairAlg() {
		return keyPairAlg;
	}

	public void setKeyPairAlg(String keyPairAlg) {
		this.keyPairAlg = keyPairAlg;
	}

	public String getProvider() {
		return provider;
	}

	public void setProvider(String provider) {
		this.provider = provider;
	}
	
	
	
}
