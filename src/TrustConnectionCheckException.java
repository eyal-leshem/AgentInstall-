
public class TrustConnectionCheckException  extends Exception{

	
	public TrustConnectionCheckException(String msg ) {
		super(msg); 
	}
	
	public TrustConnectionCheckException(String msg ,Throwable e ) {
		super(msg,e); 
	}
}
