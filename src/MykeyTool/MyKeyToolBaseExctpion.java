package MykeyTool;

public class MyKeyToolBaseExctpion extends Exception{
	
	public MyKeyToolBaseExctpion(String errorMsg) {
		super(errorMsg);
	}
	
	public MyKeyToolBaseExctpion(String errorMsg,Throwable cause) {
		super(errorMsg,cause); 
	};

}
