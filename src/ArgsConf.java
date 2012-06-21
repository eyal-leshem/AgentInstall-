import java.util.HashMap;
import java.util.Scanner;


public class ArgsConf {
	
	
	
	

	public static InstallConf setConf(String[] args ,InstallConf conf) throws AgentInstallException {
	
		try{
			
			//run over all and add the parmeters  
			for(int i=0;i<args.length;i++){
				
				if(args[i].startsWith("-")){
					if(i+1>=args.length){
						throw new AgentInstallException("must to give value after parmeter "+ args[i]); 
					}
					addArg(args[i].substring(1),args[i+1],conf); 
					i++; 
				}
				else{
					throw new AgentInstallException("value "+args[i]+"for unknowparmeter");
				}
			}
			
			//get the rest of the parmters fron the user
			askUserParmeter(conf); 
			
		 
			
			return conf; 
			
			
		}catch (AgentInstallException e) {
			throw new AgentInstallException("problem to load the parmeters", e); 
		}					
		
	}


	private static void askUserParmeter(InstallConf conf) {
	
		Scanner in = new Scanner(System.in);
		
		if(conf.getAgentName()==null){
			System.out.println("what is your agent name:");
			conf.setAgentName(in.nextLine()); 
		}
		if(conf.getAgentSerivcePath()==null){
			System.out.println("please enter the full path to dircotry of the agnet path : ");
			conf.setAgentSerivcePath(in.nextLine()); 
		}
		if(conf.getInstName()==null){
			System.out.println("what is the username of the installer :");
			conf.setInstName(in.nextLine());
		}
		if(conf.getInstPassword()==null){
			System.out.println("what is the password of istaller :");
			conf.setInstPassword(in.nextLine()); 
		}
		if(conf.getServerCaPath()==null){
			System.out.println("full path to the certificate file of the server :");
			conf.setServerCaPath(in.nextLine());
		}
		if(conf.getServerRegAgentPath()==null){
			System.out.println("full path to the resiter agnet url of server : ");
			conf.setServerRegAgentPath(in.nextLine()); 			
		}
		if(conf.getServerChekTrustConectionPath()==null){
			System.out.println("full path to the resiter agnet url of server :");
			conf.setServerChekTrustConectionPath(in.nextLine()); 			
		}
		
		
	}


	private static void addArg(String confStr, String value,InstallConf conf) throws AgentInstallException {

		if(value.startsWith("-"))
			throw new AgentInstallException("can't value"+value+" can't start whith '-'  for parmter: "+ confStr);
		
		if(confStr.equals("agentName")){
			conf.setAgentName(value); 
			return;  
		}
		if(confStr.equals("agentServicePath")){
			conf.setAgentSerivcePath(value); 
			return;  
		}
		if(confStr.equals("serverCaPath")){
			conf.setServerCaPath(value); 
			return;  
		}
		if(confStr.equals("instName")){
			conf.setInstName(value); 
			return;  
		}
		if(confStr.equals("instPassword")){
			conf.setInstPassword(value);  
			return;  
		}
		if(confStr.equals("serverRegAgentPath")){
			conf.setServerRegAgentPath(value); 
			return;  
		}
		if(confStr.equals("serverChekTrustConectionPath")){
			conf.setServerChekTrustConectionPath(value);
			return;  
		}
		
		 throw new AgentInstallException("unnown parmeter -"+confStr); 
		
	}

}
