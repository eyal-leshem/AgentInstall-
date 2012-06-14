import java.io.IOException;

import org.json.JSONException;
import org.json.JSONObject;


public class InstallConf {
	
	private	String 			agentSerivcePath;
	private	String 			serverCaPath;
	private	final String  	slesh=System.getProperty("file.separator"); 	
	private	String			agentName; 
	private String  		instName; 
	private String  		instPassword; 
	private String			serverRegAgentPath; 
	
	
	public String getTrustStorePath() {
		 return this.getAgentSerivcePath()+ this.getSlesh()+"keystore"+this.getSlesh()+"my.ts";
	}


	public String getServerRegAgentPath() {
		return serverRegAgentPath;
	}

	public void setServerRegAgentPath(String serverRegAgentPath) {
		this.serverRegAgentPath = serverRegAgentPath;
	}

	public String getServerChekTrustConectionPath() {
		return serverChekTrustConectionPath;
	}

	public void setServerChekTrustConectionPath(String serverChekTrustConectionPath) {
		this.serverChekTrustConectionPath = serverChekTrustConectionPath;
	}

	private String			serverChekTrustConectionPath; 
	/**
	 * genrate all parms from json string
	 * @param jsonStr
	 * @throws IOException
	 */
	public InstallConf(String jsonStr) throws AgentInstallException{
		try {
			
			JSONObject json=new JSONObject(jsonStr);			 			
			this.setAgentName(json.getString("agentName"));
			this.setAgentSerivcePath(json.getString("agentServicePath")); 
			this.setServerCaPath(json.getString("serverCaPath")); 
			this.setInstName(json.getString("instName")); 
			this.setInstPassword(json.getString("instPassword")); 
			this.setServerRegAgentPath(json.getString("serverRegAgentPath"));
			this.setServerChekTrustConectionPath(json.getString("serverChekTrustConectionPath"));
			
			
			
			
		} catch (JSONException e) {
			throw new AgentInstallException("cann't get the paramter from json : " + jsonStr, e);
		} 
		
	}
	
	public String getInstName() {
		return instName;
	}

	public void setInstName(String instName) {
		this.instName = instName;
	}

	public String getInstPassword() {
		return instPassword;
	}

	public void setInstPassword(String instPassword) {
		this.instPassword = instPassword;
	}

	public String getAgentName() {
		return agentName;
	}
	public void setAgentName(String agentName) {
		this.agentName = agentName;
	}
	public String getAgentSerivcePath() {
		return agentSerivcePath;
	}
	public void setAgentSerivcePath(String agentSerivcePath) {
		this.agentSerivcePath = agentSerivcePath;
	}
	public String getServerCaPath() {
		return serverCaPath;
	}
	public String getSlesh() {
		return slesh;
	}
	
	public void setServerCaPath(String serverCaPath) {
		this.serverCaPath = serverCaPath;
	} 
	
	public String getKsPath(){
		return this.getAgentSerivcePath()+ this.getSlesh()+"keystore"+this.getSlesh()+"my.ks";
	}
	
	
	

}
