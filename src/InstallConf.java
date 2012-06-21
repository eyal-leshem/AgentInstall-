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
	private String			serverChekTrustConectionPath; 
	
	/**
	 * genrate all parms from json string
	 * @param jsonStr
	 * @throws IOException
	 */
	public InstallConf(String jsonStr) throws AgentInstallException{
		
		//install all varible to b null 
		agentName=null; 
		instName=null; 
		instPassword=null; 
		serverRegAgentPath=null; 
		instName=null; 
		instPassword=null; 
		serverRegAgentPath=null;
			
		JSONObject json;
		try {
			json = new JSONObject(jsonStr);
		} catch (JSONException e) {
			throw new AgentInstallException("can't genrate json from the string", e); 
		}
		/*
		 * if there is no such parmeter in the json 
		 * the json object will throw exception but it is not problem 
		 * Because the holes will b fix later  	
		 */
		try {
			this.setAgentName(json.getString("agentName"));
		} catch (JSONException e) {}
	
		try {
			this.setAgentSerivcePath(json.getString("agentServicePath"));
		} catch (JSONException e) {}
		
		try {
			this.setServerCaPath(json.getString("serverCaPath"));
		} catch (JSONException e) {}
		
		try {
			this.setInstName(json.getString("instName"));
		} catch (JSONException e) {} 
		
		try {
			this.setInstPassword(json.getString("instPassword"));
		} catch (JSONException e) {}
		
		try	{
		this.setServerRegAgentPath(json.getString("serverRegAgentPath"));
		}
		catch (JSONException e) {}
		
		try	{
		this.setServerChekTrustConectionPath(json.getString("serverChekTrustConectionPath"));
		}catch (JSONException e) {}	
			
			
			
		
		
	}
	
	
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
