package com.miltos.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.stream.Stream;

import org.apache.log4j.Logger;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.WindowsCodec;

/**
 * OS Command Injection - Clean Version **************************
 * 
 *  This program contains the appropriate security mechanisms for eliminating 
 *  the identified security issues. 
 * 		
 * 	Main Issue: 
 * 
 * 		- OS Command Injection vulnerability (CWE-78)
 * 
 *  Secondary Issues:
 *  
 *  	- Improper Resource Handling (CWE-399)
 *  	- Improper Exception Handling (CWE-388, CWE-199, CWE-209)
 *  	- Improper Logging (CWE-778)
 *  
 *  Applied Security Mechanisms for mitigating OS Command Injection:
 *  
 *  	- Input Validation: Check for illegal characters
 *  	- Input Sanitization: Neutralize the input by removing the identified 
 *  						  illegal characters.
 *  	- Input Encoding: Properly encode the command before executing it to the console.
 *  	- Parameterization: Distinguish the actual command from the input data.
 *  
 *  Other Implemented Security Mechanisms:
 *  
 *  	- Proper Resource handling: Usage of try/catch/finally block.
 *  	- Proper Exception Handling:
 *  			- Avoid catching generic exceptions
 *  			- Avoid printing the stack trace
 *  			- Avoid printing error messages to the user console
 *  	- Proper Logging:
 *  			- Avoid information leakage. 
 * 
 *  Sources of information:
 *  
 *  	- CWE: https://cwe.mitre.org/data/definitions/78.html
 *  	- OWASP: https://www.owasp.org/index.php/OS_Command_Injection_Defense_Cheat_Sheet
 * 
 * @author Miltiadis Siavvas
 *
 */

public class OSCommandInjectionClean {

	final static Logger logger = Logger.getLogger(OSCommandInjectionClean.class);
	final static String DATA_PATH = new File("./input_data.txt").getAbsolutePath();
	final static String APP_PATH = new File("./test.jar").getAbsolutePath();

	public static void main(String[] args) {
		
		// Initialize the objects required for reading the data from the corresponding file
    	FileReader fr = null;
    	BufferedReader br = null;
    	
		try {
			
			/*
			 * 0. Read the input data (i.e. input parameters)
			 */
	
			// Set up a connection to the file containing the input data 
			fr = new FileReader(DATA_PATH);
			br = new BufferedReader(fr);
	    	
	    	// Read the user-defined parameters from the corresponding file
	    	Stream<String> parameters = br.lines();
	    	Iterator<String> parameterIt = parameters.iterator();
	    	
	    	/*
	    	 * 1. Execute the application for each parameter
	    	 */
	    
	    	// Initialize the required objects
	    	String parameter = "";
	    	ProcessBuilder builder;
	    	Process process;
	    	
	    	// For each one of the retrieved parameters...
	    	while(parameterIt.hasNext()) {
	    		
	    		// Read the value of the parameter
	    		parameter = parameterIt.next();
	    		
	    		// Log the value of the retrieved parameter
	    		if(logger.isDebugEnabled()) {
	    			logger.debug("-------------------------------");
	    			logger.debug("Input Parameter: " + parameter);
	    		}
	    		
	    		/*
	    		 * Security Mechanisms:
	    		 * 	A. Input Validation
	    		 *  B. Input Neutralization (Sanitization)
	    		 *  C. Encoding
	    		 *  D. Parameterization
	    		 */
	    		
	    		// A. Input Validation: Check if the parameter contains illegal characters
	    		if(!Pattern.matches("^[a-zA-Z0-9 ]{1,20}$", parameter)){	
	    			
	    			// Log the event
	    			logger.debug("The parameter contains illegal characters.");
	    			
	    			// B. Sanitize/Neutralize the input parameter (i.e. remove illegal characters)
	    			parameter = parameter.replaceAll("[^a-zA-Z0-9 ]", "");
	    			parameter = parameter.replaceAll(" ", "");
	    			
	    		} else {
	    			
	    			// Log the event
	    			logger.debug("The command does not contain any illegal character.");
	    			
	    		}
	    		
	    		// C. Encoding: Create and encode the basic command
	    		String command = "java -jar %s";
	    		command = String.format(command, APP_PATH);
	    		command =  ESAPI.encoder().encodeForOS(new WindowsCodec(), command);
	    		
	    		// C. Encoding: Encode the parameter that will be provided as input to the command
	    		parameter = ESAPI.encoder().encodeForOS(new WindowsCodec(), parameter);
	    		
	    		/*
	    		 * Execute the command
	    		 */
	    		
	    		// D. Parameterization: Provide command and data separately to the ProcessBuilder
	    		builder = new ProcessBuilder("cmd.exe", "/c", command, "", parameter);
	        	builder.redirectErrorStream(true);
	        	
	    		try {
	    			
	    			// Execute the command as an individual process
					process = builder.start();
					
					/*
					 * Log the console output...
					 */
					
					BufferedReader consoleReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
					
					// Retrieve the console output
		    		String line = "";
		    		String output = "";
		    		while (true) {
		    			line = consoleReader.readLine();
		    			if (line == null) { break; }
		    			output += line;
		    		}
		    		
		    		// Log the console output
		    		if(logger.isDebugEnabled()) {
		    			logger.debug("Command: " + command + " " + parameter);
		    			logger.debug("Console Output: " + output);
		    		}
		    		
				} catch (IOException e) {
					logger.error("The process could not be executed successfully!");
					logger.error(e.getMessage());
				}
	    	}
	    	
		} catch (FileNotFoundException e) {
			
			logger.error("The file could not be found!");
			logger.error(e.getMessage());
			
		} finally {
			
			/*
			 * Properly release the resources...
			 */
	    	try {
	    		
	    		if (br != null) {
	    			br.close();
	    		}
	    		
			} catch (IOException e) {
				
				logger.error("Error closing the BufferedReader");
				logger.error(e.getMessage());
				
			} 	
	    	
	    	try {
	    		
	    		if (fr != null) {
	    			fr.close();
	    		}
	    		
			} catch (IOException e) {
				
				logger.error("Error closing the FileReader");
				logger.error(e.getMessage());
				
			} 

		}
	}
}


