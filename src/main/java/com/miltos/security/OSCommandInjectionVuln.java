package com.miltos.security;


import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStreamReader;
import java.util.Iterator;
import java.util.stream.Stream;

/**
 * OS Command Injection - Vulnerable Version **************************
 * 
 *  This program contains several security issues.
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
 *  Description: 
 * 
 * 		1. The program receives the input parameters from a specific text file.
 * 		2. Subsequently, it executes a given software program called test.jar
 * 		   for each one of the retrieved input parameters.
 * 
 *  Exploitation of the Main Issue:
 *  
 *  	1. Inside the text file with the parameters add a new parameter and 
 *  	   append the & character followed by an OS Command. 
 *  	2. This will lead to the execution of the selected OS Command. 
 * 
 *  Sources of information:
 *  
 *  	- CWE: https://cwe.mitre.org/data/definitions/78.html
 *  	- OWASP: https://www.owasp.org/index.php/OS_Command_Injection_Defense_Cheat_Sheet
 * 
 * @author Miltiadis Siavvas
 *
 */

public class OSCommandInjectionVuln {
	
	final static String DATA_PATH = new File("./input_data.txt").getAbsolutePath();
	final static String APP_PATH = new File("./test.jar").getAbsolutePath();
	
	public static void main(String[] args) throws Exception {

    	// 1. Open the file with the user-defined parameters
    	FileReader fr = new FileReader(DATA_PATH);
    	BufferedReader br = new BufferedReader(fr);
    	
    	// 2. Read the user-defined parameters from the corresponding file
    	Stream<String> parameters = br.lines();
    	Iterator<String> parameterIt = parameters.iterator();
    	
    	String parameter = "";
    	ProcessBuilder builder;
    	Process process;
    	
    	// 3. Execute the desired program for each one of the retrieved input parameters
    	while(parameterIt.hasNext()) {
    		
    		// Read the parameter 
    		parameter = parameterIt.next();
    		
    		// Construct the command
    		String command = "java -jar " + APP_PATH + " " + parameter;
    		System.out.println("Command: " + command);
    		
    		// Create the ProcessBuilder object
    		builder = new ProcessBuilder("/bin/bash","-c", command);
        	builder.redirectErrorStream(true);
        	
			// Execute the command 
        	/* Potential OS Command Injection vulnerability */
			process = builder.start();
			
			// Log the console output
			BufferedReader consoleReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
			
			// Retrieve the console output
    		String line = "";
    		String output = "";
    		while (true) {
  
    			line = consoleReader.readLine();
    			
    			if (line == null) { break; }
    			output += line;
    		}
    		
    		// Print the console output
    		System.out.println("Console Output: " + output);
    	}
    	
    	// 4. Close the connection to the file
    	br.close();
    	fr.close();
	}
}
