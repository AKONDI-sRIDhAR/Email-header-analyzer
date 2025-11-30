# Email-header-analyzer
EML Analyzer is a command-line Java tool that analyzes .eml email files to identify potential security risks such as spoofing, phishing, and forged headers. It checks SPF, DKIM, and DMARC authentication, inspects email routing paths, and provides a simple verdict on whether the email is safe or suspicious.

how to run it 
 & "C:\Program Files\apache-maven-3.9.9\bin\mvn.cmd" clean package  //to clean package for the first time only 

 
java -jar target/eml-analyzer-1.0-jar-with-dependencies.jar "<path to eml file"
