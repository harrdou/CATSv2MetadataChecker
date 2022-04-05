package ca.gc.ssc.cats;

import org.xml.sax.ErrorHandler;
import org.xml.sax.SAXException;
import org.xml.sax.SAXParseException;

public class ParseErrorHandler implements ErrorHandler {
	int errorCount, warningCount;
	
	String handlerName;

	public ParseErrorHandler (String name) {
		this.handlerName = name;
	}
	
	public int getErrorCount() {
		return errorCount;
	}

	public int getWarningCount() {
		return warningCount;
	}

	@Override
	public void warning(SAXParseException exception) throws SAXException {
		warningCount++;
		System.out.println(handlerName + " Warning: Line " +
	                       exception.getLineNumber() +
	                       ", Column " + 
	                       exception.getColumnNumber());
		System.out.println(exception.getLocalizedMessage());
	}

	@Override
	public void error(SAXParseException exception) throws SAXException {
		errorCount++;
		System.out.println(handlerName + " Error: Line " +
                           exception.getLineNumber() +
                           ", Column " + 
                           exception.getColumnNumber());
		System.out.println(exception.getLocalizedMessage());

	}

	@Override
	public void fatalError(SAXParseException exception) throws SAXException {
		System.out.println("FATAL "+ handlerName + " Error: Line " +
                exception.getLineNumber() +
                ", Column " + 
                exception.getColumnNumber());
        System.out.println(exception.getLocalizedMessage());
        throw exception;
	}

}
