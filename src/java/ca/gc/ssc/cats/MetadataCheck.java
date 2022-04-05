package ca.gc.ssc.cats;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.LDAPCertStoreParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLSelector;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import javax.security.auth.x500.X500Principal;
import javax.xml.XMLConstants;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;


/**
 * A tool to check a SAML 2 metadata file for compliance with CATS v2 and other
 * GCCF operational requirements and best practices.
 */

public class MetadataCheck {
	
	// Namespaces
	private static String SAML_MD_NS = "urn:oasis:names:tc:SAML:2.0:metadata";
	private static String SIG_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

	// Major elements of the metadata
	private Document metadata;
	private Element signature;
	private Element roleDescriptor;
	
	// Metadata Certificates
	X509Certificate signingCert, encryptionCert, signatureCert;
	
	// ICM stuff
	private enum CertType {CATE, PROD, UNKNOWN, REVOKED, INVALID};
	static X500Principal ICM_ROOT = new X500Principal("OU=1CA-AC1, OU=GSS-SPG, O=GC, C=CA");
	
	private static int KEY_USAGE_SIGNATURE = 0;
	private static int KEY_USAGE_ENCIPHERMENT = 2;
	
	
	CertStore icmProdStore, icmCateStore;
	
	// Global problem counters
	private int errorCount = 0;
	private int warningCount = 0;
	
	/**
	 * Constructor. Connects to ICM CATE & PROD, grabs the CA root certificates,
	 * then loads the metadata.
	 * @param fileName the name of the metadata file to be loaded
	 * @throws Exception
	 */
	public MetadataCheck(String fileName) throws Exception {
		try {
			// Connect to ICM
			icmProdStore = CertStore.getInstance("LDAP", new LDAPCertStoreParameters("ldap.gss-spg.gc.ca"));
			icmCateStore = CertStore.getInstance("LDAP", new LDAPCertStoreParameters("ldap.cate.gss-spg.gc.ca"));
		} catch (Exception e) {
			System.err.println("Unable to connect to ICM. Check network connection.");
			throw e;
		}
	 
		// Enable partitioned CRL checks
		System.setProperty("com.sun.security.enableCRLDP", "true");

		// Parse the file and check schema validity
		metadata = parseMetadata(fileName);
	}
	
	/**
	 * Main method
	 * @param args
	 */
	
	public static void main(String[] args) throws Exception {
		String inFileName;
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		
		System.out.println("Cyber Authentication Technology Solutions");
		System.out.println("SAML metadata checking tool");
		System.out.println("Version 1.9\n");
		
		if (args.length != 1) {
			System.out.print("Enter the location of the xml file to be checked: ");
			inFileName = br.readLine();
		} else {
			inFileName = args[0];
		}
		
		MetadataCheck checker = new MetadataCheck(inFileName);
		
		// Check for CATS compliance
		if (checker.metadata != null) {
			checker.checkCompliance();
		}
		
		// Check Entity name against GCCF naming conventions
		if (checker.metadata != null) {
			checker.checkEntityId();
		}
		
		// Check the signing and encryption certificates
		if (checker.roleDescriptor != null) {
			checker.checkCertificates();
		}
		
		// Check the signature
		if (checker.signature != null) {
			checker.checkSignature();
		}
		System.out.println("\nResults summary:");
		if (checker.errorCount == 0) {
			System.out.println("The metadata appears to be CATSv2 compliant");
		} else {
			System.out.println(checker.errorCount + " errors were discovered");
			System.out.println("The metadata is not CATSv2 compliant");
		}
		System.out.println("There are " + checker.warningCount + " warnings");
	}

	/**
	 * Parse the metadata XML and validate it against the OASIS metadata
	 * schema.
	 * @param fileName the name of the file to parse
	 * @return the metadata document DOM 
	 * @throws Exception
	 */
	private Document parseMetadata(String fileName) throws Exception {

		// Load the SAML2 metadata schema
		SchemaFactory sf = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
		URL metadataSchemaUrl = this.getClass().getResource("/saml-schema-metadata-2.0.xsd");
		Schema metadataSchema = sf.newSchema(metadataSchemaUrl);
		
		// Parse the metadata document
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		
		DocumentBuilder parser = dbf.newDocumentBuilder();
		ParseErrorHandler parseErrorHandler = new ParseErrorHandler("XML Parsing");
		parser.setErrorHandler(parseErrorHandler);
		Document doc = parser.parse(
				       new FileInputStream(fileName));
		
		if (parseErrorHandler.getErrorCount() > 0) {
			System.out.println("Parsing Summary: The file is not valid XML!");
		}
		errorCount += parseErrorHandler.getErrorCount();
		warningCount += parseErrorHandler.getWarningCount();

		// Now validate it against the OASIS SAML metadata schema
		ParseErrorHandler validationErrorHandler = new ParseErrorHandler("XML Parsing");
		Validator validator = metadataSchema.newValidator();
		validator.setErrorHandler(validationErrorHandler);
		validator.validate(new DOMSource(doc));
		
		if (validationErrorHandler.getErrorCount() > 0) {
			System.out.println("Validation Summary: The file is not valid SAML Metadata!");
		}
		errorCount += validationErrorHandler.getErrorCount();
		warningCount += validationErrorHandler.getWarningCount();
		
		return doc;
	}

	/**
	 * Check for the presence of specific elements allowed/required by
	 * CATS v2, and report elements that should not be there.
	 * @throws Exception
	 */
	private void checkCompliance() throws Exception {
		// Check the top level element is EntityDescriptor
		Element topElement = metadata.getDocumentElement();
		String topElementName = topElement.getLocalName();
		if (! "EntityDescriptor".equals(topElementName)) {
			System.out.println("CATS Error: Root element is " + topElementName +
					           ", it must be EntityDescriptor");
			errorCount++;
		}

		NodeList children = topElement.getChildNodes();
		if (children.getLength() == 0) {
			System.out.println("CATS Error: EntityDescriptor has no children");
			// Can't go any further
			return;
		}
			
		// Check all the children
		for (int i = 0; i < children.getLength(); i++) {
			Node child = children.item(i);
			if (child.getNodeType() != Node.ELEMENT_NODE) {
				continue;
			}
			if ("Signature".equals(child.getLocalName())) {
				signature = (Element) child;
			} else if ("IDPSSODescriptor".equals(child.getLocalName())
					|| "SPSSODescriptor".equals(child.getLocalName())) {
				if (roleDescriptor == null) {
					roleDescriptor = (Element) child;
				} else {
					System.out.println("CATS Error: Only one SPSSODescriptor or IDPSSODescriptor is allowed");
					errorCount++;
				}
			} else if ("Organization".equals(child.getLocalName())
					    || "ContactPerson".equals(child.getLocalName())) {
				continue;
			} else if ("Extensions".equals(child.getLocalName())) {
				System.out.println("CATS Warning: " + child.getLocalName() + " to Entity Descriptor may cause interoperability issues");
				warningCount++;
			} else {
					System.out.println("CATS Error: " + child.getLocalName() + " is not allowed");
					errorCount++;
			}
		}
		
		if (signature == null) {
			System.out.println("CATS Error: Signature is missing or out of place");
			errorCount++;
		}

		if (roleDescriptor == null) {
			System.out.println("CATS Error: No IDP or SP descriptor found");
			errorCount++;
			return;
		}
		
		// Check for the persistent NameID format
		NodeList nameIDFormats = roleDescriptor.getElementsByTagNameNS(SAML_MD_NS, "NameIDFormat");
		if (nameIDFormats.getLength() == 0) {
			System.out.println("CATS Warning: Missing NameIDFormat element (should specify persistent)");
			warningCount++;
		}
		for (int i = 0; i < nameIDFormats.getLength() ; i++) {
			Element nameIDFormat = (Element)nameIDFormats.item(i);
			if (! "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent".equals(nameIDFormat.getTextContent().trim())) {
				System.out.println("CATS Error: invalid NameIDFormat " + nameIDFormat.getTextContent());
				errorCount++;
			}
		}
		
		// Check for the required Single Logout endpoints
		boolean hasSoapSlo = false;
		boolean hasRedirectSlo = false;
		NodeList logoutServices = roleDescriptor.getElementsByTagNameNS(SAML_MD_NS, "SingleLogoutService");
		for (int i = 0; i < logoutServices.getLength() ; i++) {
			Element logoutService = (Element)logoutServices.item(i);
			String binding = logoutService.getAttribute("Binding");
			if ("urn:oasis:names:tc:SAML:2.0:bindings:SOAP".equals(binding)) {
				hasSoapSlo = true;
			} else if ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".equals(binding)) {
				hasRedirectSlo = true;
			} else {
				System.out.println("CATS Error: Single Logout binding " + binding + " is not allowed");
				errorCount++;
			}
			if (! checkUrl("Single Logout Service Location", logoutService.getAttribute("Location"))) {
				errorCount++;
			}
			if (logoutService.hasAttribute("ResponseLocation")) {
				if (! checkUrl("Single Logout Service ResponseLocation", logoutService.getAttribute("ResponseLocation"))) {
					errorCount++;
				}
			}
		}
		if (! hasSoapSlo) {
			String entityId = metadata.getDocumentElement().getAttribute("entityID");
			if (!entityId.matches("^https://(?:[a-z0-9]+-)?auth\\.id(?:\\.alpha)?\\.canada\\.ca$")) {
				System.out.println("CATS Error: missing SOAP Single Logout Service");
				errorCount++;
			}
		}
		if (! hasRedirectSlo) {
			System.out.println("CATS Error: missing HTTP-Redirect Single Logout Service");
			errorCount++;
		}
		
		// Check for any Artifact Resolution Service
		NodeList arServices = roleDescriptor.getElementsByTagNameNS(SAML_MD_NS, "ArtifactResolutionService");
		if (arServices.getLength() > 0) {
			System.out.println("CATS Error: Artifact Resolution Service is not allowed");
			errorCount++;
		}

		if ("IDPSSODescriptor".equals(roleDescriptor.getLocalName())) {
			// Check for WantAuthnRequestsSigned
			String wantAuthReqsSigned = roleDescriptor.getAttribute("WantAuthnRequestsSigned");
			if (!("true".equals(wantAuthReqsSigned) || "1".equals(wantAuthReqsSigned))) {
				System.out.println("CATS Error: WantAuthnRequestsSigned should be true (or 1)");
				errorCount++;
			}
			// Check the IDP SSO Service
			NodeList ssoServices = roleDescriptor.getElementsByTagNameNS(SAML_MD_NS, "SingleSignOnService");
			for (int i = 0; i < ssoServices.getLength() ; i++) {
				Element ssoService = (Element)ssoServices.item(i);
				String binding = ssoService.getAttribute("Binding");
				if ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".equals(binding)) {
					if (! checkUrl("Single Sign On Service Location", ssoService.getAttribute("Location"))) {
						errorCount++;
					}
				} else {
					System.out.println("CATS Error: Single Sign On binding " + binding + " is not allowed");
					errorCount++;
				}
			}

			// Check for any NameID Mapping Resolution Service
			NodeList nidmServices = roleDescriptor.getElementsByTagNameNS(SAML_MD_NS, "NameIDMappingService");
			if (nidmServices.getLength() > 0) {
				System.out.println("CATS Error: NameID Mapping Service is not allowed");
				errorCount++;
			}

			// Check for any Assertion ID Request Service
			NodeList airServices = roleDescriptor.getElementsByTagNameNS(SAML_MD_NS, "AssertionIDRequestService");
			if (airServices.getLength() > 0) {
				System.out.println("CATS Error: Assertion ID Request Service is not allowed");
				errorCount++;
			}

			// Check for any Attribute Profiles
			NodeList apServices = roleDescriptor.getElementsByTagNameNS(SAML_MD_NS, "AttributeProfile");
			if (apServices.getLength() > 0) {
				System.out.println("CATS Error: Attribute Profile is not allowed");
				errorCount++;
			}

/*			// Check for any Attributes
			NodeList attributes = roleDescriptor.getElementsByTagNameNS(SAML_CORE_NS, "Attribute");
			if (attributes.getLength() > 0) {
				System.out.println("CATS Error: Attribute is not allowed");
				errorCount++;
			}
*/
		} else {
			// Check for AuthnRequestsSigned
			String authReqsSigned = roleDescriptor.getAttribute("AuthnRequestsSigned");
			if (!("true".equals(authReqsSigned) || "1".equals(authReqsSigned))) {
				System.out.println("CATS Error: AuthnRequestsSigned should be true (or 1)");
				errorCount++;
			}
			// Check for wantAssertionsSigned
			String wantAssertionsSigned = roleDescriptor.getAttribute("WantAssertionsSigned");
			if (!("true".equals(wantAssertionsSigned) || "1".equals(wantAssertionsSigned))) {
				System.out.println("CATS Error: WantAssertionsSigned should be true (or 1)");
				errorCount++;
			}
			// Check the SP Assertion Consumer Service
			NodeList acsServices = roleDescriptor.getElementsByTagNameNS(SAML_MD_NS, "AssertionConsumerService");
			for (int i = 0; i < acsServices.getLength() ; i++) {
				Element acsService = (Element)acsServices.item(i);
				String binding = acsService.getAttribute("Binding");
				if ("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(binding)) {
					if (! checkUrl("Assertion Consumer Service Location", acsService.getAttribute("Location"))) {
						errorCount++;
					}
					String isDefault = acsService.getAttribute("isDefault");
					if (! ("true".equals(isDefault) || "1".equals(isDefault))) {
						System.out.println("CATS Warning: isDefault on the AssertionConsumerService should be true");
						warningCount++;
					}
				} else {
					System.out.println("CATS Error: Assertion Consumer Service binding " + binding + " is not allowed");
					errorCount++;
				}
			}
			
			// Check the MNI Service
			NodeList mniServices = roleDescriptor.getElementsByTagNameNS(SAML_MD_NS, "ManageNameIDService");
			for (int i = 0; i < mniServices.getLength() ; i++) {
				Element mniService = (Element)mniServices.item(i);
				String binding = mniService.getAttribute("Binding");
				if ("urn:oasis:names:tc:SAML:2.0:bindings:SOAP".equals(binding)) {
					if (! checkUrl("Assertion Consumer Service Location", mniService.getAttribute("Location"))) {
						errorCount++;
					}
				} else {
					System.out.println("CATS Error: Manage NameID Service binding " + binding + " is not allowed");
					errorCount++;
				}
			}
			
			// Check for any Attribute Consuming Service
			NodeList attrServices = roleDescriptor.getElementsByTagNameNS(SAML_MD_NS, "AttributeConsumingService");
			if (attrServices.getLength() > 0) {
				System.out.println("CATS Error: Attribute Consuming Service is not allowed");
				errorCount++;
			}
		}
		
		return;
	}
	
	/**
	 * Check the EntityID against GC naming conventions
	 */
	private void checkEntityId() {
		String entityIdString = metadata.getDocumentElement().getAttribute("entityID");
		URI entityId;
		try {
			entityId = new URI(entityIdString);
		} catch (URISyntaxException e) {
			System.out.println("CATS Error: Entity ID " + entityIdString + " is not a valid URI");
			errorCount++;
			return;
		}
		if (entityId.getScheme() == null) {
			System.out.println("CATS Error: Scheme component is missing from Entity ID URI " + entityIdString);
			errorCount++;
		}
		else if (!"https".equalsIgnoreCase(entityId.getScheme())) {
			System.out.println("Naming Convention Warning: Entity ID should be an https URL");
			warningCount++;
		}
		
		if (entityId.getHost() == null) {
			System.out.println("CATS Error: Entity ID " + entityIdString + "is not a valid URI");
			errorCount++;
		}
		else if (!entityId.getHost().toLowerCase().endsWith(".gc.ca")
				 && !entityId.getHost().toLowerCase().endsWith(".canada.ca")) {
			System.out.println("Naming Convention Warning: Entity ID is not in the .gc.ca or canda.ca domain");
			warningCount++;
		}
		
		if (entityId.getPort() != -1) {
			System.out.println("Naming Convention Warning: Port number is not usually included in an Entity ID");
			warningCount++;
		}
	}

	/**
	 * Checks the validity of a URL
	 * @param description the URL description used in error messages
	 * @param urlString the URL to be validated
	 * @return
	 */
	private boolean checkUrl(String description, String urlString) {
		URL url;
		boolean result = true;
		// Is it a valid URL ?
		try {
			url = new URL(urlString);
		} catch (MalformedURLException e) {
			System.out.println("CATS Error: Malformed URL for " + description + ":" + urlString);
			return false;
			}
		
		// Is it secure ?
		if (! "https".equalsIgnoreCase(url.getProtocol())) {
			System.out.println("CATS Error: URL for " + description + " is not https");
			result = false;
		}
		
		// Is it registered in DNS ?
		try {
			InetAddress.getByName(url.getHost());
		} catch (UnknownHostException e) {
			System.out.println("CATS Warning: host name (DNS) lookup failed for " + description + "\n  URL " + urlString);
			warningCount++;
		}
		return result;
	}

    /**
     * Check the Signing, decryption and signature certificates
     * @throws Exception
     */
	private void checkCertificates() throws Exception {

		CertType signingCertType = CertType.UNKNOWN;
		CertType decryptionCertType = CertType.UNKNOWN;;
 
		KeyInfoFactory certificateParser = KeyInfoFactory.getInstance("DOM");

		// Extract and check the decryption and signature certificates
		NodeList keyDescriptors = roleDescriptor.getElementsByTagNameNS(SAML_MD_NS, "KeyDescriptor");
		for (int i = 0; i < keyDescriptors.getLength(); i++) {
			Element keyDescriptor = (Element)keyDescriptors.item(i);
			String use = keyDescriptor.getAttribute("use");
			Element keyInfoElement = (Element)keyDescriptor.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo").item(0);
			DOMStructure keyInfoDOM = new DOMStructure(keyInfoElement);
			KeyInfo keyInfo;
			try {
				keyInfo = certificateParser.unmarshalKeyInfo(keyInfoDOM);
			} catch (MarshalException e) {
				System.out.println("Error parsing " + use +" certificate: " +
				e.getLocalizedMessage());
				errorCount++;
				continue;
			}
			
			// Dig out the certificate from the KeyInfo
			X509Certificate certificate = extractCertificate(keyInfo);

			if (certificate == null) {
				System.out.println ("CATS Error: no X509Certificate in " + use + " KeyDescriptor");
				errorCount++;
				continue;
			}
			
			if (use == null || use.isEmpty()) {
				System.out.println("CATS Error: KeyDescriptor is missing the \"use\" attribute");
				errorCount++;
			} else if ("signing".equals(use)) {
				signingCertType = checkCertificate(use, certificate);
				signingCert = certificate;
				if (signingCertType != CertType.REVOKED) {
					System.out.println("Info: signing certificate valid until    " + signingCert.getNotAfter());
					System.out.println("      signature algorithm is " + signingCert.getSigAlgName()
							            + ", key size is "
							            + ((RSAKey)signingCert.getPublicKey()).getModulus().bitLength()
							            + " bits. ");
				}
			} else if ("encryption".equals(use)) {
				decryptionCertType = checkCertificate(use, certificate);
				encryptionCert = certificate;
				if (decryptionCertType != CertType.REVOKED) {
					System.out.println("Info: encryption certificate valid until " + encryptionCert.getNotAfter());
					System.out.println("      signature algorithm is " + encryptionCert.getSigAlgName()
				            + ", key size is "
				            + ((RSAKey)encryptionCert.getPublicKey()).getModulus().bitLength()
				            + " bits. ");
				}
			} else {
				System.out.println("CATS Error: invalid use \"" + use + "\" on KeyDescriptor");
				errorCount++;
			}
			
		}
		if (signingCert == null) {
			System.out.println("CATS Error: missing signing certificate");
			errorCount++;
		}
		if (encryptionCert == null) {
			System.out.println("CATS Error: missing encryption certificate");
			errorCount++;
		}
		if (keyDescriptors.getLength() > 2) {
			System.out.println("CATS Error: too many certificates");
			errorCount++;
		}

		if (signingCertType == decryptionCertType) {
			switch (signingCertType) {
				case PROD:
					System.out.println("Info: Metadata contains ICM Production certificates,\n" +
					                   "      it should not be used for testing.");
					break;
				case CATE:
					System.out.println("Info: Metadata contains ICM CATE certificates,\n" +
			                           "      it should not be used for production.");
					break;
				default:
					System.out.println("CATS Error: Metadata does not contain valid ICM certificates");
					errorCount++;
			}
		} else if ((decryptionCertType == CertType.CATE && signingCertType == CertType.PROD) ||
				   (decryptionCertType == CertType.PROD && signingCertType == CertType.CATE)) {
			System.out.println("CATS Error: Signing and Decryption certificates are not from the same CA");
			errorCount++;
		}
		
		if (signingCert != null) {
			if (!signingCert.getSubjectX500Principal().equals(encryptionCert.getSubjectX500Principal())){
				System.out.println("CATS Error: Signing and Decryption certificates have different subjects");
				errorCount++;
			} else {
				System.out.println("Info: Subject is " + signingCert.getSubjectX500Principal().getName());
			}
		}
		
		if (signingCert != null && signingCert.equals(encryptionCert)) {
			System.out.println("CATS Error: Signing and Decryption certificates are the same");
			errorCount++;
		}
		
		if (signingCert!= null && (signingCert.getKeyUsage() == null || !(signingCert.getKeyUsage())[KEY_USAGE_SIGNATURE])) {
			System.out.println("CATS Error: Signing certificate key usage does not include digital signature (possible missmatch?)");
			errorCount++;
		}
			
		if (encryptionCert!= null && (encryptionCert.getKeyUsage() == null || !(encryptionCert.getKeyUsage())[KEY_USAGE_ENCIPHERMENT])) {
			System.out.println("CATS Error: Decryption certificate key usage does not include key encipherment (possible missmatch?)");
			errorCount++;
		}

		// Check the certificate used for the signature
		if (signature != null) {
			Element signatureKeyInfo = (Element)signature.getElementsByTagNameNS(XMLSignature.XMLNS, "KeyInfo").item(0);
			DOMStructure keyInfoDOM = new DOMStructure(signatureKeyInfo);
			KeyInfo keyInfo;
			try {
				keyInfo = certificateParser.unmarshalKeyInfo(keyInfoDOM);
			} catch (MarshalException e) {
				System.out.println("XML Error: could not parse the certificate in the metadata signature" +
				e.getLocalizedMessage());
				errorCount++;
				return;
			}
			signatureCert = extractCertificate(keyInfo);
			
			if (signatureCert.getSerialNumber() != signingCert.getSerialNumber()
					|| checkCertificate("signature", signatureCert) != signingCertType)	{
				System.out.println("CATS Error: Metadata was not signed using the federation member's signing key");
				errorCount++;
			}
		}
		return;
	}
		/**
		 * Extract the X509 Certificate from an XML KeyInfo structure
		 * @param keyInfo The XML KeyInfo structure
		 * @return the  X509 Certificate
		 */
		@SuppressWarnings("unchecked")
		private X509Certificate extractCertificate(KeyInfo keyInfo) {
			X509Certificate certificate = null;
			List<XMLStructure> keyInfoContent = (List<XMLStructure>) keyInfo.getContent();
			for (XMLStructure keyInfoItem : keyInfoContent) {
				if (keyInfoItem instanceof X509Data) {
					List<XMLStructure> x509Data = (List<XMLStructure>) ((X509Data)keyInfoItem).getContent();
					for (Object x509DataItem : x509Data) {
						if (x509DataItem instanceof X509Certificate) {
							certificate = (X509Certificate) x509DataItem;
						}
					}
				}
			}
			return certificate;
		}

	/**
	 * Perform a series of checks on an individual certificate	
	 * @param use a string describing the use of the certificate that will be used in error messages
	 * @param certificate the certificate to be checked
	 * @return the detected type or status of the certificate
	 * @throws CertStoreException
	 */
	private CertType checkCertificate (String use, X509Certificate certificate) throws CertStoreException {
		
		final byte[] SUBJ_ID_PREFIX =  {(byte)0x04, // OCTET_STRING
            							(byte)0x14  // Length=20
           							   };
		
		CertType certType = CertType.UNKNOWN;

		// First check to see that it is an ICM certificate
		if (!certificate.getIssuerX500Principal().equals(ICM_ROOT)) {
			System.out.println("CATS Error: " + use + " certificate was not issued by ICM");
			errorCount++;
			return certType;
		}
		
		byte[] authorityKeyIdentifier = certificate.getExtensionValue("2.5.29.35");

		byte[] caSubjectKeyIdentifier = new byte[22];
		System.arraycopy(SUBJ_ID_PREFIX, 0, caSubjectKeyIdentifier, 0, SUBJ_ID_PREFIX.length);
		System.arraycopy(Arrays.copyOfRange(authorityKeyIdentifier, 6, 26), 0, caSubjectKeyIdentifier, 2, 20);
		byte[] caAuthorityKeyIdentifier = Arrays.copyOfRange(authorityKeyIdentifier, 2, 26);
		
		// Try to find the root certificate
		X509CertSelector rootSelector = new X509CertSelector();
		rootSelector.setSubject(certificate.getIssuerX500Principal());
		rootSelector.setIssuer(certificate.getIssuerX500Principal());
		rootSelector.setAuthorityKeyIdentifier(caAuthorityKeyIdentifier);
		rootSelector.setSubjectKeyIdentifier(caSubjectKeyIdentifier);
		
		Collection <? extends Certificate> caCerts;

		if ((caCerts = icmProdStore.getCertificates(rootSelector)).size()> 0) {
			certType = CertType.PROD;
		} else if ((caCerts = icmCateStore.getCertificates(rootSelector)).size()> 0) {
			certType = CertType.CATE;
		} else {
			System.out.println("CATS Error: "+ use + " certificate was not issued by ICM Prod or CATE");
			errorCount++;
			return certType;
		}
		
		Certificate caCert = (X509Certificate)caCerts.iterator().next();
		
		// Check the signature on the cert
		try {
			certificate.verify(caCert.getPublicKey());
		} catch (Exception e) {
			// Not looking good
			System.out.println("CATS Error: " + use + " certificate failed signature validation");
			errorCount++;
			return CertType.INVALID;
		}
		
		// Perform validity and CRL check
		CertStore certStore = (certType == CertType.PROD ? icmProdStore : icmCateStore);

		try {
			certificate.checkValidity();
			
			X509CRLSelector selector = new X509CRLSelector();
			selector.setCertificateChecking(certificate);
				
			@SuppressWarnings("unchecked")
			Collection<X509CRL> crls = (Collection<X509CRL>)certStore.getCRLs(selector);
			for (X509CRL crl : crls) {
				if (crl.isRevoked(certificate)) {
					System.out.println("CATS Error: " + use + " certificate has been revoked");
					errorCount++;
					certType = CertType.REVOKED;
				}
			}
		} catch (CertStoreException e) {
			System.err.println("Fatal Error: CRL Check Failed. Check Network Connection.");
			throw e;
		} catch (CertificateExpiredException e) {
			System.out.println("CATS Error: " + use + " certificate has expired");
					errorCount++;
		} catch (CertificateNotYetValidException e) {
			System.out.println("CATS Error: " + use + " certificate is not yet valid");
			errorCount++;
		}

	return certType;
	}
	
	/**
	 * Check the digital signature on the metadata
	 */
	private void checkSignature() {

		metadata.getDocumentElement().setIdAttribute("ID", true);
		// Create a DOM XMLSignatureFactory that will be used to unmarshal the
		// document containing the XMLSignature
		XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
		
		// Create a DOMValidateContext and specify a KeyValue KeySelector
		// and document context
		DOMValidateContext valContext = new DOMValidateContext(signatureCert.getPublicKey(), signature);
		
		// unmarshal the XMLSignature
		XMLSignature xmlsig;
		try {
			xmlsig = signatureFactory.unmarshalXMLSignature(valContext);
		} catch (MarshalException e) {
			System.out.println("XML Error: signature parsing failed: " +
					e.getLocalizedMessage());
					errorCount++;
					return;
		}
		
		// Check Algorithms
		if (! SIG_SHA256.equals(xmlsig.getSignedInfo().getSignatureMethod().getAlgorithm())) {
			System.out.println("Warning: Signature is not SHA-256");
			warningCount++;
		}
		@SuppressWarnings("unchecked")
		List<Reference> references = xmlsig.getSignedInfo().getReferences();
		for (Reference reference : references)  {
			if (!DigestMethod.SHA256.equals(reference.getDigestMethod().getAlgorithm())) {
				System.out.println("Warning: Digest on signature reference "+ reference.getURI() +" is not SHA-256");
				warningCount++;
			}
		}
		
		
		try {
			// Validate the XMLSignature
			if (!xmlsig.validate(valContext)) {
				System.out.println("CATS Error: signature validation failed:");
				errorCount++;

				// Validate the signature value
				if (!xmlsig.getSignatureValue().validate(valContext)) {
					System.out.println("       Signature value validation failed");					
				} else {
					System.out.println("       Signature value validation passed");
				}

				// Validate the references (there should only be one)
				for (Reference reference : references)  {
					if (!reference.validate(valContext)) {
						System.out.println("       Signature reference validation failed for " + new String(reference.getURI()));
					} else {
						System.out.println("       Signature reference validation passed for " + new String(reference.getURI()));
					}
				}
			}
		} catch (XMLSignatureException e) {
			System.out.println("CATS Error: signature validation failed: " +
					e.getLocalizedMessage());
					errorCount++;
		}
		return;
	}
}

