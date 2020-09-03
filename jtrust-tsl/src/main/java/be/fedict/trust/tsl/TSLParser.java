/*
 * Java Trust Project.
 * Copyright (C) 2009-2011 FedICT.
 * Copyright (C) 2019-2020 e-Contract.be BV.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package be.fedict.trust.tsl;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.URL;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.eid.tsl.jaxb.tsl.AdditionalInformationType;
import be.fedict.eid.tsl.jaxb.tsl.AnyType;
import be.fedict.eid.tsl.jaxb.tsl.DigitalIdentityListType;
import be.fedict.eid.tsl.jaxb.tsl.DigitalIdentityType;
import be.fedict.eid.tsl.jaxb.tsl.ObjectFactory;
import be.fedict.eid.tsl.jaxb.tsl.OtherTSLPointerType;
import be.fedict.eid.tsl.jaxb.tsl.OtherTSLPointersType;
import be.fedict.eid.tsl.jaxb.tsl.TSLSchemeInformationType;
import be.fedict.eid.tsl.jaxb.tsl.TSPServiceInformationType;
import be.fedict.eid.tsl.jaxb.tsl.TSPServiceType;
import be.fedict.eid.tsl.jaxb.tsl.TSPServicesListType;
import be.fedict.eid.tsl.jaxb.tsl.TSPType;
import be.fedict.eid.tsl.jaxb.tsl.TrustServiceProviderListType;
import be.fedict.eid.tsl.jaxb.tsl.TrustStatusListType;

/**
 * @author Frank Cornelis
 * 
 */
public class TSLParser {

	private final static QName _MimeType_QNAME = new QName("http://uri.etsi.org/02231/v2/additionaltypes#", "MimeType");
	private final static QName _SchemeTerritory_QNAME = new QName("http://uri.etsi.org/02231/v2#", "SchemeTerritory");

	private static final Logger LOGGER = LoggerFactory.getLogger(TSLParser.class);

	private final InputStream tslInputStream;

	private final TSLParserState tslParserState;

	private final List<TSLConsumer> tslConsumers;

	private final CertificateFactory certificateFactory;

	private final String tslLocation;

	/**
	 * Main constructor.
	 * 
	 * @param tslInputStream
	 */
	public TSLParser(InputStream tslInputStream) {
		this.tslLocation = "unknown";
		this.tslInputStream = tslInputStream;
		this.tslConsumers = new LinkedList<>();
		this.tslParserState = new TSLParserState();
		try {
			this.certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}

	public TSLParser(String location) {
		this.tslLocation = location;
		this.tslParserState = new TSLParserState();
		this.tslParserState.addParsedLocation(location);
		this.tslInputStream = null;
		this.tslConsumers = new LinkedList<>();
		try {
			this.certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}

	public TSLParser(String location, TSLParserState tslParserState, List<TSLConsumer> tslConsumers) {
		this.tslLocation = location;
		this.tslParserState = tslParserState;
		this.tslParserState.addParsedLocation(location);
		this.tslConsumers = tslConsumers;
		this.tslInputStream = null;
		try {
			this.certificateFactory = CertificateFactory.getInstance("X.509");
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		}
	}

	public void addTSLConsumer(TSLConsumer tslConsumer) {
		this.tslConsumers.add(tslConsumer);
	}

	public void parseTrustedList() {
		try {
			_parseTrustedList();
		} catch (Exception e) {
			for (TSLConsumer tslConsumer : this.tslConsumers) {
				tslConsumer.error(this.tslLocation, e);
			}
		}
	}

	public void _parseTrustedList() throws Exception {
		InputStream inputStream;
		if (null == this.tslInputStream) {
			inputStream = new URL(this.tslLocation).openStream();
		} else {
			inputStream = this.tslInputStream;
		}
		TrustStatusListType trustStatusList;
		try {
			trustStatusList = parseTslInputStream(inputStream);
		} catch (JAXBException e) {
			throw new RuntimeException("TSL parsing error: " + e.getMessage(), e);
		}
		LOGGER.debug("TSL parsed");
		TSLSchemeInformationType tslSchemeInformation = trustStatusList.getSchemeInformation();
		BigInteger tslSequenceNumber = tslSchemeInformation.getTSLSequenceNumber();
		LOGGER.debug("TSL sequence number: {}", tslSequenceNumber);
		for (TSLConsumer tslConsumer : this.tslConsumers) {
			tslConsumer.setTSLSequenceNumber(tslSequenceNumber);
		}
		TrustServiceProviderListType trustServiceProviderList = trustStatusList.getTrustServiceProviderList();
		if (null != trustServiceProviderList) {
			List<TSPType> tspList = trustServiceProviderList.getTrustServiceProvider();
			for (TSPType tsp : tspList) {
				TSPServicesListType tspServicesList = tsp.getTSPServices();
				List<TSPServiceType> tspServices = tspServicesList.getTSPService();
				for (TSPServiceType tspService : tspServices) {
					TSPServiceInformationType tspServiceInformation = tspService.getServiceInformation();
					String serviceTypeIdentifier = tspServiceInformation.getServiceTypeIdentifier();
					DigitalIdentityListType digitalIdentityList = tspServiceInformation.getServiceDigitalIdentity();
					List<DigitalIdentityType> digitalIdentities = digitalIdentityList.getDigitalId();
					X509Certificate x509Certificate = null;
					for (DigitalIdentityType digitalIdentity : digitalIdentities) {
						byte[] x509CertificateData = digitalIdentity.getX509Certificate();
						if (null == x509CertificateData) {
							continue;
						}
						x509Certificate = (X509Certificate) this.certificateFactory
								.generateCertificate(new ByteArrayInputStream(x509CertificateData));
					}
					LOGGER.debug("service type identifier: {}", serviceTypeIdentifier);
					for (TSLConsumer tslConsumer : this.tslConsumers) {
						tslConsumer.service(serviceTypeIdentifier, x509Certificate);
					}
				}
			}
		}
		OtherTSLPointersType otherTSLPointers = tslSchemeInformation.getPointersToOtherTSL();
		if (null == otherTSLPointers) {
			return;
		}
		List<OtherTSLPointerType> otherTSLPointerList = otherTSLPointers.getOtherTSLPointer();
		for (OtherTSLPointerType otherTSLPointer : otherTSLPointerList) {
			String tslLocation = otherTSLPointer.getTSLLocation();
			LOGGER.debug("other TSL location: {}", tslLocation);
			if (this.tslParserState.isAlreadyParser(tslLocation)) {
				continue;
			}
			AdditionalInformationType additionalInformation = otherTSLPointer.getAdditionalInformation();
			if (null == additionalInformation) {
				continue;
			}
			String mimetype = null;
			String schemeTerritory = null;
			List<Object> additionalInformationList = additionalInformation.getTextualInformationOrOtherInformation();
			for (Object additionalInformationObject : additionalInformationList) {
				LOGGER.debug("additional information object type: {}",
						additionalInformationObject.getClass().getName());
				if (additionalInformationObject instanceof AnyType) {
					AnyType additionalInformationAnyType = (AnyType) additionalInformationObject;
					List<Object> additionalInformationContentList = additionalInformationAnyType.getContent();
					for (Object additionalInformationContent : additionalInformationContentList) {
						LOGGER.debug("additional information content type: {}",
								additionalInformationContent.getClass().getName());
						if (additionalInformationContent instanceof JAXBElement) {
							JAXBElement additionalInformationElement = (JAXBElement) additionalInformationContent;
							LOGGER.debug("additional information element: {}", additionalInformationElement.getName());
							if (additionalInformationElement.getName().equals(_MimeType_QNAME)) {
								mimetype = (String) additionalInformationElement.getValue();
								LOGGER.debug("mimetype: {}", mimetype);
							} else if (additionalInformationElement.getName().equals(_SchemeTerritory_QNAME)) {
								schemeTerritory = (String) additionalInformationElement.getValue();
								LOGGER.debug("scheme territory: {}", schemeTerritory);
							}
						}
					}
				}
			}
			if ("application/vnd.etsi.tsl+xml".equals(mimetype)) {
				try {
					TSLParser tslParser = new TSLParser(tslLocation, this.tslParserState, this.tslConsumers);
					tslParser.parseTrustedList();
				} catch (Exception e) {
					LOGGER.error("error parsing TSL : " + e.getMessage(), e);
				}
			}
		}
	}

	private TrustStatusListType parseTslInputStream(InputStream inputStream) throws JAXBException {
		Unmarshaller unmarshaller = getUnmarshaller();
		JAXBElement<TrustStatusListType> jaxbElement = (JAXBElement<TrustStatusListType>) unmarshaller
				.unmarshal(inputStream);
		TrustStatusListType trustServiceStatusList = jaxbElement.getValue();
		return trustServiceStatusList;
	}

	private Unmarshaller getUnmarshaller() throws JAXBException {
		JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class,
				be.fedict.eid.tsl.jaxb.tslx.ObjectFactory.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
		return unmarshaller;
	}
}
