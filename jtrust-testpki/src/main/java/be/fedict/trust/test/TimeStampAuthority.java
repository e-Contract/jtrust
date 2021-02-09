/*
 * Java Trust Project.
 * Copyright (C) 2018-2021 e-Contract.be BV.
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

package be.fedict.trust.test;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.DefaultSignedAttributeTableGenerator;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.bouncycastle.tsp.TimeStampRequest;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.tsp.TimeStampResponseGenerator;
import org.bouncycastle.tsp.TimeStampTokenGenerator;
import org.bouncycastle.util.Store;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of a timestamp authority according to RFC 3161.
 * 
 * @author Frank Cornelis
 *
 */
public class TimeStampAuthority implements EndpointProvider, FailableEndpoint {

	private final World world;

	private final CertificationAuthority certificationAuthority;

	private final String identifier;

	private KeyPair keyPair;

	private X509Certificate certificate;

	private List<X509Certificate> certificateChain;

	private String url;

	private String keyAlgorithm;

	private FailBehavior failBehavior;

	private final static Map<String, TimeStampAuthority> timeStampAuthorities;

	static {
		timeStampAuthorities = new HashMap<>();
	}

	/**
	 * Main constructor.
	 * 
	 * @param world
	 * @param certificationAuthority the TSA issuing CA.
	 */
	public TimeStampAuthority(World world, CertificationAuthority certificationAuthority) {
		this.identifier = UUID.randomUUID().toString();
		timeStampAuthorities.put(this.identifier, this);
		this.world = world;
		this.world.addEndpointProvider(this);
		this.certificationAuthority = certificationAuthority;
		this.keyAlgorithm = "RSA";
	}

	public String getKeyAlgorithm() {
		return this.keyAlgorithm;
	}

	/**
	 * Sets the key algorithm used by this time stamp authority. This can be either
	 * "RSA" or "EC".
	 * 
	 * @param keyAlgorithm
	 */
	public void setKeyAlgorithm(String keyAlgorithm) {
		this.keyAlgorithm = keyAlgorithm;
	}

	@Override
	public void addEndpoints(ServletContextHandler context) throws Exception {
		String pathSpec = "/" + this.identifier + "/tsa";
		ServletHolder servletHolder = context.addServlet(TSAServlet.class, pathSpec);
		servletHolder.setInitParameter("identifier", this.identifier);
	}

	@Override
	public void started(String url) throws Exception {
		this.url = url + "/" + this.identifier + "/tsa";
		reissueCertificate("CN=TSA");
	}

	/**
	 * Reissue the TSA certificate using the new DN.
	 * 
	 * @param dn
	 * @throws Exception
	 */
	public void reissueCertificate(String dn) throws Exception {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}

		if ("RSA".equals(this.keyAlgorithm)) {
			this.keyPair = PKITestUtils.generateKeyPair();
		} else {
			this.keyPair = PKITestUtils.generateKeyPair("EC");
		}

		CertificationAuthority issuer = this.certificationAuthority;
		if (issuer != null) {
			// make sure that the CA's are generated before our TSA certificate
			issuer.getCertificate();
		}

		this.certificate = this.certificationAuthority.issueTimeStampAuthority(this.keyPair.getPublic(), dn);
		this.certificateChain = new LinkedList<>();
		this.certificateChain.add(this.certificate);
		while (issuer != null) {
			this.certificateChain.add(issuer.getCertificate());
			issuer = issuer.getIssuer();
		}
	}

	/**
	 * Gives back the URL on which the timestamp service is available.
	 * 
	 * @return
	 */
	public String getUrl() {
		if (!this.world.isRunning()) {
			throw new IllegalStateException();
		}
		return this.url;
	}

	/**
	 * Gives back the TSA certificate.
	 * 
	 * @return
	 */
	public X509Certificate getCertificate() {
		return this.certificate;
	}

	@Override
	public void setFailureBehavior(FailBehavior failBehavior) {
		this.failBehavior = failBehavior;
	}

	public static final class TSAServlet extends HttpServlet {
		private static final Logger LOGGER = LoggerFactory.getLogger(TSAServlet.class);

		private static final long serialVersionUID = 1L;

		private String identifier;

		@Override
		protected void doPost(HttpServletRequest request, HttpServletResponse response)
				throws ServletException, IOException {
			try {
				_doPost(request, response);
			} catch (Exception e) {
				LOGGER.error("error: " + e.getMessage(), e);
			}
		}

		private void _doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
			TimeStampAuthority timeStampAuthority = getTimeStampAuthority();

			byte[] reqData = IOUtils.toByteArray(request.getInputStream());
			TimeStampRequest timeStampRequest = new TimeStampRequest(reqData);

			// CMS signing-time also has to change accordingly
			LocalDateTime now = timeStampAuthority.certificationAuthority.getClock().getTime();
			Attribute attr = new Attribute(CMSAttributes.signingTime,
					new DERSet(new Time(Date.from(now.atZone(ZoneId.systemDefault()).toInstant()))));
			ASN1EncodableVector v = new ASN1EncodableVector();
			v.add(attr);
			String signatureAlgorithm;
			if ("RSA".equals(timeStampAuthority.keyAlgorithm)) {
				signatureAlgorithm = "SHA256withRSA";
			} else {
				signatureAlgorithm = "SHA256withECDSA";
			}
			TimeStampTokenGenerator tsTokenGen = new TimeStampTokenGenerator(
					new JcaSimpleSignerInfoGeneratorBuilder()
							.setSignedAttributeGenerator(
									new DefaultSignedAttributeTableGenerator(new AttributeTable(v)))
							.build(signatureAlgorithm, timeStampAuthority.keyPair.getPrivate(),
									timeStampAuthority.certificate),
					new JcaDigestCalculatorProviderBuilder().build().get(
							new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256)),
					new ASN1ObjectIdentifier("1.2"));

			LOGGER.debug("certificate chain size: {}", timeStampAuthority.certificateChain.size());
			Store certs = new JcaCertStore(timeStampAuthority.certificateChain);
			tsTokenGen.addCertificates(certs);

			TimeStampResponseGenerator timeStampResponseGenerator = new TimeStampResponseGenerator(tsTokenGen,
					TSPAlgorithms.ALLOWED);
			LOGGER.debug("genTime: {}", now);
			TimeStampResponse timeStampResponse;
			if (null != timeStampAuthority.failBehavior && timeStampAuthority.failBehavior.fail()) {
				timeStampResponse = timeStampResponseGenerator.generateFailResponse(PKIStatus.REJECTION,
						PKIFailureInfo.systemFailure, "woops");
			} else {
				timeStampResponse = timeStampResponseGenerator.generate(timeStampRequest, BigInteger.ONE,
						Date.from(now.atZone(ZoneId.systemDefault()).toInstant()));
			}

			response.setContentType("application/timestamp-reply");
			OutputStream outputStream = response.getOutputStream();
			IOUtils.write(timeStampResponse.getEncoded(), outputStream);
		}

		@Override
		public void init(ServletConfig config) throws ServletException {
			this.identifier = config.getInitParameter("identifier");
		}

		private TimeStampAuthority getTimeStampAuthority() {
			return timeStampAuthorities.get(this.identifier);
		}
	}
}
