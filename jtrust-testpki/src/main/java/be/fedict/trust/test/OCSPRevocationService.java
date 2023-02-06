/*
 * Java Trust Project.
 * Copyright (C) 2018-2023 e-Contract.be BV.
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
import java.net.URLDecoder;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.BasicOCSPRespBuilder;
import org.bouncycastle.cert.ocsp.CertificateID;
import org.bouncycastle.cert.ocsp.CertificateStatus;
import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.bouncycastle.cert.ocsp.OCSPRespBuilder;
import org.bouncycastle.cert.ocsp.Req;
import org.bouncycastle.cert.ocsp.RevokedStatus;
import org.bouncycastle.cert.ocsp.UnknownStatus;
import org.bouncycastle.cert.ocsp.jcajce.JcaBasicOCSPRespBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.encoders.Base64;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Implementation of an OCSP revocation service.
 * 
 * @author Frank Cornelis
 *
 */
public class OCSPRevocationService implements RevocationService, FailableEndpoint {

	private final String identifier;

	private final boolean withOcspResponderCertificate;

	private String ocspUri;

	private CertificationAuthority certificationAuthority;

	private static final Map<String, OCSPRevocationService> ocspRevocationServices;

	private FailBehavior failBehavior;

	private PublicKey ocspResponderPublicKey;
	private PrivateKey ocspResponderPrivateKey;
	private X509Certificate ocspResponderCertificate;

	static {
		ocspRevocationServices = new HashMap<>();
	}

	/**
	 * Default constructor.
	 */
	public OCSPRevocationService() {
		this(false);
	}

	/**
	 * Constructor.
	 * 
	 * @param withOcspResponderCertificate set to <code>true</code> to have an
	 *                                     explicit OCSP responder certificate.
	 */
	public OCSPRevocationService(boolean withOcspResponderCertificate) {
		this.identifier = UUID.randomUUID().toString();
		this.withOcspResponderCertificate = withOcspResponderCertificate;
		ocspRevocationServices.put(this.identifier, this);
	}

	@Override
	public void addExtension(X509v3CertificateBuilder x509v3CertificateBuilder) throws Exception {
		GeneralName ocspName = new GeneralName(GeneralName.uniformResourceIdentifier, this.ocspUri);
		AuthorityInformationAccess authorityInformationAccess = new AuthorityInformationAccess(
				X509ObjectIdentifiers.ocspAccessMethod, ocspName);
		x509v3CertificateBuilder.addExtension(Extension.authorityInfoAccess, false, authorityInformationAccess);
	}

	@Override
	public void addEndpoints(ServletContextHandler context) {
		String pathSpec = "/" + this.identifier + "/ocsp/*";
		ServletHolder servletHolder = context.addServlet(OCSPServlet.class, pathSpec);
		servletHolder.setInitParameter("identifier", this.identifier);

	}

	@Override
	public void started(String url) throws Exception {
		this.ocspUri = url + "/" + this.identifier + "/ocsp";
		reissueCertificate("CN=OCSP Responder");
	}

	/**
	 * Reissue the OCSP responder certificate with the new DN.
	 * 
	 * @param dn
	 * @throws Exception
	 */
	public void reissueCertificate(String dn) throws Exception {
		if (this.withOcspResponderCertificate) {
			KeyPair ocspResponderKeyPair;
			if (this.certificationAuthority.getSignatureAlgorithm().contains("RSA")) {
				ocspResponderKeyPair = PKITestUtils.generateKeyPair();
			} else {
				ocspResponderKeyPair = PKITestUtils.generateKeyPair("EC");
			}

			this.ocspResponderPublicKey = ocspResponderKeyPair.getPublic();
			this.ocspResponderPrivateKey = ocspResponderKeyPair.getPrivate();
			this.ocspResponderCertificate = this.certificationAuthority.issueOCSPResponder(this.ocspResponderPublicKey,
					dn);
		} else {
			this.ocspResponderPublicKey = this.certificationAuthority.getCertificate().getPublicKey();
			this.ocspResponderPrivateKey = this.certificationAuthority.getPrivateKey();
		}
	}

	public static final class OCSPServlet extends HttpServlet {
		private static final Logger LOGGER = LoggerFactory.getLogger(OCSPServlet.class);

		private static final long serialVersionUID = 1L;

		private String identifier;

		@Override
		protected void doPost(HttpServletRequest request, HttpServletResponse response)
				throws ServletException, IOException {
			LOGGER.debug("doPost");
			byte[] reqData = IOUtils.toByteArray(request.getInputStream());
			try {
				_doPost(reqData, response);
			} catch (Exception e) {
				LOGGER.error("OCSP error: " + e.getMessage(), e);
			}
		}

		@Override
		protected void doGet(HttpServletRequest request, HttpServletResponse response)
				throws ServletException, IOException {
			LOGGER.debug("doGet");
			LOGGER.debug("request URI: {}", request.getRequestURI());
			String requestBase64 = request.getRequestURI().substring(("/pki/" + this.identifier + "/ocsp/").length());
			LOGGER.debug("request: {}", requestBase64);
			byte[] reqData = Base64.decode(URLDecoder.decode(requestBase64, "UTF-8"));
			try {
				_doPost(reqData, response);
			} catch (Exception e) {
				LOGGER.error("OCSP error: " + e.getMessage(), e);
			}
		}

		private void _doPost(byte[] reqData, HttpServletResponse response) throws Exception {
			OCSPRevocationService ocspRevocationService = getOCSPRevocationService();
			if (null != ocspRevocationService.failBehavior && ocspRevocationService.failBehavior.fail()) {
				throw new RuntimeException("failing OCSP responder");
			}

			OCSPReq ocspReq = new OCSPReq(reqData);

			DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder()
					.setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
			BasicOCSPRespBuilder basicOCSPRespBuilder = new JcaBasicOCSPRespBuilder(
					ocspRevocationService.ocspResponderPublicKey, digCalcProv.get(CertificateID.HASH_SHA1));

			Clock clock = null;
			if (null != ocspRevocationService.failBehavior
					&& (ocspRevocationService.failBehavior instanceof OCSPFailBehavior)) {
				OCSPFailBehavior ocspFailBehavior = (OCSPFailBehavior) ocspRevocationService.failBehavior;
				clock = ocspFailBehavior.getFailingClock();
			}
			if (null == clock) {
				clock = ocspRevocationService.certificationAuthority.getClock();
			}
			LocalDateTime now = clock.getTime();
			LocalDateTime thisUpdate = now.minusSeconds(1);
			LocalDateTime nextUpdate = thisUpdate.plusMinutes(1);

			// request processing
			Req[] requestList = ocspReq.getRequestList();
			for (Req ocspRequest : requestList) {
				CertificateID certificateID = ocspRequest.getCertID();
				CertificateStatus certificateStatus;
				if (ocspRevocationService.isUnknownCertificate(certificateID)) {
					certificateStatus = new UnknownStatus();
				} else {
					LocalDateTime revocationDate = ocspRevocationService.getRevocationDate(certificateID);
					if (null == revocationDate) {
						certificateStatus = CertificateStatus.GOOD;
					} else {
						certificateStatus = new RevokedStatus(
								Date.from(revocationDate.atZone(ZoneId.systemDefault()).toInstant()),
								CRLReason.privilegeWithdrawn);
					}
				}
				basicOCSPRespBuilder.addResponse(certificateID, certificateStatus,
						Date.from(thisUpdate.atZone(ZoneId.systemDefault()).toInstant()),
						Date.from(nextUpdate.atZone(ZoneId.systemDefault()).toInstant()), null);
			}

			// basic response generation
			X509CertificateHolder[] chain = null;
			if (ocspRevocationService.ocspResponderCertificate != null) {
				chain = new X509CertificateHolder[] {
						new X509CertificateHolder(ocspRevocationService.ocspResponderCertificate.getEncoded()),
						new X509CertificateHolder(
								ocspRevocationService.certificationAuthority.getCertificate().getEncoded()) };
			}

			ContentSigner contentSigner = new JcaContentSignerBuilder(
					ocspRevocationService.certificationAuthority.getSignatureAlgorithm())
					.build(ocspRevocationService.ocspResponderPrivateKey);
			BasicOCSPResp basicOCSPResp = basicOCSPRespBuilder.build(contentSigner, chain,
					Date.from(now.atZone(ZoneId.systemDefault()).toInstant()));

			// response generation
			OCSPRespBuilder ocspRespBuilder = new OCSPRespBuilder();
			OCSPResp ocspResp = ocspRespBuilder.build(OCSPRespBuilder.SUCCESSFUL, basicOCSPResp);

			response.setContentType("application/ocsp-response");
			OutputStream outputStream = response.getOutputStream();
			IOUtils.write(ocspResp.getEncoded(), outputStream);
		}

		@Override
		public void init(ServletConfig config) throws ServletException {
			this.identifier = config.getInitParameter("identifier");
		}

		private OCSPRevocationService getOCSPRevocationService() {
			return ocspRevocationServices.get(this.identifier);
		}
	}

	@Override
	public void setCertificationAuthority(CertificationAuthority certificationAuthority) {
		this.certificationAuthority = certificationAuthority;
	}

	private boolean isUnknownCertificate(CertificateID certificateID) {
		for (X509Certificate certificate : this.certificationAuthority.getIssuedCertificates()) {
			if (certificate.getSerialNumber().equals(certificateID.getSerialNumber())) {
				return false;
			}
		}
		return true;
	}

	private LocalDateTime getRevocationDate(CertificateID certificateID) {
		for (Map.Entry<X509Certificate, LocalDateTime> revokedCertificateEntry : this.certificationAuthority
				.getRevokedCertificates().entrySet()) {
			X509Certificate revokedCertificate = revokedCertificateEntry.getKey();
			if (revokedCertificate.getSerialNumber().equals(certificateID.getSerialNumber())) {
				return revokedCertificateEntry.getValue();
			}
		}
		return null;
	}

	@Override
	public void setFailureBehavior(FailBehavior failBehavior) {
		this.failBehavior = failBehavior;
	}

	public String getOcspUrl() {
		return this.ocspUri;
	}
}
