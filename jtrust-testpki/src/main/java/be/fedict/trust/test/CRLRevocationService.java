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
import java.security.PrivateKey;
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
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.bc.BcECContentSignerBuilder;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CRL revocation service implementation.
 * 
 * @author Frank Cornelis
 *
 */
public class CRLRevocationService implements RevocationService, FailableEndpoint {

	private final String identifier;

	private BigInteger crlNumber;

	private String crlUri;

	private CertificationAuthority certificationAuthority;

	private FailBehavior failBehavior;

	private static final Map<String, CRLRevocationService> crlRevocationServices;

	static {
		crlRevocationServices = new HashMap<>();
	}

	/**
	 * Default constructor.
	 */
	public CRLRevocationService() {
		this.identifier = UUID.randomUUID().toString();
		this.crlNumber = BigInteger.ONE;
		crlRevocationServices.put(this.identifier, this);
	}

	@Override
	public void addExtension(X509v3CertificateBuilder x509v3CertificateBuilder) throws Exception {
		GeneralName generalName = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(this.crlUri));
		GeneralNames generalNames = new GeneralNames(generalName);
		DistributionPointName distPointName = new DistributionPointName(generalNames);
		DistributionPoint distPoint = new DistributionPoint(distPointName, null, null);
		DistributionPoint[] crlDistPoints = new DistributionPoint[] { distPoint };
		CRLDistPoint crlDistPoint = new CRLDistPoint(crlDistPoints);
		x509v3CertificateBuilder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);
	}

	@Override
	public void addEndpoints(ServletContextHandler context) {
		String pathSpec = "/" + this.identifier + "/crl.der";
		ServletHolder servletHolder = context.addServlet(CRLServlet.class, pathSpec);
		servletHolder.setInitParameter("identifier", this.identifier);
	}

	public static final class CRLServlet extends HttpServlet {

		private static final Logger LOGGER = LoggerFactory.getLogger(CRLServlet.class);

		private static final long serialVersionUID = 1L;

		private String identifier;

		@Override
		protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
			CRLRevocationService crlRevocationService = getCRLRevocationService();
			if (null != crlRevocationService.failBehavior && crlRevocationService.failBehavior.fail()) {
				throw new IOException("failing CRL endpoint");
			}
			CertificationAuthority certificationAuthority = crlRevocationService.certificationAuthority;
			try {
				// make sure we first get the CA certificate, so it gets generated before our
				// CRL notBefore
				PrivateKey caPrivateKey = certificationAuthority.getPrivateKey();
				X509Certificate caCertificate = certificationAuthority.getCertificate();
				Clock clock = certificationAuthority.getClock();
				LocalDateTime now = clock.getTime();
				// make sure the CRL is younger than the "now" of the world
				LocalDateTime thisUpdate = now.minusMinutes(1);
				LocalDateTime nextUpdate = now.plusDays(1);

				X500Name issuerName = new X500Name(caCertificate.getSubjectX500Principal().toString());
				X509v2CRLBuilder x509v2crlBuilder = new X509v2CRLBuilder(issuerName,
						Date.from(thisUpdate.atZone(ZoneId.systemDefault()).toInstant()));
				x509v2crlBuilder.setNextUpdate(Date.from(nextUpdate.atZone(ZoneId.systemDefault()).toInstant()));

				for (Map.Entry<X509Certificate, LocalDateTime> revokedCertificateEntry : certificationAuthority
						.getRevokedCertificates().entrySet()) {
					X509Certificate revokedCertificate = revokedCertificateEntry.getKey();
					LocalDateTime revocationDate = revokedCertificateEntry.getValue();
					x509v2crlBuilder.addCRLEntry(revokedCertificate.getSerialNumber(),
							Date.from(revocationDate.atZone(ZoneId.systemDefault()).toInstant()),
							CRLReason.privilegeWithdrawn);
				}

				JcaX509ExtensionUtils extensionUtils = new JcaX509ExtensionUtils();
				x509v2crlBuilder.addExtension(Extension.authorityKeyIdentifier, false,
						extensionUtils.createAuthorityKeyIdentifier(caCertificate));
				x509v2crlBuilder.addExtension(Extension.cRLNumber, false,
						new CRLNumber(crlRevocationService.crlNumber));
				crlRevocationService.crlNumber = crlRevocationService.crlNumber.add(BigInteger.ONE);

				AlgorithmIdentifier sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder()
						.find(certificationAuthority.getSignatureAlgorithm());
				AlgorithmIdentifier digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId);
				AsymmetricKeyParameter asymmetricKeyParameter = PrivateKeyFactory.createKey(caPrivateKey.getEncoded());

				ContentSigner contentSigner;
				if (certificationAuthority.getSignatureAlgorithm().contains("RSA")) {
					contentSigner = new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
				} else {
					contentSigner = new BcECContentSignerBuilder(sigAlgId, digAlgId).build(asymmetricKeyParameter);
				}

				X509CRLHolder x509crlHolder = x509v2crlBuilder.build(contentSigner);
				byte[] crlValue = x509crlHolder.getEncoded();
				OutputStream outputStream = resp.getOutputStream();
				IOUtils.write(crlValue, outputStream);
			} catch (Exception e) {
				LOGGER.error("error: " + e.getMessage(), e);
				throw new IOException(e);
			}
		}

		@Override
		public void init(ServletConfig config) throws ServletException {
			this.identifier = config.getInitParameter("identifier");
		}

		private CRLRevocationService getCRLRevocationService() {
			return crlRevocationServices.get(this.identifier);
		}
	}

	@Override
	public void started(String url) {
		this.crlUri = url + "/" + this.identifier + "/crl.der";
	}

	@Override
	public void setCertificationAuthority(CertificationAuthority certificationAuthority) {
		this.certificationAuthority = certificationAuthority;
	}

	@Override
	public void setFailureBehavior(FailBehavior failBehavior) {
		this.failBehavior = failBehavior;
	}
}
