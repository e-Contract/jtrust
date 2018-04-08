/*
 * Java Trust Project.
 * Copyright (C) 2018 e-Contract.be BVBA.
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
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.joda.time.DateTime;
import org.mortbay.jetty.servlet.ServletHolder;
import org.mortbay.jetty.testing.ServletTester;

public class CRLRevocationService implements RevocationService {

	private final String identifier;

	private String crlUri;

	private static final Map<String, CertificationAuthority> certificationAuthorities;

	static {
		certificationAuthorities = new HashMap<>();
	}

	public CRLRevocationService() {
		this.identifier = UUID.randomUUID().toString();
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
	public void addEndpoints(ServletTester servletTester) {
		String pathSpec = "/" + this.identifier + "/crl.der";
		ServletHolder servletHolder = servletTester.addServlet(CRLServlet.class, pathSpec);
		servletHolder.setInitParameter("identifier", this.identifier);
	}

	public static final class CRLServlet extends HttpServlet {

		private static final Log LOG = LogFactory.getLog(CRLServlet.class);

		private static final long serialVersionUID = 1L;

		private String identifier;

		@Override
		protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws ServletException, IOException {
			CertificationAuthority certificationAuthority = getCertificationAuthority();
			DateTime notBefore = new DateTime();
			DateTime notAfter = notBefore.plusDays(1);
			X509CRL crl;
			try {
				crl = PKITestUtils.generateCrl(certificationAuthority.getPrivateKey(),
						certificationAuthority.getCertificate(), notBefore, notAfter);
			} catch (Exception e) {
				LOG.error("error: " + e.getMessage(), e);
				throw new IOException(e);
			}
			OutputStream outputStream = resp.getOutputStream();
			try {
				IOUtils.write(crl.getEncoded(), outputStream);
			} catch (CRLException e) {
				throw new IOException(e);
			}
		}

		@Override
		public void init(ServletConfig config) throws ServletException {
			this.identifier = config.getInitParameter("identifier");
		}

		private CertificationAuthority getCertificationAuthority() {
			return certificationAuthorities.get(this.identifier);
		}
	}

	@Override
	public void started(String url) {
		this.crlUri = url + "/" + this.identifier + "/crl.der";
	}

	@Override
	public void setCertificationAuthority(CertificationAuthority certificationAuthority) {
		certificationAuthorities.put(this.identifier, certificationAuthority);
	}
}
