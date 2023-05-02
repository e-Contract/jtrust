/*
 * Java Trust Project.
 * Copyright (C) 2009 FedICT.
 * Copyright (C) 2020-2023 e-Contract.be BV.
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

package test.integ.be.fedict.trust;

import java.io.IOException;
import java.io.OutputStream;
import java.net.URI;
import java.security.KeyPair;
import java.security.Security;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import be.fedict.trust.crl.OnlineCrlRepository;
import be.fedict.trust.test.PKIBuilder;

public class OnlineCrlRepositoryTest {

	private static final Logger LOGGER = LoggerFactory.getLogger(OnlineCrlRepositoryTest.class);

	private Server server;

	private URI crlUri;

	private Date validationDate;

	private OnlineCrlRepository testedInstance;

	@BeforeAll
	public static void oneTimeSetUp() throws Exception {
		Security.addProvider(new BouncyCastleProvider());
	}

	@BeforeEach
	public void setUp() throws Exception {
		this.server = new Server(0);
		ServletContextHandler servletContextHandler = new ServletContextHandler();
		servletContextHandler.setContextPath("/pki");
		String pathSpec = "/test.crl";
		servletContextHandler.addServlet(CrlRepositoryTestServlet.class, pathSpec);
		this.server.setHandler(servletContextHandler);
		this.server.start();

		ServerConnector serverConnector = (ServerConnector) this.server.getConnectors()[0];
		int port = serverConnector.getLocalPort();
		String servletUrl = "http://localhost:" + port + "/pki";
		this.crlUri = new URI(servletUrl + pathSpec);
		this.validationDate = new Date();

		this.testedInstance = new OnlineCrlRepository();

		CrlRepositoryTestServlet.reset();
	}

	@AfterEach
	public void tearDown() throws Exception {
		this.server.stop();
	}

	@Test
	public void testDownloadCrlPerformance() throws Exception {
		// setup
		KeyPair keyPair = new PKIBuilder.KeyPairBuilder().build();
		X509Certificate certificate = new PKIBuilder.CertificateBuilder(keyPair).withSubjectName("CN=Test")
				.withValidityMonths(1).build();

		X509CRL crl = new PKIBuilder.CRLBuilder(keyPair.getPrivate(), certificate).build();
		CrlRepositoryTestServlet.setCrlData(crl.getEncoded());

		// operate
		long t0 = System.currentTimeMillis();
		final int COUNT = 50 * 1000;
		for (int idx = 0; idx < COUNT; idx++) {
			try {
				this.testedInstance.findCrl(this.crlUri, certificate, this.validationDate);
			} catch (Exception ex) {
				LOGGER.error("CRL download error: " + ex.getMessage(), ex);
				LOGGER.debug("counter: {}", idx);
				break;
			}
		}
		long t1 = System.currentTimeMillis();
		double dt = ((double) t1 - t0) / COUNT;
		LOGGER.debug("dt: {} ms", dt);
	}

	public static class CrlRepositoryTestServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		private static final Logger LOGGER = LoggerFactory.getLogger(CrlRepositoryTestServlet.class);

		private static int responseStatus;

		private static byte[] crlData;

		public static void reset() {
			CrlRepositoryTestServlet.responseStatus = 0;
			CrlRepositoryTestServlet.crlData = null;
		}

		public static void setResponseStatus(int responseStatus) {
			CrlRepositoryTestServlet.responseStatus = responseStatus;
		}

		public static void setCrlData(byte[] crlData) {
			CrlRepositoryTestServlet.crlData = crlData;
		}

		@Override
		protected void doGet(HttpServletRequest request, HttpServletResponse response)
				throws ServletException, IOException {
			LOGGER.debug("doGet");
			if (null != CrlRepositoryTestServlet.crlData) {
				OutputStream outputStream = response.getOutputStream();
				IOUtils.write(CrlRepositoryTestServlet.crlData, outputStream);
			}
			if (0 != CrlRepositoryTestServlet.responseStatus) {
				response.setStatus(CrlRepositoryTestServlet.responseStatus);
			}
		}
	}
}
