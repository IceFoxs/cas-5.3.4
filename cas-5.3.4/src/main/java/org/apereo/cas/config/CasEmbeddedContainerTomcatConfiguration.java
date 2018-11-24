package org.apereo.cas.config;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.authenticator.BasicAuthenticator;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.valves.ExtendedAccessLogValve;
import org.apache.catalina.valves.SSLValve;
import org.apache.catalina.valves.rewrite.RewriteValve;
import org.apache.commons.lang3.StringUtils;
import org.apache.coyote.http2.Http2Protocol;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityCollection;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.apereo.cas.CasEmbeddedContainerUtils;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.core.web.tomcat.CasEmbeddedApacheTomcatAjpProperties;
import org.apereo.cas.configuration.model.core.web.tomcat.CasEmbeddedApacheTomcatBasicAuthenticationProperties;
import org.apereo.cas.configuration.model.core.web.tomcat.CasEmbeddedApacheTomcatExtendedAccessLogProperties;
import org.apereo.cas.configuration.model.core.web.tomcat.CasEmbeddedApacheTomcatHttpProperties;
import org.apereo.cas.configuration.model.core.web.tomcat.CasEmbeddedApacheTomcatHttpProxyProperties;
import org.apereo.cas.configuration.model.core.web.tomcat.CasEmbeddedApacheTomcatSslValveProperties;
import org.apereo.cas.configuration.support.Beans;
import org.apereo.cas.util.ResourceUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.AutoConfigureOrder;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.web.EmbeddedServletContainerAutoConfiguration;
import org.springframework.boot.autoconfigure.web.ServerProperties;
import org.springframework.boot.context.embedded.EmbeddedServletContainerCustomizer;
import org.springframework.boot.context.embedded.EmbeddedServletContainerFactory;
import org.springframework.boot.context.embedded.tomcat.TomcatEmbeddedServletContainerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.io.Resource;
import org.springframework.util.SocketUtils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;

/**
 * This is {@link CasEmbeddedContainerTomcatConfiguration}.
 *
 * @author Misagh Moayyed
 * @since 5.0.0
 */
@Configuration("casEmbeddedContainerTomcatConfiguration")
@EnableConfigurationProperties(CasConfigurationProperties.class)
@ConditionalOnProperty(name = CasEmbeddedContainerUtils.EMBEDDED_CONTAINER_CONFIG_ACTIVE, havingValue = "true")
@ConditionalOnClass(value = { Tomcat.class, Http2Protocol.class })
@AutoConfigureBefore(EmbeddedServletContainerAutoConfiguration.class)
@AutoConfigureOrder(Ordered.HIGHEST_PRECEDENCE)
@Slf4j
public class CasEmbeddedContainerTomcatConfiguration {
	@Autowired
	private ServerProperties serverProperties;

	@Autowired
	private CasConfigurationProperties casProperties;

	@ConditionalOnMissingBean(name = "casServletContainerFactory")
	@Bean
	public EmbeddedServletContainerFactory casServletContainerFactory() {
		return new CasTomcatEmbeddedServletContainerFactory(casProperties.getServer().getClustering());
	}

	@ConditionalOnMissingBean(name = "casTomcatEmbeddedServletContainerCustomizer")
	@Bean
	public EmbeddedServletContainerCustomizer casTomcatEmbeddedServletContainerCustomizer() {
		return configurableEmbeddedServletContainer -> {
			if (configurableEmbeddedServletContainer instanceof TomcatEmbeddedServletContainerFactory) {
				final TomcatEmbeddedServletContainerFactory tomcat = (TomcatEmbeddedServletContainerFactory) configurableEmbeddedServletContainer;
				configureAjp(tomcat);
				configureHttp(tomcat);
				configureHttpProxy(tomcat);
				configureExtendedAccessLogValve(tomcat);
				configureRewriteValve(tomcat);
				configureSSLValve(tomcat);
				configureBasicAuthn(tomcat);
			} else {
			}
		};
	}

	private void configureBasicAuthn(final TomcatEmbeddedServletContainerFactory tomcat) {
		final CasEmbeddedApacheTomcatBasicAuthenticationProperties basic = casProperties.getServer().getBasicAuthn();
		if (basic.isEnabled()) {
			tomcat.addContextCustomizers(ctx -> {
				final LoginConfig config = new LoginConfig();
				config.setAuthMethod("BASIC");
				ctx.setLoginConfig(config);

				basic.getSecurityRoles().forEach(ctx::addSecurityRole);

				basic.getAuthRoles().forEach(r -> {
					final SecurityConstraint constraint = new SecurityConstraint();
					constraint.addAuthRole(r);
					final SecurityCollection collection = new SecurityCollection();
					basic.getPatterns().forEach(collection::addPattern);
					constraint.addCollection(collection);
					ctx.addConstraint(constraint);
				});
			});
			tomcat.addContextValves(new BasicAuthenticator());
		}
	}

	private void configureRewriteValve(final TomcatEmbeddedServletContainerFactory tomcat) {
		final Resource res = casProperties.getServer().getRewriteValve().getLocation();
		if (ResourceUtils.doesResourceExist(res)) {

			final RewriteValve valve = new RewriteValve() {
				@Override
				@SneakyThrows
				protected synchronized void startInternal() throws LifecycleException {
					super.startInternal();
					try (InputStream is = res.getInputStream();
							InputStreamReader isr = new InputStreamReader(is, StandardCharsets.UTF_8);
							BufferedReader buffer = new BufferedReader(isr)) {
						parse(buffer);
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}
				}
			};
			valve.setAsyncSupported(true);
			valve.setEnabled(true);

			tomcat.addContextValves(valve);
		}
	}

	private void configureExtendedAccessLogValve(final TomcatEmbeddedServletContainerFactory tomcat) {
		final CasEmbeddedApacheTomcatExtendedAccessLogProperties ext = casProperties.getServer().getExtAccessLog();

		if (ext.isEnabled() && StringUtils.isNotBlank(ext.getPattern())) {
			final ExtendedAccessLogValve valve = new ExtendedAccessLogValve();
			valve.setPattern(ext.getPattern());

			if (StringUtils.isBlank(ext.getDirectory())) {
				valve.setDirectory(serverProperties.getTomcat().getAccesslog().getDirectory());
			} else {
				valve.setDirectory(ext.getDirectory());
			}
			valve.setPrefix(ext.getPrefix());
			valve.setSuffix(ext.getSuffix());
			valve.setAsyncSupported(true);
			valve.setEnabled(true);
			valve.setRotatable(true);
			valve.setBuffered(true);
			tomcat.addContextValves(valve);
			tomcat.addEngineValves(valve);
		}
	}

	private void configureHttp(final TomcatEmbeddedServletContainerFactory tomcat) {
		final CasEmbeddedApacheTomcatHttpProperties http = casProperties.getServer().getHttp();
		if (http.isEnabled()) {
			final Connector connector = new Connector(http.getProtocol());
			int port = http.getPort();
			if (port <= 0) {
				port = SocketUtils.findAvailableTcpPort();
			}
			connector.setPort(port);
			connector.addUpgradeProtocol(new Http2Protocol());

			http.getAttributes().forEach(connector::setAttribute);
			tomcat.addAdditionalTomcatConnectors(connector);
		}
	}

	private void configureHttpProxy(final TomcatEmbeddedServletContainerFactory tomcat) {
		final CasEmbeddedApacheTomcatHttpProxyProperties proxy = casProperties.getServer().getHttpProxy();
		if (proxy.isEnabled()) {
			tomcat.getTomcatConnectorCustomizers().add(connector -> {
				connector.setSecure(proxy.isSecure());
				connector.setScheme(proxy.getScheme());

				if (StringUtils.isNotBlank(proxy.getProtocol())) {
					connector.setProtocol(proxy.getProtocol());
				}
				if (proxy.getRedirectPort() > 0) {
					connector.setRedirectPort(proxy.getRedirectPort());
				}
				if (proxy.getProxyPort() > 0) {
					connector.setProxyPort(proxy.getProxyPort());
				}
				connector.addUpgradeProtocol(new Http2Protocol());

				proxy.getAttributes().forEach(connector::setAttribute);
			});
		} else {
		}
	}

	private void configureAjp(final TomcatEmbeddedServletContainerFactory tomcat) {
		final CasEmbeddedApacheTomcatAjpProperties ajp = casProperties.getServer().getAjp();
		if (ajp.isEnabled() && ajp.getPort() > 0) {
			final Connector ajpConnector = new Connector(ajp.getProtocol());
			ajpConnector.setProtocol(ajp.getProtocol());
			ajpConnector.setPort(ajp.getPort());
			ajpConnector.setSecure(ajp.isSecure());
			ajpConnector.setAllowTrace(ajp.isAllowTrace());
			ajpConnector.setScheme(ajp.getScheme());
			ajpConnector.setAsyncTimeout(Beans.newDuration(ajp.getAsyncTimeout()).toMillis());
			ajpConnector.setEnableLookups(ajp.isEnableLookups());
			ajpConnector.setMaxPostSize(ajp.getMaxPostSize());
			ajpConnector.addUpgradeProtocol(new Http2Protocol());

			if (ajp.getProxyPort() > 0) {
				ajpConnector.setProxyPort(ajp.getProxyPort());
			}

			if (ajp.getRedirectPort() > 0) {
				ajpConnector.setRedirectPort(ajp.getRedirectPort());
			}

			ajp.getAttributes().forEach(ajpConnector::setAttribute);

			tomcat.addAdditionalTomcatConnectors(ajpConnector);
		}
	}

	private void configureSSLValve(final TomcatEmbeddedServletContainerFactory tomcat) {
		final CasEmbeddedApacheTomcatSslValveProperties valveConfig = casProperties.getServer().getSslValve();

		if (valveConfig.isEnabled()) {
			final SSLValve valve = new SSLValve();
			valve.setSslCipherHeader(valveConfig.getSslCipherHeader());
			valve.setSslCipherUserKeySizeHeader(valveConfig.getSslCipherUserKeySizeHeader());
			valve.setSslClientCertHeader(valveConfig.getSslClientCertHeader());
			valve.setSslSessionIdHeader(valveConfig.getSslSessionIdHeader());
			tomcat.addContextValves(valve);
		}
	}
}
