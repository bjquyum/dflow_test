package ssi.ncba;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.ldap.core.LdapTemplate;
// import org.springframework.ldap.query.LdapQuery;
// import static org.springframework.ldap.query.LdapQueryBuilder.query;

import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;

@SpringBootApplication
public class LdapAuthTesterApplication implements CommandLineRunner {

    @Autowired
    private LdapTemplate ldapTemplate;

    public static void main(String[] args) {
        disableSslVerification(); // Disable SSL certificate validation (for testing only)
        SpringApplication.run(LdapAuthTesterApplication.class, args);
    }

    @Override
    public void run(String... args) {
        // 0. Test if internet is working
        try {
            java.net.InetAddress address = java.net.InetAddress.getByName("8.8.8.8");
            if (address.isReachable(2000)) {
                System.out.println("🌐 Internet connectivity: OK");
            } else {
                System.out.println("🌐 Internet connectivity: FAILED");
            }
        } catch (Exception e) {
            System.out.println("🌐 Internet connectivity: FAILED (" + e.getMessage() + ")");
        }

        // 0.1 Test if machine can reach LDAP/LDAPS URL
        String ldapHost = "192.168.52.100"; // from spring.ldap.urls
        int[] ports = {389, 636}; // 389=LDAP, 636=LDAPS
        for (int port : ports) {
            try (java.net.Socket socket = new java.net.Socket()) {
                socket.connect(new java.net.InetSocketAddress(ldapHost, port), 2000);
                System.out.println("🔗 Can reach " + ldapHost + ":" + port + " (" + (port == 389 ? "LDAP" : "LDAPS") + ")");
            } catch (Exception e) {
                System.out.println("🔗 Cannot reach " + ldapHost + ":" + port + " (" + (port == 389 ? "LDAP" : "LDAPS") + "): " + e.getMessage());
            }
        }

        // 1. Simple bind (anonymous or with configured user)
        try {
            ldapTemplate.list("");
            System.out.println("✅ Simple bind to LDAP server succeeded.");
        } catch (Exception e) {
            System.err.println("❌ Simple bind to LDAP server failed: " + e.getMessage());
            return;
        }

        // 2. Attempt to authenticate (bind) with the configured username and password
        try {
            boolean authenticated = ldapTemplate.authenticate(
                "",
                "(cn=TZSStatutoryReporting)",
                null
            );
            if (authenticated) {
                System.out.println("✅ Successfully authenticated to LDAP with the provided credentials.");
            } else {
                System.out.println("❌ Failed to authenticate to LDAP: Invalid credentials or insufficient permissions.");
            }
        } catch (Exception e) {
            System.err.println("❌ Failed to authenticate to LDAP: " + e.getMessage());
        }

        // 3. Try to use Spring Security's LdapAuthenticationProvider
        try {
            org.springframework.security.ldap.authentication.LdapAuthenticationProvider provider =
                new org.springframework.security.ldap.authentication.LdapAuthenticationProvider(
                    new org.springframework.security.ldap.authentication.BindAuthenticator(
                        org.springframework.security.ldap.DefaultSpringSecurityContextSource.class
                            .getConstructor(String.class)
                            .newInstance("ldap://192.168.52.100:389")
                    )
                );
            org.springframework.security.core.Authentication auth =
                provider.authenticate(
                    new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
                        "CN=TZSStatutoryReporting,OU=R18,OU=ServiceAccounts,DC=ncbabank,DC=local",
                        "SvDG61Z@State@255"
                    )
                );
            if (auth.isAuthenticated()) {
                System.out.println("✅ Spring Security LdapAuthenticationProvider: Authentication successful.");
            } else {
                System.out.println("❌ Spring Security LdapAuthenticationProvider: Authentication failed.");
            }
        } catch (Exception e) {
            System.err.println("❌ Spring Security LdapAuthenticationProvider failed: " + e.getMessage());
        }
    }

    // Trust all SSL certs – NOT FOR PRODUCTION USE!
    private static void disableSslVerification() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                    new X509TrustManager() {
                        public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                        public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                    }
            };

            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new SecureRandom());
            HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
        } catch (Exception e) {
            System.err.println("⚠️ Failed to disable SSL verification: " + e.getMessage());
        }
    }
}
