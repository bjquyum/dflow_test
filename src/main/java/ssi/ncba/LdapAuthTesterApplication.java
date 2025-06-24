package ssi.ncba;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
// import org.springframework.ldap.core.LdapTemplate;
// import org.springframework.ldap.query.LdapQuery;
// import static org.springframework.ldap.query.LdapQueryBuilder.query;

import org.springframework.context.annotation.Bean;
import javax.net.ssl.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Hashtable;

@SpringBootApplication
public class LdapAuthTesterApplication implements CommandLineRunner {

    // @Autowired
    // private LdapTemplate ldapTemplate;

    @Autowired
    private org.springframework.core.env.Environment env;

    private String inputLdapUrl;
    private String inputLdapBase;
    private String inputLdapUsername;
    private String inputLdapPassword;
    private String inputUserToAuth;
    private String inputUserPassword;

    public static void main(String[] args) {
        disableSslVerification(); // Disable SSL certificate validation (for testing only)
        SpringApplication.run(LdapAuthTesterApplication.class, args);
    }

    private void promptForLdapConfig() {
        try (java.util.Scanner scanner = new java.util.Scanner(System.in)) {
            String defUrl = env.getProperty("spring.ldap.urls", "");
            String defBase = env.getProperty("spring.ldap.base", "");
            String defBindUser = env.getProperty("spring.ldap.username", "");
            String defBindPass = env.getProperty("spring.ldap.password", "");

            System.out.print("LDAP URL [" + defUrl + "]: ");
            inputLdapUrl = scanner.nextLine().trim();
            if (inputLdapUrl.isEmpty()) inputLdapUrl = defUrl;

            System.out.print("LDAP Base DN [" + defBase + "]: ");
            inputLdapBase = scanner.nextLine().trim();
            if (inputLdapBase.isEmpty()) inputLdapBase = defBase;

            System.out.print("LDAP Bind Username [" + defBindUser + "]: ");
            inputLdapUsername = scanner.nextLine().trim();
            if (inputLdapUsername.isEmpty()) inputLdapUsername = defBindUser;

            System.out.print("LDAP Bind Password [hidden, press Enter to use default]: ");
            inputLdapPassword = scanner.nextLine();
            if (inputLdapPassword.isEmpty()) inputLdapPassword = defBindPass;

            System.out.print("Username to authenticate: ");
            inputUserToAuth = scanner.nextLine().trim();
            System.out.print("Password for user '" + inputUserToAuth + "': ");
            inputUserPassword = scanner.nextLine();
        }
    }

    public void run(String... args) {
        promptForLdapConfig();

        // // 0. Test if internet is working
        // try {
        //     java.net.InetAddress address = java.net.InetAddress.getByName("8.8.8.8");
        //     if (address.isReachable(2000)) {
        //         System.out.println("🌐 Internet connectivity: OK");
        //     } else {
        //         System.out.println("🌐 Internet connectivity: FAILED");
        //     }
        // } catch (Exception e) {
        //     System.out.println("🌐 Internet connectivity: FAILED (" + e.getMessage() + ")");
        // }

        // // 0.1 Test if machine can reach LDAP/LDAPS URL
        // String ldapHost = "192.168.52.100"; // from spring.ldap.urls
        // // String ldapHost = "172.31.47.49"; // from spring.ldap.urls
        // int[] ports = {389, 636}; // 389=LDAP, 636=LDAPS
        // for (int port : ports) {
        //     try (java.net.Socket socket = new java.net.Socket()) {
        //         socket.connect(new java.net.InetSocketAddress(ldapHost, port), 2000);
        //         System.out.println("🔗 Can reach " + ldapHost + ":" + port + " (" + (port == 389 ? "LDAP" : "LDAPS") + ")");
        //     } catch (Exception e) {
        //         System.out.println("🔗 Cannot reach " + ldapHost + ":" + port + " (" + (port == 389 ? "LDAP" : "LDAPS") + "): " + e.getMessage());
        //     }
        // }

        // // 1. Simple bind as 'beejez'
        // try {
        //     ldapTemplate.getContextSource().getContext(
        //         "CN=beejez,OU=Users,OU=bjquyum,DC=bjquyum,DC=local",
        //         "iam.Quyum2002"
        //     );
        //     System.out.println("✅ Simple bind to LDAP server as beejez succeeded.");
        // } catch (Exception e) {
        //     System.err.println("❌ Simple bind to LDAP server as beejez failed: " + e.getMessage());
        // }

        // // 1.1 Simple bind as 'mubarak'
        // try {
        //     ldapTemplate.getContextSource().getContext(
        //         "CN=mubarak,OU=Users,OU=bjquyum,DC=bjquyum,DC=local",
        //         "iam.Quyum2002"
        //     );
        //     System.out.println("✅ Simple bind to LDAP server as mubarak succeeded.");
        // } catch (Exception e) {
        //     System.err.println("❌ Simple bind to LDAP server as mubarak failed: " + e.getMessage());
        // }

        // // 2. Authentication test for 'beejez' using distinguishedName (DN)
        // try {
        //     boolean authenticated = ldapTemplate.authenticate(
        //     "",
        //     "distinguishedName=CN=beejez,OU=Users,OU=bjquyum,DC=bjquyum,DC=local",
        //     "iam.Quyum2002"
        //     );
        //     if (authenticated) {
        //     System.out.println("✅ Successfully authenticated to LDAP as beejez (distinguishedName) with the provided password.");
        //     } else {
        //     System.out.println("❌ Failed to authenticate to LDAP as beejez (distinguishedName): Invalid credentials or insufficient permissions.");
        //     }
        // } catch (Exception e) {
        //     System.err.println("❌ Failed to authenticate to LDAP as beejez (distinguishedName): " + e.getMessage());
        // }

        // // 2.1 Authentication test for 'mubarak' using distinguishedName (DN)
        // try {
        //     boolean authenticated = ldapTemplate.authenticate(
        //     "",
        //     "distinguishedName=CN=mubarak,OU=Users,OU=bjquyum,DC=bjquyum,DC=local",
        //     "iam.Quyum2002"
        //     );
        //     if (authenticated) {
        //     System.out.println("✅ Successfully authenticated to LDAP as mubarak (distinguishedName) with the provided password.");
        //     } else {
        //     System.out.println("❌ Failed to authenticate to LDAP as mubarak (distinguishedName): Invalid credentials or insufficient permissions.");
        //     }
        // } catch (Exception e) {
        //     System.err.println("❌ Failed to authenticate to LDAP as mubarak (distinguishedName): " + e.getMessage());
        // }

        // // 2.2 Authentication test for 'beejez' using userPrincipalName
        // try {
        //     boolean authenticated = ldapTemplate.authenticate(
        //     "OU=Users,OU=bjquyum,DC=bjquyum,DC=local",
        //     "(userPrincipalName=beejez@bjquyum.local)",
        //     "iam.Quyum2002"
        //     );
        //     if (authenticated) {
        //     System.out.println("✅ Successfully authenticated to LDAP as beejez (userPrincipalName) with the provided password.");
        //     } else {
        //     System.out.println("❌ Failed to authenticate to LDAP as beejez (userPrincipalName): Invalid credentials or insufficient permissions.");
        //     }
        // } catch (Exception e) {
        //     System.err.println("❌ Failed to authenticate to LDAP as beejez (userPrincipalName): " + e.getMessage());
        // }

        // // 2.3 Authentication test for 'mubarak' using userPrincipalName
        // try {
        //     boolean authenticated = ldapTemplate.authenticate(
        //     "OU=Users,OU=bjquyum,DC=bjquyum,DC=local",
        //     "(userPrincipalName=mubarak@bjquyum.local)",
        //     "iam.Quyum2002"
        //     );
        //     if (authenticated) {
        //     System.out.println("✅ Successfully authenticated to LDAP as mubarak (userPrincipalName) with the provided password.");
        //     } else {
        //     System.out.println("❌ Failed to authenticate to LDAP as mubarak (userPrincipalName): Invalid credentials or insufficient permissions.");
        //     }
        // } catch (Exception e) {
        //     System.err.println("❌ Failed to authenticate to LDAP as mubarak (userPrincipalName): " + e.getMessage());
        // }

        // // 2.4 Authentication test for 'beejez' using sAMAccountName
        // try {
        //     boolean authenticated = ldapTemplate.authenticate(
        //     "OU=Users,OU=bjquyum,DC=bjquyum,DC=local",
        //     "(sAMAccountName=beejez)",
        //     "iam.Quyum2002"
        //     );
        //     if (authenticated) {
        //     System.out.println("✅ Successfully authenticated to LDAP as beejez (sAMAccountName) with the provided password.");
        //     } else {
        //     System.out.println("❌ Failed to authenticate to LDAP as beejez (sAMAccountName): Invalid credentials or insufficient permissions.");
        //     }
        // } catch (Exception e) {
        //     System.err.println("❌ Failed to authenticate to LDAP as beejez (sAMAccountName): " + e.getMessage());
        // }

        // // 2.5 Authentication test for 'mubarak' using sAMAccountName
        // try {
        //     boolean authenticated = ldapTemplate.authenticate(
        //     "OU=Users,OU=bjquyum,DC=bjquyum,DC=local",
        //     "(sAMAccountName=mubarak)",
        //     "iam.Quyum2002"
        //     );
        //     if (authenticated) {
        //     System.out.println("✅ Successfully authenticated to LDAP as mubarak (sAMAccountName) with the provided password.");
        //     } else {
        //     System.out.println("❌ Failed to authenticate to LDAP as mubarak (sAMAccountName): Invalid credentials or insufficient permissions.");
        //     }
        // } catch (Exception e) {
        //     System.err.println("❌ Failed to authenticate to LDAP as mubarak (sAMAccountName): " + e.getMessage());
        // }

        // // 3. Try to use Spring Security's LdapAuthenticationProvider for mubarak
        // try {
        //     org.springframework.security.ldap.DefaultSpringSecurityContextSource contextSource =
        //     new org.springframework.security.ldap.DefaultSpringSecurityContextSource("ldap://172.31.47.49:389/OU=Users,OU=bjquyum,DC=bjquyum,DC=local");
        //     contextSource.afterPropertiesSet();
        //     org.springframework.security.ldap.authentication.BindAuthenticator authenticator =
        //     new org.springframework.security.ldap.authentication.BindAuthenticator(contextSource);
        //     authenticator.setUserDnPatterns(new String[]{"CN={0},OU=Users,OU=bjquyum,DC=bjquyum,DC=local"});
        //     org.springframework.security.ldap.authentication.LdapAuthenticationProvider provider =
        //     new org.springframework.security.ldap.authentication.LdapAuthenticationProvider(authenticator);
        //     org.springframework.security.core.Authentication auth =
        //     provider.authenticate(
        //         new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
        //         "mubarak",
        //         "iam.Quyum2002"
        //         )
        //     );
        //     if (auth.isAuthenticated()) {
        //     System.out.println("✅ Spring Security LdapAuthenticationProvider: Authentication as mubarak successful.");
        //     } else {
        //     System.out.println("❌ Spring Security LdapAuthenticationProvider: Authentication as mubarak failed.");
        //     }
        // } catch (Exception e) {
        //     System.err.println("❌ Spring Security LdapAuthenticationProvider failed for mubarak: " + e.getMessage());
        // }

        // // 3.1 Try to use Spring Security's LdapAuthenticationProvider for beejez
        // try {
        //     org.springframework.security.ldap.DefaultSpringSecurityContextSource contextSource =
        //     new org.springframework.security.ldap.DefaultSpringSecurityContextSource("ldap://172.31.47.49:389/OU=Users,OU=bjquyum,DC=bjquyum,DC=local");
        //     contextSource.afterPropertiesSet();
        //     org.springframework.security.ldap.authentication.BindAuthenticator authenticator =
        //     new org.springframework.security.ldap.authentication.BindAuthenticator(contextSource);
        //     authenticator.setUserDnPatterns(new String[]{"CN={0},OU=Users,OU=bjquyum,DC=bjquyum,DC=local"});
        //     org.springframework.security.ldap.authentication.LdapAuthenticationProvider provider =
        //     new org.springframework.security.ldap.authentication.LdapAuthenticationProvider(authenticator);
        //     org.springframework.security.core.Authentication auth =
        //     provider.authenticate(
        //         new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
        //         "beejez",
        //         "iam.Quyum2002"
        //         )
        //     );
        //     if (auth.isAuthenticated()) {
        //     System.out.println("✅ Spring Security LdapAuthenticationProvider: Authentication as beejez successful.");
        //     } else {
        //     System.out.println("❌ Spring Security LdapAuthenticationProvider: Authentication as beejez failed.");
        //     }
        // } catch (Exception e) {
        //     System.err.println("❌ Spring Security LdapAuthenticationProvider failed for beejez: " + e.getMessage());
        // }

        // 4. Test custom contextSource authenticate method for beejez and mubarak
        // authenticateWithContextSource("beejez", "iam.Quyum2002");
        // authenticateWithContextSource("mubarak", "iam.Quyum2002");
        
        System.out.println("===============================================");
        authenticateWithContextSource(inputUserToAuth, inputUserPassword);
        fetchUserAttributes(inputUserToAuth);
        fetchUserDataWithJndi(inputUserToAuth);
        System.out.println("===============================================");

        // Fetch and print some attributes for a user after successful authentication
        // fetchUserAttributes("beejez");
        // fetchUserAttributes("mubarak");

        // Fetch user data using JNDI for beejez and mubarak
        // fetchUserDataWithJndi("beejez");
        // fetchUserDataWithJndi("mubarak");
    }

    @Bean
    public org.springframework.ldap.core.support.LdapContextSource contextSource() {
        org.springframework.ldap.core.support.LdapContextSource contextSource = new org.springframework.ldap.core.support.LdapContextSource();
        contextSource.setUrl(env.getRequiredProperty("spring.ldap.urls"));
        contextSource.setBase(env.getRequiredProperty("spring.ldap.base"));
        contextSource.setUserDn(env.getRequiredProperty("spring.ldap.username"));
        contextSource.setPassword(env.getRequiredProperty("spring.ldap.password"));
        // Follow referrals to avoid 'Unprocessed Continuation Reference(s)'
        java.util.Hashtable<String, Object> envProps = new java.util.Hashtable<>();
        envProps.put("java.naming.referral", "follow");
        contextSource.setBaseEnvironmentProperties(envProps);
        return contextSource;
    }

    @Bean
    public org.springframework.ldap.core.LdapTemplate customLdapTemplate() {
        return new org.springframework.ldap.core.LdapTemplate(contextSource());
    }

    public void authenticateWithContextSource(String username, String password) {
        try {
            String dn;
            dn = "CN=" + username + ",OU=R18,OU=ServiceAccounts,DC=ncbabank,DC=local"; // Example for R18
            // dn = "CN=" + username + ",OU=Users,OU=bjquyum,DC=bjquyum,DC=local";
            contextSource().getContext(dn, password);
            System.out.println("✅ Custom contextSource: Simple bind as '" + username + "' succeeded.");
        } catch (Exception e) {
            System.err.println("❌ Custom contextSource: Simple bind as '" + username + "' failed: " + e.getMessage());
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

    // Fetch and print some attributes for a user after successful authentication
    public void fetchUserAttributes(String username) {
        try {
            // Use the domain base and filter for user objects to avoid NO_OBJECT errors
            // String searchBase = "DC=bjquyum,DC=local";
            org.springframework.ldap.query.LdapQuery query = org.springframework.ldap.query.LdapQueryBuilder.query()
                    .where("CN").is(username);

            java.util.List<String> results = customLdapTemplate().search(query, (javax.naming.directory.Attributes attrs) -> {
                String dn = attrs.get("distinguishedName") != null ? attrs.get("distinguishedName").get().toString() : "No DN";
                String displayName = attrs.get("displayName") != null ? attrs.get("displayName").get().toString() : "";
                String mail = attrs.get("mail") != null ? attrs.get("mail").get().toString() : "";
                String userPrincipalName = attrs.get("userPrincipalName") != null ? attrs.get("userPrincipalName").get().toString() : "";
                String sn = attrs.get("sn") != null ? attrs.get("sn").get().toString() : "";
                String givenName = attrs.get("givenName") != null ? attrs.get("givenName").get().toString() : "";
                return "dn=" + dn + ", displayName=" + displayName + ", mail=" + mail + ", userPrincipalName=" + userPrincipalName + ", surname=" + sn + ", givenName=" + givenName;
            });

            if (!results.isEmpty()) {
                System.out.println("🔍 User attributes for '" + username + "': " + results);
            } else {
                System.out.println("🔍 No user attributes found for '" + username + "'.");
            }
        } catch (Exception e) {
            System.err.println("❌ Error fetching user attributes for '" + username + "': " + e.getMessage());
        }
    }

    public void fetchUserDataWithJndi(String searchCn) {
        String ldapUrl = env.getRequiredProperty("spring.ldap.urls");
        String baseDn = env.getRequiredProperty("spring.ldap.base");
        String username = env.getRequiredProperty("spring.ldap.username");
        String password = env.getRequiredProperty("spring.ldap.password");
        String searchFilter = "(cn=" + searchCn + ")";

        try {
            Hashtable<String, String> jndiEnv = new Hashtable<>();
            jndiEnv.put(javax.naming.Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            jndiEnv.put(javax.naming.Context.PROVIDER_URL, ldapUrl);
            jndiEnv.put(javax.naming.Context.SECURITY_AUTHENTICATION, "simple");
            jndiEnv.put(javax.naming.Context.SECURITY_PRINCIPAL, username);
            jndiEnv.put(javax.naming.Context.SECURITY_CREDENTIALS, password);

            javax.naming.directory.DirContext ctx = new javax.naming.directory.InitialDirContext(jndiEnv);

            javax.naming.directory.SearchControls controls = new javax.naming.directory.SearchControls();
            controls.setSearchScope(javax.naming.directory.SearchControls.SUBTREE_SCOPE);

            javax.naming.NamingEnumeration<javax.naming.directory.SearchResult> results =
                    ctx.search(baseDn, searchFilter, controls);

            while (results.hasMore()) {
                javax.naming.directory.SearchResult result = results.next();
                javax.naming.directory.Attributes attrs = result.getAttributes();

                System.out.println("Distinguished Name: " + result.getNameInNamespace());
                javax.naming.NamingEnumeration<? extends javax.naming.directory.Attribute> attributes = attrs.getAll();
                while (attributes.hasMore()) {
                    javax.naming.directory.Attribute attr = attributes.next();
                    System.out.println(attr.getID() + ": " + attr.get());
                }
            }

            ctx.close();
        } catch (Exception e) {
            System.err.println("❌ Error fetching user data with JNDI: " + e.getMessage());
        }
    }
}
