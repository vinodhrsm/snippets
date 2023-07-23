Sure! Here's the source code for implementing JWT generation and setting the token in the header using `AuthenticationSuccessHandler` in Spring Framework 5.0 (without Spring Boot). Additionally, I'll provide unit test cases using JUnit and Mockito for the authentication process.

1. Configure your Spring Context:

Create a configuration class to define your Spring context and set up the LDAP authentication provider.

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private LdapUserDetailsService ldapUserDetailsService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(ldapUserDetailsService).passwordEncoder(passwordEncoder());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests().anyRequest().authenticated()
            .and().formLogin()
            .successHandler(jwtAuthenticationSuccessHandler)
            .and().apply(new JwtConfigurer(jwtTokenProvider));
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
```

2. Implement LDAP UserDetailsService:

Create a custom `LdapUserDetailsService` to fetch user details from LDAP and convert them to Spring's `UserDetails` format.

```java
@Service
public class LdapUserDetailsService implements UserDetailsService {

    @Autowired
    private LdapTemplate ldapTemplate;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        LdapUser user = ldapTemplate.findOne(
                LdapQueryBuilder.query().where("uid").is(username),
                LdapUser.class);

        if (user == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        // Assuming "uid" is the username attribute and "userPassword" is the password attribute in LDAP
        return User.withUsername(user.getUid())
                .password(user.getUserPassword())
                .authorities(Collections.emptyList())
                .build();
    }
}
```

3. Create a JWT Token Provider:

Implement the `JwtTokenProvider` class to generate and validate JWT tokens using asymmetric keys.

```java
@Component
public class JwtTokenProvider {

    @Value("${jwt.privateKey}")
    private String privateKey;

    @Value("${jwt.publicKey}")
    private String publicKey;

    @Value("${jwt.expirationTime}")
    private int expirationTime;

    private KeyPair keyPair;

    @PostConstruct
    public void init() {
        keyPair = loadKeyPair();
    }

    private KeyPair loadKeyPair() {
        // Load the keys from properties or any secure location
        // Implement the loading logic based on your specific use case
        // For simplicity, we'll assume the keys are provided in Base64 encoded format
        // You should use a more secure approach to manage keys in production
        byte[] privateKeyBytes = Base64.getDecoder().decode(privateKey);
        byte[] publicKeyBytes = Base64.getDecoder().decode(publicKey);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return new KeyPair(keyFactory.generatePublic(publicKeySpec), keyFactory.generatePrivate(privateKeySpec));
    }

    public String generateToken(String username) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationTime * 1000);

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiration)
                .signWith(keyPair.getPrivate(), SignatureAlgorithm.RS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(keyPair.getPublic()).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public Authentication getAuthentication(String token) {
        Claims claims = Jwts.parserBuilder().setSigningKey(keyPair.getPublic()).build().parseClaimsJws(token).getBody();
        String username = claims.getSubject();
        if (username != null) {
            return new UsernamePasswordAuthenticationToken(username, null, Collections.emptyList());
        }
        return null;
    }
}
```

4. Implement the JWT Configuration:

Create a configuration class for JWT token handling.

```java
@Configuration
public class JwtConfiguration {

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Bean
    public JwtFilter jwtFilter() {
        return new JwtFilter(jwtTokenProvider);
    }

    @Bean
    public JwtAuthenticationSuccessHandler jwtAuthenticationSuccessHandler() {
        return new JwtAuthenticationSuccessHandler(jwtTokenProvider);
    }
}
```

5. Create a JWT Filter:

Implement the `JwtFilter` class to validate the JWT token in incoming requests.

```java
public class JwtFilter extends OncePerRequestFilter {

    private JwtTokenProvider jwtTokenProvider;

    public JwtFilter(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String token = extractToken(request);
        if (token != null) {
            try {
                if (jwtTokenProvider.validateToken(token)) {
                    Authentication authentication = jwtTokenProvider.getAuthentication(token);
                    if (authentication != null) {
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }
            } catch (JwtException e) {
                // Token is invalid or expired
            }
        }
        filterChain.doFilter(request, response);
    }

    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
```

6. Implement the JwtAuthenticationSuccessHandler:

Create a custom `JwtAuthenticationSuccessHandler` to set the JWT token in the header after successful authentication.

```java
public class JwtAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private JwtTokenProvider jwtTokenProvider;

    public JwtAuthenticationSuccessHandler(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        String username = authentication.getName();
        String token = jwtTokenProvider.generateToken(username);
        response.addHeader("Authorization", "Bearer " + token);
    }
}
```

7. Implement Unit Test Cases:

Now let's create the unit test cases using JUnit and Mockito for the authentication process.

```java
@RunWith(MockitoJUnitRunner.class)
public class LdapUserDetailsServiceTest {

    @Mock
    private LdapTemplate ldapTemplate;

    @InjectMocks
    private LdapUserDetailsService userDetailsService;

    @Test
    public void testLoadUserByUsername() {
        String validUsername = "validUsername";
        String validPassword = "validPassword";

        LdapUser ldapUser = new LdapUser();
        ldapUser.setUid(validUsername

);
        ldapUser.setUserPassword(new BCryptPasswordEncoder().encode(validPassword));

        when(ldapTemplate.findOne(any(LdapQuery.class), eq(LdapUser.class))).thenReturn(ldapUser);

        UserDetails userDetails = userDetailsService.loadUserByUsername(validUsername);

        assertEquals(validUsername, userDetails.getUsername());
        assertTrue(new BCryptPasswordEncoder().matches(validPassword, userDetails.getPassword()));
        assertTrue(userDetails.getAuthorities().isEmpty());
    }

    @Test(expected = UsernameNotFoundException.class)
    public void testLoadUserByUsernameUserNotFound() {
        String invalidUsername = "invalidUsername";

        when(ldapTemplate.findOne(any(LdapQuery.class), eq(LdapUser.class))).thenReturn(null);

        userDetailsService.loadUserByUsername(invalidUsername);
    }
}
```

```java
@RunWith(MockitoJUnitRunner.class)
public class JwtTokenProviderTest {

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Test
    public void testGenerateToken() {
        String validUsername = "validUsername";
        when(jwtTokenProvider.generateToken(validUsername)).thenCallRealMethod();

        String token = jwtTokenProvider.generateToken(validUsername);

        assertNotNull(token);
    }

    @Test
    public void testValidateToken() {
        String validToken = "validToken";
        when(jwtTokenProvider.validateToken(validToken)).thenCallRealMethod();

        boolean isValid = jwtTokenProvider.validateToken(validToken);

        assertTrue(isValid);
    }

    @Test
    public void testValidateTokenInvalid() {
        String invalidToken = "invalidToken";
        when(jwtTokenProvider.validateToken(invalidToken)).thenCallRealMethod();

        boolean isValid = jwtTokenProvider.validateToken(invalidToken);

        assertFalse(isValid);
    }

    @Test
    public void testGetAuthentication() {
        String validToken = "validToken";
        String validUsername = "validUsername";

        when(jwtTokenProvider.getAuthentication(validToken)).thenCallRealMethod();
        when(jwtTokenProvider.validateToken(validToken)).thenReturn(true);

        Authentication authentication = jwtTokenProvider.getAuthentication(validToken);

        assertNotNull(authentication);
        assertEquals(validUsername, authentication.getName());
        assertTrue(authentication.getAuthorities().isEmpty());
    }

    @Test
    public void testGetAuthenticationInvalid() {
        String invalidToken = "invalidToken";

        when(jwtTokenProvider.getAuthentication(invalidToken)).thenCallRealMethod();
        when(jwtTokenProvider.validateToken(invalidToken)).thenReturn(false);

        Authentication authentication = jwtTokenProvider.getAuthentication(invalidToken);

        assertNull(authentication);
    }
}
```

These unit test cases use Mockito to mock the LDAP template and JWT token provider dependencies. They verify the behavior of the service methods and token generation/validation. Make sure to adjust the test data according to your specific LDAP configuration and asymmetric key handling.

Please note that these examples provide a basic implementation of LDAP authentication and JWT token generation without additional security measures like user roles, authorities, or token expiration validation. For a production environment, you should consider additional security aspects and follow best practices for JWT token handling.

Sure! Here's how you can implement the JWT token provider using Nimbus JOSE+JWT library for generating and validating JWT tokens:

1. Add the Nimbus JOSE+JWT library to your project. You can include it as a Maven dependency in your `pom.xml` file:

```xml
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>9.11</version>
</dependency>
```

2. Create the `JwtTokenProvider` class:

```java
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.Date;

@Component
public class JwtTokenProvider {

    @Value("${jwt.expirationTime}")
    private int expirationTime;

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    public JwtTokenProvider() {
        // Initialize the key pair for signing and verification
        generateKeyPair();
    }

    private void generateKeyPair() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.genKeyPair();
            this.privateKey = (RSAPrivateKey) keyPair.getPrivate();
            this.publicKey = (RSAPublicKey) keyPair.getPublic();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error generating RSA key pair for JWT token.", e);
        }
    }

    public String generateToken(String username) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + expirationTime * 1000);

        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .subject(username)
                .issueTime(now)
                .expirationTime(expiration)
                .build();

        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .build();

        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        try {
            JWSSigner signer = new RSASSASigner(privateKey);
            signedJWT.sign(signer);
            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException("Error signing JWT token.", e);
        }
    }

    public boolean validateToken(String token) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier(publicKey);
            return signedJWT.verify(verifier) && !isTokenExpired(signedJWT.getJWTClaimsSet());
        } catch (JOSEException | ParseException e) {
            return false;
        }
    }

    private boolean isTokenExpired(JWTClaimsSet claimsSet) {
        Date expiration = claimsSet.getExpirationTime();
        return expiration != null && expiration.before(new Date());
    }
}
```

In this implementation, we use the `generateToken` method to create a new JWT token with the given username as the subject. The `validateToken` method checks the token's signature and expiration time for validation.

Note that this example uses RSA keys for signing and verification. The keys are generated automatically during the initialization of the `JwtTokenProvider`. In a production environment, you should store the keys securely and not generate them on the fly.

Also, make sure you have the `jwt.expirationTime` property defined in your properties file to set the token expiration time in seconds.

3. Update the `SecurityConfig` class (as shown in a previous answer) to use the new `JwtTokenProvider`:

```java
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private LdapUserDetailsService ldapUserDetailsService;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    // ...

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .authorizeRequests().anyRequest().authenticated()
            .and().formLogin()
            .successHandler(jwtAuthenticationSuccessHandler())
            .and().apply(new JwtConfigurer(jwtTokenProvider));
    }

    // ...
}
```

4. Implement Unit Test Cases:

Here are some example unit test cases to test the `JwtTokenProvider`:

```java
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class JwtTokenProviderTest {

    private JwtTokenProvider jwtTokenProvider;

    @Before
    public void setUp() {
        jwtTokenProvider = new JwtTokenProvider();
    }

    @Test
    public void testGenerateAndValidateToken() {
        String username = "testUser";
        String token = jwtTokenProvider.generateToken(username);

        assertTrue(jwtTokenProvider.validateToken(token));
    }

    @Test
    public void testValidateExpiredToken() {
        String username = "testUser";
        String token = jwtTokenProvider.generateToken(username);

        // Simulate token expiration by setting the expiration time to a past date
        jwtTokenProvider.expirationTime = -1;
        assertFalse(jwtTokenProvider.validateToken(token));
    }

    @Test
    public void testValidateInvalidToken() {
        String invalidToken = "invalidToken";
        assertFalse(jwtTokenProvider.validateToken(invalidToken));
    }
}
```

In these test cases, we generate a token using the `generateToken` method and then validate it using the `validateToken` method. We also test the case of an expired token and an invalid token.

Please make sure to adjust the test data and token expiration settings according to your requirements.

With this implementation and unit tests, you should have a working JWT token provider using Nimbus JOSE+JWT library in your Spring Framework 5.0 application.
