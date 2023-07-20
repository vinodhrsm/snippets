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