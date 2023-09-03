In Spring Boot, you can use an `EnvironmentPostProcessor` to decrypt properties with a specific prefix during the application startup process. This is often used for sensitive information like database passwords or API keys that you want to encrypt in your configuration files.

Here's a step-by-step guide on how to implement this:

1. Create a custom `EnvironmentPostProcessor` implementation:

```java
import org.springframework.boot.SpringApplication;
import org.springframework.boot.env.EnvironmentPostProcessor;
import org.springframework.core.env.ConfigurableEnvironment;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.PropertySource;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;

@Component
public class CustomEnvironmentPostProcessor implements EnvironmentPostProcessor {

    private static final String PROPERTY_PREFIX = "custom.decrypt.";

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment, SpringApplication application) {
        Map<String, Object> decryptedProperties = new HashMap<>();
        for (PropertySource<?> propertySource : environment.getPropertySources()) {
            if (propertySource instanceof MapPropertySource) {
                MapPropertySource mapPropertySource = (MapPropertySource) propertySource;
                Map<String, Object> sourceProperties = mapPropertySource.getSource();
                for (String key : sourceProperties.keySet()) {
                    if (key.startsWith(PROPERTY_PREFIX)) {
                        String encryptedValue = (String) sourceProperties.get(key);
                        String decryptedValue = decrypt(encryptedValue); // Implement your decryption logic here
                        decryptedProperties.put(key.substring(PROPERTY_PREFIX.length()), decryptedValue);
                    }
                }
            }
        }
        environment.getPropertySources().addFirst(new MapPropertySource("custom-decrypted-properties", decryptedProperties));
    }

    // Implement your decryption logic here
    private String decrypt(String encryptedValue) {
        // Add your decryption code here
        // For example, you can use a custom decryption algorithm or a library like Jasypt
        return encryptedValue;
    }
}
```


2. In the code above, we define a custom `EnvironmentPostProcessor` named `CustomEnvironmentPostProcessor`. It searches for properties with a prefix of "custom.decrypt." and then decrypts those properties using your custom decryption logic (replace `decrypt` method with your actual decryption logic).

3. Add the encrypted properties to your `application.properties` or `application.yml` file with the "custom.decrypt." prefix:

```properties
custom.decrypt.encrypted.property1=your-encrypted-value-1
custom.decrypt.encrypted.property2=your-encrypted-value-2
```

4. When your Spring Boot application starts, the `CustomEnvironmentPostProcessor` will be automatically invoked, and it will decrypt the properties with the "custom.decrypt." prefix and add them back to the environment.

Now, you can use these decrypted properties in your Spring application as you normally would.


Alternative using value prefix "ENC_"

Sure, you can decrypt all encrypted properties with a prefix in Spring Boot using EnvironmentPostProcessor. Here are the steps involved:

1. Create a class that extends `EnvironmentPostProcessor`.
2. Override the `postProcessEnvironment` method.
3. In the `postProcessEnvironment` method, get the environment object.
4. Iterate over all the property sources in the environment.
5. For each property source, check if the property value starts with the specified prefix.
6. If the property value starts with the specified prefix, decrypt the property value using a text encryptor.
7. Replace the encrypted property value with the decrypted property value in the environment.

Here is an example of a class that decrypts all encrypted properties with the prefix `ENC_`:

```java
public class DecryptingEnvironmentPostProcessor extends EnvironmentPostProcessor {

    private final TextEncryptor textEncryptor;

    public DecryptingEnvironmentPostProcessor(TextEncryptor textEncryptor) {
        this.textEncryptor = textEncryptor;
    }

    @Override
    public void postProcessEnvironment(ConfigurableEnvironment environment) {
        Map<String, Object> propertyOverrides = new LinkedHashMap<>();
        for (PropertySource<?> propertySource : environment.getPropertySources()) {
            for (String propertyName : propertySource.getPropertyNames()) {
                String propertyValue = propertySource.getProperty(propertyName);
                if (propertyValue.startsWith("ENC_")) {
                    String decryptedPropertyValue = textEncryptor.decrypt(propertyValue);
                    propertyOverrides.put(propertyName, decryptedPropertyValue);
                }
            }
        }
        environment.getPropertySources().addFirst(new PropertySource<Map<String, Object>>("decrypted-properties", propertyOverrides));
    }
}
```

In this example, we are using the `TextEncryptor` class from the Jasypt library to decrypt the properties. You can use any text encryptor that you want.

Once you have created the `DecryptingEnvironmentPostProcessor` class, you need to register it in your Spring Boot application. You can do this by adding the following dependency to your pom.xml file:

```xml
<dependency>
    <groupId>org.jasypt</groupId>
    <artifactId>jasypt</artifactId>
    <version>1.9.3</version>
</dependency>
```

You also need to add the following configuration to your application.properties file:

```
jasypt.encryptor.password=my-secret-password
```

The value of the `jasypt.encryptor.password` property is the password that will be used to decrypt the properties.

Finally, you need to register the `DecryptingEnvironmentPostProcessor` class in your Spring Boot application. You can do this by adding the following bean definition to your application.yml file:

```yaml
decryptingEnvironmentPostProcessor:
  class: com.example.DecryptingEnvironmentPostProcessor
  textEncryptor:
    class: org.jasypt.encryption.pbe.StandardPBEStringEncryptor
    password: ${jasypt.encryptor.password}
```

Once you have done all of this, all of the encrypted properties with the prefix `ENC_` will be decrypted when your Spring Boot application starts up.

I hope this helps! Let me know if you have any other questions.