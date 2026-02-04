# Local Development of Inji Certify

**Pre-requisites**: 

- Java 21, Postgres DB installed & configured
- Git Bash for Windows users

1. Clone the repo, usually the active development happens on the `develop` branch but one can check out a tagged version as well.
2. Run the DB init scripts present in `db_scripts/inji_certify` , running `./deploy.sh deploy.properties` is a good way to init the DB.
3. Decide on the issuance mode of Certify. Some plugins enable Certify to operate as a Proxy and others enable it to work as an Issuer, configure `mosip.certify.plugin-mode` appropriately as `DataProvider` or `VCIssuance`.
    * [Recommended] Set it to `DataProvider` if you want a quickest possible working setup, and configure `mosip.certify.data-provider-plugin.issuer-uri` and `mosip.certify.data-provider-plugin.issuer-public-key-uri` appropriately.
    * If you have another Issuance module such as Sunbird, MOSIP Stack, you may want to set it up in `VCIssuance` mode.
4. Decide on the VCI plugin for use locally and configure it, while running locally from an IDE such as Eclipse or IntelliJ one needs to add configuration to the `application-local.properties` and add the VCI plugin dependency JAR to the certify-service project which implements one of `DataProviderPlugin` or `VCIssuancePlugin` interfaces.
5. Get a compatible eSignet setup running configured with the appropriate Authenticator plugin implementation matching the VCI plugin.
    * Configure `mosip.certify.authorization.url` to point to your Authorization service hostname, this could be a working eSignet instance or another AuthZ provider configured with an [Authenticator plugin implementation](https://docs.esignet.io/integration/authenticator), essentially enabling the VC Issuing plugin to do the work.
    * Configure `mosip.certify.domain.url`, `mosip.certify.identifier`, `mosip.certify.authn.issuer-uri`, `mosip.certify.authn.jwk-set-uri`, `mosip.certify.authn.allowed-audiences` appropriately as per the Authorization service and Certify URI.
    * Update the `mosip.certify.key-values` with the well known appropriately, with the correct credential-type, scope and other relevant attributes.
    * Update the well known configuration in `mosip.certify.key-values` to match the Credential type, scope and other fields to match your VerifiableCredential.
    * Appropriately configure the `mosip.certify.authn.allowed-audiences` to allowed audiences such that it matches with the AuthZ token when the Credential issue request is made to Certify.
6. (required if Mobile driving license configured) Onboard issuer key and certificate data into property `mosip.certify.mock.mdoc.issuer-key-cert` using the creation script.
7. Perform Authentication & VC Issuance to see if the Certify & AuthZ stack is working apprpriately. Look out for the Postman collections referred to in the main README.md of this project.
   * Use the **Inji Certify - Pre Auth Code** collection located at `docs/postman-collections/Inji Certify - Pre Auth Code.postman_collection.json` to test the "Credential Offer with Pre Authorization Code Flow".



# Setup Guide: Custom Plugin with Local `inji-certify` 🚀

This guide outlines how to use an existing certify plugin or build a custom plugin.

-----

## 1. Modifying and Building the Plugin

These steps prepare your custom plugin JAR file.

### 1.1. Clone the Repository

Get the source code for the plugins.

```bash
git clone https://github.com/mosip/digital-credential-plugins
```

### 1.2 Using an Existing Plugin
Currently, certify supports 2 types of plugins in `DataProvider` mode.

### 1.2.1 Mock CSV Data Provider Plugin
This plugin reads user data from a CSV file.
- **Location:** [MockCSVDataProviderPlugin](https://github.com/mosip/digital-credential-plugins/blob/master/mock-certify-plugin/src/main/java/io.mosip.certify.mock.integration/service/MockCSVDataProviderPlugin.java)

### Configurations required:
```properties
# Set Plugin Mode
mosip.certify.plugin-mode=DataProvider

#Set Plugin Class Implementation
mosip.certify.integration.data-provider-plugin=MockCSVDataProviderPlugin

## CSV Plugin specific configurations
# Path to CSV file
# Classpath can be used to load file from resources folder
mosip.certify.mock.data-provider.csv-registry-uri=classpath:farmer-identity-data.csv
# Use the correct URI if the file is hosted.
#mosip.certify.mock.data-provider.csv-registry-uri=https://inji.github.io/inji-config/collab/farmer-identity-data.csv

# Identifier Column in CSV
mosip.certify.mock.data-provider.csv.identifier-column=id

# CSV data columns
mosip.certify.mock.data-provider.csv.data-columns=id,name,age
```

### Use the plugin as runtime-dependency in certify-service pom.xml
```xml 
<dependency>
    <groupId>io.inji.certify</groupId>
    <artifactId>mock-certify-plugin</artifactId>
    <!-- Use the latest version or the version if the existing plugin is modified --> 
    <version>0.6.0</version>
</dependency>
```

### 1.2.2 Postgres Data Provider Plugin
This plugin fetches user data from a PostgreSQL database.
- **Location:** [PostgresDataProviderPlugin](https://github.com/mosip/digital-credential-plugins/tree/master/postgres-dataprovider-plugin)

### Configurations required:
```properties
# Set Plugin Mode
mosip.certify.plugin-mode=DataProvider

#Set Plugin Class Implementation
mosip.certify.integration.data-provider-plugin=PostgresDataProviderPlugin

## Postgres Plugin specific configurations
# Define a OpenID scope to DB query map where :id is fetched from the "sub" field of the token.
# sample_vc_ldp is the credential scope
# farmer_data is the table name and farmer_id is the column to be matched with :id
mosip.certify.data-provider-plugin.postgres.scope-query-mapping={\
    'sample_vc_ldp': 'select * from farmer_data where farmer_id=:id'\
  }
```
### Use the plugin as runtime-dependency in certify-service pom.xml
```xml 
<dependency>
    <groupId>io.inji.certify</groupId>
    <artifactId>postgres-dataprovider-plugin</artifactId>
    <!-- Use the latest version or the version if the existing plugin is modified --> 
    <version>0.6.0</version>
</dependency>
```

### 1.2. Develop Your Own Plugin

Create a new project or modify an existing project within the cloned repository.

**References:**
- Implement `DataProviderPlugin` or `VCIssuancePlugin` interfaces from [Certify Plugin API](https://github.com/inji/inji-certify/tree/develop/certify-integration-api/src/main/java/io/mosip/certify/api/spi)
- Write your custom logic to fetch data and/or issue VCs.
**Note:** Recommended to use `DataProviderPlugin` for most use cases.


### 1.3. Build the Plugin

Navigate to your project folder inside the `digital-credential-plugins` repository and run the build command. This generates the snapshot JAR in your local Maven repository.

```bash
mvn clean install -Dgpg.skip=true
```

## Run Inji Certify locally with default-setup



## Locally setting up CSV Plugin


The above README can be used to setup the [CSV Plugin](https://github.com/mosip/digital-credential-plugins/tree/develop/mock-certify-plugin) and it'll help showcase how one can setup a custom authored plugin for local testing.

Pre-requisites:

* a working Authorization service which gives an identifiable information in the end-user's ID in the `sub` field
* pre-populated CSV file configured with the matching identities to be authenticated against
