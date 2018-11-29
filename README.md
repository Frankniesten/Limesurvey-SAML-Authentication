# LimeSurvey-SAML
LimeSurvey authentication plugin for authenticating users against an SAML Identity Provider. 

## Requirements
- LimeSurvey 3.XX
- simpleSAMLphp

## Installation instructions
- Create folder **AuthSAML** inside **limesurvey/plugins** folder
- Copy **AuthSAML.php** from repo folder **Limesurvey-SAML-Authentication**
- Paste it inside **limesurvey/plugins/AuthSAML** folder
- Configure the plugin from the **Plugin Manager**
- Go to **Admin > Configuration > Plugin Manager** or **https:/example.com/index.php/admin/pluginmanager/sa/index** and **Enable** the plugin 

## Configuration options
- **Path to the SimpleSAMLphp folder**: path to the simpleSAMLphp installation
- **Does simplesamlphp use cookie as a session storage ?**: if simpleSAMLPHP is configured to use cookies as session storage
set this to **true** so the code can handle session conficts between simpleSAMLphp and LimeSurvey
- **SAML authentication source**: name of simpleSAMLphp service provider configuration from **authsources.php**
- **SAML attributed used as username**: the attribute returned from the IdP that will be the unique **username** of the user on LimeSurvey. This attribute **MUST NOT** change on the IdP.
**WARNING!!!** Please do not allow users to aquire the **admin** username, because is the super user of LimeSurvey
- **SAML attributed used as email**: the attribute returned from the IdP that will be used as an email of the user on LimeSurvey
- **SAML attributed used as name**: the attribute returned from the IdP that will be the users human friendly name
- **Auto update users**: check if IdP has different attribute values for email and name and update them on LimeSurvey
- **Force SAML login**: if this is set to true the plugin will force the login path to use only simpleSAMLphp
- **Authtype base**: LimeSurvey internal configuration options, use it only if you know what you are doing. Configures where the users data are stored.
- **Storage base**: LimeSurvey internal configuration options, use it only if you know what you are doing. Configures where the plugin settings are stored.
- **Logout Redirect URL**: configures where should the user be redirected after the logout path


## External material
- [simpleSAMLphp](https://simplesamlphp.org)
- [How to setup a simpleSAMLphp Service Provider](https://simplesamlphp.org/docs/stable/simplesamlphp-sp)
- [LimeSurvey](https://www.limesurvey.org/)
- [How to install LimeSurvey](https://manual.limesurvey.org/Installation_-_LimeSurvey_CE)
