[[_TOC_]]


##Identity Protection
This page describes the configuration of Identity Protection within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicon's Blueprint for Secure Cloud.

>The below pages outline the as built configuration for Rubicon's Blueprint for Secure Cloud (the Blueprint) for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade

### User risk policy
This page describes the configuration of a user risk policy within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicon's Blueprint for Secure Cloud.

The below tables outline the as built configuration for Rubicon's Blueprint for Secure Cloud (the Blueprint) for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/IdentityProtectionMenuBlade/~/UserPolicy

| Item | Value | 
|-----------|:-----------:|
| Users	| Include: All users |
| | Exclude: Break Glass accounts |
| User risk | Medium and above |
| Controls | Require password change |
| Policy enforcement | Enabled |

###Sign-in risk policy
###MFA registration policy


## Authentication Methods
This page describes the configuration of authentication methods within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicon's Blueprint for Secure Cloud.

>The below pages outline the as built configuration for Rubicon's Blueprint for Secure Cloud (the Blueprint) for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade

###Policies
This page describes the configuration of authentication policies within Microsoft Entra ID associated with systems built according to the guidance provided by ASD's Blueprint for Secure Cloud.

>The below tables outline the as built configuration for Rubicon's Blueprint for Secure Cloud (the Blueprint) for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods 

![image.png](/.attachments/image-a84f4f49-efcd-48df-8f14-b3852ffae5cf.png)


###Password protection
This page describes the configuration of password protection within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicons's Blueprint for Secure Cloud. 

>The below tables outline the as built configuration for Rubicon's Blueprint for Secure Cloud (the Blueprint) for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/PasswordProtection/

![image.png](/.attachments/image-4985edfe-056b-44bf-b651-aa93b22b13e9.png)

###Registration Campaign

Start a registration campaign that prompts users to set up more secure authentication methods.
Exclude users and groups from the entire campaign in the Settings section or include users and groups for each authentication method (currently limited to Microsoft Authenticator). Learn more: https://aka.ms/nudgedoc

![image.png](/.attachments/image-739e652b-b0d8-4aa5-afc2-9b71fcb48bf3.png)

###Authentication Strengths
Authentication strengths determine the combination of authentication methods that can be used. Learn more: https://aka.ms/authstrengthdocs

![image.png](/.attachments/image-fbd743be-7474-4e0a-9038-e8d91dc8b417.png)

###Settings
Allows users to report suspicious activities if they receive an authentication request that they did not initiate. This control is available when using the Microsoft Authenticator app and voice calls. Reporting suspicious activity will set the user's risk to high. If the user is subject to risk-based Conditional Access policies, they may be blocked. Learn more: https://aka.ms/reportsuspiciousactivity

![image.png](/.attachments/image-8788ba10-d7e0-404e-b6f4-7eaf5a80a4d5.png)


##Password Reset
Designates whether users in this directory can reset their own password. Choose "All" to enable for all users.

![image.png](/.attachments/image-d64085c4-ab52-428a-8486-6e7e51e041f7.png)

###Authentication Methods
Defines the number of alternate methods of identification a user in this directory must have to reset their password.

![image.png](/.attachments/image-fa925a68-62d5-4cd4-929d-76bdfe534e3e.png)

###Registration
Designates whether unregistered users are prompted to register their own authentication information when they sign in for the first time. 

![image.png](/.attachments/image-e1518cd6-ef2f-45e7-a5cd-c43fd3166238.png)

###Notification
Determines whether or not users receive an email to their primary and alternate email addresses notifying them when their own password has been reset via the Self-Service Password Reset portal.

![image.png](/.attachments/image-7aa97ccc-245d-4515-9365-9f990667592e.png)

##External Identities
###All identity providers
###Cross-tenant access settings
### External Collaboration Settings
This page describes the configuration of external collaboration settings within Microsoft Entra ID associated with systems built according to the guidance provided by ASD's Blueprint for Secure Cloud.

>The below tables outline the as built configuration for ASD’s Blueprint for Secure Cloud (the Blueprint) for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/CompanyRelationshipsMenuBlade/~/Settings

**Guest user access and Guest invite settings**

![image.png](/.attachments/image-cafa8210-db7e-408a-81cf-329f09b77d8e.png)

**External user leave settings and Collaboration restrictions**

![image.png](/.attachments/image-9f4548e5-04be-4c1d-aded-18e32b0e4e30.png)


## Identity Governance
This page describes the configuration of identity governance within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicon's Blueprint for Secure Cloud.

>The below pages outline the as built configuration for ASD’s Blueprint for Secure Cloud (the Blueprint) for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_Azure_IdentityGovernance/Dashboard.ReactView

###Access Reviews for External users
This page describes the configuration of access review settings within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicon's Blueprint for Secure Cloud.

**Manage the lifecycle of external users**


###Access Reviews for Administrators

>License requirements for this feature have changed. After October 30, 2023, access to capabilities formerly in preview will be read-only, unless you purchase the new Microsoft Entra ID Governance license. Learn more: https://learn.microsoft.com/en-us/entra/id-governance/licensing-fundamentals


![image.png](/.attachments/image-f8dcf44c-1cd4-40a7-b220-4abe418e3380.png)

