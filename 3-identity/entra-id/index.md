# EntraID
[[_TOC_]]

##Users
###Setup break glass accounts
his page describes the configuration of break glass accounts within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicon Blueprint for Secure Cloud.

| Item | Value | 
|-----------|:-----------:|
| Display Name	| Break Glass 1 |
| User type | Member |
| Account enabled | Checked |
| Usage location | The Netherlands |
| Assigned role	| Global Administrator | 
| Groups | <CA exclude group> |

| Item | Value | 
|-----------|:-----------:|
| Display Name	| Break Glass 2 |
| User type | Member |
| Account enabled | Checked |
| Usage location | The Netherlands |
| Assigned role	| Global Administrator | 
| Groups | <CA exclude group> |

###Users settings
This page describes the configuration of user settings within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicon Blueprint for Secure Cloud. 

>Setup configuration for Rubicon's Cloud Blueprint for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/UserSettings/menuId/UserSettings

![image.png](/.attachments/image-a21009de-5e78-45e8-b6d0-d8c0fcf3d0b1.png)

| Item | Value | 
|-----------|:-----------:|
| User can register application | No | 
| Restrict non-admin users from creating tenants | Yes | 
| Users can create security groups | No | 
| Guest user access restrictions | Guest user access is restricted to properties and memberships of their own directory objects (most restrictive) | 
| Restrict access to Microsoft Entra admin centre | Yes | 
| Allow users to connect their work or school account with LinkedIn | No |
| Show keep user signed in | No | 
| User can use preview features for My Apps | None |
| Administrators can access My Staff | None |


###User Features
This page describes the configuration of user features within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicon's Blueprint for Secure Cloud.

>The below tables outline the as built configuration for Rubicon's Blueprint for Secure Cloud (the Blueprint) for the Microsoft Entra admin portal at the following URL: https://portal.azure.com/#view/Microsoft_AAD_IAM/FeatureSettingsBlade

![image.png](/.attachments/image-18d96a05-27f7-4e25-afad-c7815f55c5c2.png)

###Per-user MFA
>Setup configuration for Rubicon Cloud Blueprint for the Microsoft Entra admin portal at the following URL: 
https://account.activedirectory.windowsazure.com/usermanagement/multifactorverification.aspx

| Item | Value | 
|-----------|:-----------:|
| App passwords	| Do not allow users to create app passwords to sign in to non-browser apps | 
| Skip multi-factor authentication for requests from federated users on my intranet | Not checked | 
| Remember multi-factor authentication on trusted device | Not checked | 



## Groups
This page describes the configuration of group settings within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicon's Blueprint for Secure Cloud.

###Setup baseline groups
The following groups need to be created for Rubicon's Secure Cloud Blueprint:

![image.png](/.attachments/image-3c6a039c-c2bd-4dfe-8ebc-635a893e870f.png)

bl-sg-devices-windows-mdm:
```
(device.deviceModel -ne "Virtual Machine") and (device.managementType -eq "MDM")
```
bl-sg-devices-windows-autopilot:
```
(device.devicePhysicalIDs -any _ -contains "[ZTDId]")
```
bl-sg-devices-windows-avd:
```
(device.deviceModel -eq "Virtual Machine")
```
bl-sg-devices-windows-byod:
```
(device.deviceTrustType -match "workplace") -and (device.deviceOSType -eq "Windows")
```
bl-sg-users-guests:
```
(user.userType -eq "guest")
```

bl-sg-users-members:
```
(user.userType -eq "member")
```

###General
Microsoft Entra ID provides several ways to manage access to resources, applications, and tasks. With Microsoft Entra groups, you can grant access and permissions to a group of users instead of for each individual user. Limiting access to Microsoft Entra resources to only those users who need access is one of the core security principles of Zero Trust.

>Setup configuration for Rubicon's Cloud Blueprint for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/General

![image.png](/.attachments/image-308d9728-f222-477d-bfbc-52e0a3e21d7e.png)

###Expiration
This page describes the configuration of group expiration within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicon's Blueprint for Secure Cloud.

Renewal notifications are emailed to group owners 30 days, 15 days, and one day prior to group expiration. Group owners must have Exchange licenses to receive notification emails. If a group is not renewed, it is deleted along with its associated content from sources such as Outlook, SharePoint, Teams, and Power BI.

>The below tables outline the as built configuration for Rubicon's Blueprint for Secure Cloud (the Blueprint) for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/Lifecycle

![image.png](/.attachments/image-1823cb9c-3ead-49d4-ad32-aaaf964c9a04.png)

###Naming policy
This page describes the configuration of naming policies within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicon's Blueprint for Secure Cloud.

The below tables outline the as built configuration for Rubicon's Blueprint for Secure Cloud (the Blueprint) for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_AAD_IAM/GroupsManagementMenuBlade/~/NamingPolicy

| Item | Value | 
|-----------|:-----------:|
| Block word list | Not configured |  
| Add prefix | Not configured |
| Add suffix | Not configured |


##Devices
A device identity is an object in Microsoft Entra ID. This device object is similar to users, groups, or applications. A device identity gives administrators information they can use when making access or configuration decisions.

There are three ways to get a device identity:

- Microsoft Entra registration
- Microsoft Entra join
- Microsoft Entra hybrid join

###Device Settings
This page describes the configuration of device settings within Microsoft Entra ID associated with systems built according to the guidance provided by Rubicon Blueprint for Secure Cloud. 

>Setup configuration for Rubicon Cloud Blueprint for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/DeviceSettings

![image.png](/.attachments/image-ad1cedfb-9cee-4a6c-962a-cecf93d9a244.png)

**Microsoft Entra join and registration settings**
| Item | Value | 
|-----------|:-----------:|
| Users may join devices to Microsoft Entra | All | 
| Users may register their devices with Microsoft Entra | All | 
| Require Multifactor Authentication to register or join devices with Microsoft Entra | No | 
| Maximum number of devices per user | Unlimited | 

**Local administrator settings**
| Item | Value | 
|-----------|:-----------:|
| Global administrator role is added as local administrator on the device during Microsoft Entra join (Preview)	 | No | 
| Registering user is added as local administrator on the device during Microsoft Entra join (Preview) | None | 
| Enable Microsoft Entra Local Administrator Password Solution (LAPS)	 | Yes | 

**Other settings**
| Item | Value | 
|-----------|:-----------:|
| Restrict users from recovering the Bitlocker key(s) for their owned devices | No | 

###Enterprise state roaming
Enterprise State Roaming provides users with a unified experience across their Windows devices and reduces the time needed for configuring a new device. Enterprise State Roaming operates similar to the standard consumer settings sync that was first introduced in Windows 8. Enterprise State Roaming is available to any organization with a Microsoft Entra ID P1 or P2 or Enterprise Mobility + Security (EMS) license. 

>The below tables outline the as built configuration for ASD’s Blueprint for Secure Cloud (the Blueprint) for the Microsoft Entra admin portal at the following URL: https://entra.microsoft.com/#view/Microsoft_AAD_Devices/DevicesMenuBlade/~/RoamingSettings

![image.png](/.attachments/image-0fd02612-8621-4f41-9650-132f280931d1.png)

| Item | Value | 
|-----------|:-----------:|
| Users may sync settings and app data across devices | All |




