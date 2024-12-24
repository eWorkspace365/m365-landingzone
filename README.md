**Enrollment Types** 

For BYOD enrollment there is a difference between iOS and Android devices. Depending on the  Conditional Access Policies, users need to enroll their personal device into Microsoft Intune. 

Bring You Own Device (BYOD) 

For the enrollment types all personal devices will be allowed, including for iOS and Android platform. Renewi’s choice on the enrollment types are default for iOS and a work-profile for Android.  

**Go to Home > Devices > Enrollment device platform restrictions:** 

Configure the Android and iOS restrictions to allow use of personal owned devices. 

 ![Afbeelding met tafel
Automatisch gegenereerde beschrijving](file:///C:/Users/ARIANB~1/AppData/Local/Temp/msohtmlclip1/01/clip_image004.png)

| Description | Choice | Enrollment Type |
| --- | --- | --- |
| Bring You Own Device (BYOD) | Yes / No | ·                    Default (iOS) ·                    Work-Profile (Android) |

 When a device is enrolled it must meet the following requirements. The targeted group is now for all users, but can be specific to a selected group to target the users that are in scope of this project.  

| Use Cases | Groups | Device Platforms | Requirements |
| --- | --- | --- | --- |
| Access company resources | All Users | iOS | ·                    Enrollment Type: iOS (Default) ·                    Configuration Profile L2 ·                    Compliancy Policy L2 ·                    Compliant Device State (out of scope) |
| Access company resources | All Users | Android | ·                    Enrollment Type: Android (Work-Profile) ·                    Configuration Profile L2 ·                    Compliancy Policy L2 ·                    Compliant Device State (out of scope) |

Corporate Owned | Private Enable (COPE | COBO) 

Corporate owned or managed devices are enrolled with Android Zero-Touch or Apple Business Manager. This gives the IT administrator more control over the device. Also, the device is restricted to the company and can only be used by the company’s personnel.  

Device-enrollment is more user-friendly than the BYOD enrollment type, but still the end-user needs to follow a short procedure to enroll the device in Intune.   

Renewi’s choice is that devices will be enrolled with a Work-Profile. This means that a QR-code will be created that will be included in the instruction manual for the users. 

| Description | Choice | Enrollment Type |
| --- | --- | --- |
| Company Owned - Private Enable (COPE) | Yes / No | ·                    Work-Profile (Android) ·                    Default (iOS) |
| Company Owned – Business Only (COBO) | Yes / No | ·                    Fully-Managed (iOS, Android) |

Mobile Device Management (MDM) 

Intune uses the protocols or APIs available in each mobile operating system for device-facing tasks. These include: 

·                    A Enroll and inventory devices. 

·                    Configure devices to meet configuration standards and compliance policies. 

·                    Providing certificates and Wi-Fi/VPN profiles for business access. 

·                    Remove corporate data from devices. 

**Apps** 

In Intune apps are pushed to the device by MDM and it uses the Apple or Google App Store. There are requirements within Intune for assigning apps to users or devices. 

For example: you need a google or apple account to select and approve apps.   
If these account are not yet available, then they must be created first in order to assigning applications to users or devices. 

Renewi has delivered an application list that must be deployed on devices. Each application must be reviewed by Detron to determine the effort of deploying and testing the application. 

Applications 

| Application | Purpose | Platforms | Assignment Type | MAM Policy |
| --- | --- | --- | --- | --- |
| First Up = Renewi Go | General Apps | iOS and Android | Required | Yes / No |
| mySDworx | General Apps | iOS and Android | Required | Yes / No |
| Assure GO+ | General Apps | iOS and Android | Required | Yes / No |
| Tipapp | General Apps | iOS and Android | Required | Yes / No |
| Pulse | General Apps | iOS and Android | Required | Yes / No |
| Apex tool | Specific Apps | iOS and Android | Required | Yes / No |
| CMR | Specific Apps | iOS and Android | Required | Yes / No |
| Prometheus | Specific Apps | iOS and Android | Required | Yes / No |
| Renewi You | Specific Apps | iOS and Android | Required | Yes / No |
| Ekivita Edenred | Other Apps | iOS and Android | Required | Yes / No |
| Coupa | Other Apps | iOS and Android | Required | Yes / No |
| Orange | Other Apps | iOS and Android | Required | Yes / No |
| Vanbreda Risk | Other Apps | iOS and Android | Required | Yes / No |
| AG Insurance | Other Apps | iOS and Android | Required | Yes / No |
| WAZE | Other Apps | iOS and Android | Required | Yes / No |
| Adobe Acrobat Reader | Office | iOS and Android | Required | Yes / No |
| Microsoft Edge | Browser | iOS and Android | Required | Yes / No |
| Microsoft 365 app | Office | iOS and Android | Required | Yes / No |
| Microsoft Outlook | Collaboration | iOS and Android | Required | Yes / No |
| Microsoft Defender | Security | iOS and Android | Required | Yes / No |
| Microsoft Onedrive | Security | iOS and Android | Required | Yes / No |
| Microsoft Teams | Collaboration | iOS and Android | Required | Yes / No |
| Microsoft Authenticator | Security | iOS and Android | Required | Yes / No |
| Chrome | Browser | iOS and Android | Required | Yes / No |
| MS Word | Office | iOS and Android | Available | Yes / No |
| MS Excel | Office | iOS and Android | Available | Yes / No |
| MS Yammer | Office | iOS and Android | Available | Yes / No |
| MS Powerpoint | Office | iOS and Android | Available | Yes / No |
| MS Onenote | Office | iOS and Android | Available | Yes / No |

Applications that public available in the App Stored (Apple or Google) can be assigned to users as required of available. If the assignment is available, then the application will show up in the App Store and can be installed on-demand. 

For public apps Renewi has made the choice to not restrict the App Store for personal devices and for the work-profile to restrict the App Store. 

| Platform | Enrollment Type | App Store Setting |
| --- | --- | --- |
| iOS | Default | Open / Closed |
| Android | Work-Profile | Open / Closed |

**Configuration Profiles** 

These settings will have to be configured per type (iOS or Android). The choices are described per subscription model with reference to Microsoft recommendations.  Renewi’s choice is to hold on to Microsoft’s recommended setting, and will be security level 2. 

**iOS** 

| IOS (Supervised) | IOS (Personal) |
| --- | --- |
| iOS/iPadOS supervised device security configurations - Microsoft Intune | iOS/iPadOS personal device security configurations - Microsoft Intune |
| Security Level 1 | N/A |
| Security Level 2 | Security Level 2 |
| Security Level 3 | Security Level 3 |

Go Home > Devices > iOS/iPadOS > Configuration Profiles: 

Create a new profile with type: Device restrictions   
Name of the profile: IOS-DEV-CFG-Device-Restrictions   
Set all the restrictions according iOS (Personal) security level 2:  

| Section | Setting | Value |
| --- | --- | --- |
| App Store, Doc Viewing, Gaming | Treat AirDrop as an unmanaged destination | Yes |
| App Store, Doc Viewing, Gaming | Block viewing corporate documents in unmanaged apps | Yes |
| App Store, Doc Viewing, Gaming | Block viewing non-corporate documents in corporate apps | Not configured |
| App Store, Doc Viewing, Gaming | Allow managed apps to write contacts to unmanaged contacts accounts | Yes |
| App Store, Doc Viewing, Gaming | Allow copy/paste to be affected by managed open-in | Not configured |
| Built-in Apps | Block Siri while device is locked | Yes |
| Built-in Apps | Require Safari fraud warnings | Yes |
| Built-in Apps | Block Siri for dictation | Yes |
| Built-in Apps | Block Siri for translation | Yes |
| Cloud and Storage | Force encrypted backup | Yes |
| Cloud and Storage | Block managed apps from storing data in iCloud | Yes |
| Cloud Storage | Block backup of enterprise books | Yes |
| Cloud Storage | Block notes and highlights sync for enterprise books | Yes |
| Connected Devices | Force Apple Watch wrist detection | Yes |
| General | Block untrusted TLS certificates | Yes |
| General | Block trusting new enterprise app authors | Yes |
| General | Block sending diagnostic and usage data to Apple | Yes |
| Locked Screen Experience | Block Notification Center access in lock screen | Yes |
| Locked Screen Experience | Block Today view in lock screen | Yes |
| Password | Require a password | Yes |
| Password | Block simple passwords | Yes |
| Password | Required password type | Numeric |
| Password | Minimum password length | 6 |
| Password | Number of sign-in failures before wiping the device | 10 |
| Password | Maximum minutes after screen lock before password is required | 5 |
| Password | Maximum minutes of inactivity until screen locks | 5 |

  

Certificate Profile 

Not used in scope at this moment. 

 Wi-Fi Profile 

Renewi’s is to pre-configure WiFi setting for users that uses iOS devices. 

Go Home > Devices > iOS/iPadOS > Configuration Profiles: 

Create profile name: IOS-DEV-CFG-WiFi-“SSID” and configure the settings  

**Android** 

Renewi’s choice is to hold on to Microsoft’s recommended setting, and will be security level 2. 

| Android (Supervised) | Android (Personal) |
| --- | --- |
| Android Enterprise fully managed security configurations - Microsoft Intune | Android Enterprise security configurations for personally-owned work profile - Microsoft Intune |
| Security Level 1 | N/A |
| Security Level 2 | Security Level 2 |
| Security Level 3 | Security Level 3 |

Go Home > Devices > Android > Configuration Profiles: 

Create a new profile with type: Device restrictions   
Name of the profile: AND-DEV-CFG-Device-Restrictions   
Set all the restrictions according Android (Personal) security level 2:  

| Section | Setting | Value |
| --- | --- | --- |
| Device password | Minimum password length | 6 |
| Device password | Maximum minutes of inactivity until screen locks | 5 |
| Device password | Number of sign-in failures before wiping device | 10 |
| Device password | Password expiration (days) | Not configured |
| Device password | Required password type | Numeric complex |
| Device password | Prevent reuse of previous passwords | Not configured |
| System Security | Threat scan on apps | Require |
| System Security | Prevent app installations from unknown sources in the personal profile | Block |
| Work profile settings | Copy and paste between work and personal profiles | Block |
| Work profile settings | Data sharing between work and personal profiles | Apps in work profile can handle sharing request from personal profile |
| Work profile settings | Work profile notifications while device locked | Not configured |
| Work profile settings | Default app permissions | Device Default |
| Work profile settings | Add and remove accounts | Block |
| Work profile settings | Contact sharing via Bluetooth | Enable |
| Work profile settings | Screen capture | Block |
| Work profile settings | Search work contacts from personal profile | Not configured |
| Work profile settings | Allow widgets from work profile apps | Enable |
| Work profile settings | Require Work Profile Password | Require |
| Work profile settings | Minimum password length | 6 |
| Work profile settings | Maximum minutes of inactivity until work profile locks | 5 |
| Work profile settings | Number of sign-in failures before wiping the work profile | 10 |
| Work profile settings | Password expiration (days) | Numeric |
| Work profile settings | Required password type | 6 |
| Work profile settings | Prevent reuse of previous passwords | 10 |

 Certificate Profile 

Not used in scope at this moment. 

 Wi-Fi Profile 

Renewi’s is to pre-configure WiFi setting for users that uses Android devices. 

Go Home > Devices > Android > Configuration Profiles: 

Create profile name: AND-DEV-CFG-WiFi-“SSID” and configure the settings  

**Compliance Policies** 

Compliance policies are commonly used in combination with Conditional Access. The Company Portal App synchronizes the device state to Intune and compares it with the compliancy policy that is targeted for the device.  

To meet with the compliancy policy that has been targeted, of course we enforce these settings first in the configuration policy. It is basically checking if those settings were applied. 

If the device meets the compliance policy, then Intune marks the device as compliant and access to company resources is granted. 

Renewi’s choice is to hold on to Microsoft’s recommended setting, and will be security level 2. 

| iOS |
| --- |
| iOS/iPadOS device compliance security configurations - Microsoft Intune |
| Security Level 1 |
| Security Level 2 |
| Security Level 3 |

Go Home > Devices > iOS/iPadOS > Compliance Policies: 

Create a new profile name: IOS-DEV-Compliancy-L2   
Set all the restrictions according iOS security level 2:   
   
