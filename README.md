**Configuration Profiles** 

These settings will have to be configured per type (iOS or Android). The choices are described per subscription model with reference to Microsoft recommendations.

For more information see: https://learn.microsoft.com/nl-nl/mem/intune/fundamentals/protection-configuration-levels

**Windows**



**iOS** 

Go Home > Devices > iOS/iPadOS > Configuration Profiles: 

Create a new profile with type: Device restrictions   
Name of the profile: bl-ios-cfg-restrictions   
Set all the restrictions according iOS security level 2:  

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
   
