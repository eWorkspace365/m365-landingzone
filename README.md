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
