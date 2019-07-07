# OVAL-For-EL
Redhat OVAL Converted To Enterprise Linux

| File Name                 | Description                                                  |
| ------------------------- | ------------------------------------------------------------ |
| com.redhat.rhsa-RHEL*.xml | original oval from: https://www.redhat.com/security/data/oval/ |
| com.redhat.rhsa-el*.xml   | converted oval files (adapted to: redhat/centos )            |

## Usage:

1. Download oval-for-el 

2. Run oscap oval check ( Example:CentOS7 )

   oscap oval eval com.redhat.rhsa-el7.xml

   