
## Features

- CentOS OVAL

**Supports**

| OS     | Release       | Upstream                                   |
| ------ | ------------- | ------------------------------------------ |
| redhat | RHEL5 - RHEL8 | https://www.redhat.com/security/data/oval/ |
| centos | EL5 - EL8     | https://www.redhat.com/security/data/oval/ |

**Scripts** 

scripts/rh2el.py 

```
# usage:
usage: rh2el.py [-h] oval_file output_file

redhat oval definition adapt to centos

positional arguments:
  oval_file    redhat oval file path
  output_file  centos oval output file path
```


## Quick Start

Identify software vulnerabilities on centos 7 with oscap which is a best scap scanner provided by openscap.

- **Download oval-for-el**

  ```
  git clone https://github.com/joseigbv/oval-for-el.git
  ```

- **Install oscap**

  ```bash
  sudo yum install openscap openscap-scanner
  ```

- **Download OVAL content**

  ```bash
  wget https://access.redhat.com/security/data/oval/com.redhat.rhsa-RHEL7.xml.bz2
  bunzip2 com.redhat.rhsa-RHEL7.xml.bz2
  ```

- **Convert from RedHat oval**

  ```bash
  rh2el.py com.redhat.rhsa-RHEL7.xml com.redhat.rhsa-EL7.xml
  ```

  > WARNING: you may have to add a new rpm signature key 

- **Run oscap oval**

  - Check all vulnerabilities defined for centos7

    ```bash
    oscap oval eval com.redhat.rhsa-EL7.xml
    ```

  - Only check one vulnerabilitiy

    Ex: shellchock(CVE-2014-6271). this vulnerabilitiy defined with id oval:com.redhat.rhsa:def:20141293 in com.redhat.rhsa-EL7.xml

    ```bash
    oscap oval eval --id oval:com.redhat.rhsa:def:20141293 com.redhat.rhsa-EL7.xml
    ```

  - Export html report with options --report

    ```bash
    oscap oval eval --report centos7.html com.redhat.rhsa-EL7.xml
    ```

  ------

  **Console output:**![oval console ouput](_static/imgs/1567436786275.png)
  
  **HTML report:**
  
  ![html report](_static/imgs/1567437131266.png)
  
  > Result: true means the vulnerability exists, and the true results always before false in html report

## Details on ovals above

### CentOS:

 - convert from redhat oval

 - cpe and criterions for centos

   ![cpe_and_criterion](_static/imgs/1567438374921.png)

 - rpm signature key check for centos

   ![signature_key](_static/imgs/1567438175262.png)


## Resource

**Linux OVAL**

- [Redhat](https://www.redhat.com/security/data/oval/)
- [Ubuntu](https://people.canonical.com/~ubuntu-security/oval/)
- [Debian](https://www.debian.org/security/oval/)
- [Oracle Linux](https://linux.oracle.com/security/oval/)
- [SUSE](http://ftp.suse.com/pub/projects/security/oval/)

