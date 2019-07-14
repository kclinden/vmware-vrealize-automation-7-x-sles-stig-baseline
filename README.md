# vmware-vrealize-atuomation-7-x-sles-stig-baseline

InSpec Profile to validate the secure configuration of VMware vRealize Automation 7.x, against the DISA STIG version 1 release 1.

## Getting Started

It is intended and recommended that InSpec run this profile from a __"runner"__ host (such as a DevOps orchestration server, an administrative management system, or a developer's workstation/laptop) against the target remotely ove __ssh__.

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 

Latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

Git is required to download the latest InSpec profiles using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site. 

## Running This Profile

When the __"runner"__ host uses this profile overlay for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/kclinden/vmware-vrealize-atuomation-7-x-sles-stig-baseline.git
cd vmware-vrealize-atuomation-7-x-sles-stig-baseline
bundle install
cd ..
inspec exec vmware-vrealize-atuomation-7-x-sles-stig-baseline --attrs=<path_to_your_attributes_file/name_of_your_attributes_file.yml> -t ssh://<hostname>:<port> --user=<username> --password=<password> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this profile:

```
cd profiles/vmware-vrealize-atuomation-7-x-sles-stig-baseline
git pull
cd ..
inspec exec vmware-vrealize-atuomation-7-x-sles-stig-baseline --attrs=<path_to_your_attributes_file/name_of_your_attributes_file.yml> -t ssh://<hostname>:<port> --user=<username> --password=<password>] --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Contributing and Getting Help

To report a bug or feature request, please open an [issue](https://<baseline_repo>/issues/new).

## Authors

* Kasey Linden

## License

This project is licensed under the terms of the Apache 2.0 license as noted in [LICENSE](https://github.com/kclinden/vmware-vrealize-automation-7-x-sles-stig-baseline/blob/master/LICENSE). 

### NOTICE

DISA STIGs are published by DISA IASE, see: <https://public.cyber.mil/>.
