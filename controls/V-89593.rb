control "V-89593" do
  title "Bootloader authentication must be enabled to prevent users without
privilege to gain access to restricted file system resources."
  desc  "To mitigate the risk of unauthorized access to sensitive information
by entities that have been issued certificates by DoD-approved PKIs, all DoD
systems (e.g., web servers and web portals) must be properly configured to
incorporate access control methods that do not rely solely on the possession of
a certificate for access. Successful authentication must not automatically give
an entity access to an asset or security boundary. Authorization procedures and
controls must be implemented to ensure each authenticated entity also has a
validated and current authorization. Authorization is the process of
determining whether an entity, once authenticated, is permitted to access a
specific asset. Information systems use access control policies and enforcement
mechanisms to implement this requirement.

    Access control policies include identity-based policies, role-based
policies, and attribute-based policies. Access enforcement mechanisms include
access control lists, access control matrices, and cryptography. These policies
and mechanisms must be employed by the application to control access between
users (or processes acting on behalf of users) and objects (e.g., devices,
files, records, processes, programs, and domains) in the information system.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-89593"
  tag "rid": "SV-100243r1_rule"
  tag "stig_id": "VRAU-SL-000425"
  tag "fix_id": "F-96335r1_fix"
  tag "cci": ["CCI-000213"]
  tag "nist": ["AC-3", "Rev_4"]
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "To verify a boot password exists, in /boot/grub/menu.lst run
the following command:

# grep password /boot/grub/menu.lst

The output should show the following:

password --encrypted $1$[rest-of-the-password-hash]

If it does not, this is a finding."
  tag "fix": "Run the following command:

# /usr/sbin/grub-md5-crypt

An MD5 password is generated. After the password is supplied, the command
supplies the md5 hash output.

Append the password to the \"menu.lst\" file by running the following command:

echo 'password --md5 <hash from grub-md5-crypt>' >> /boot/grub/menu.lst

Or use yast2 to set the bootloader password.

Open the Boot Loader Installation tab.

Click \"Boot Loader Options\".

Activate the Protect Boot Loader with Password option with a click and type in
the password twice.

Click \"OK\" twice to save the changes."

describe file('/boot/grub/menu.lst') do
  its('content') { should match(%r{^password\s--md5\s\$1\$}) }
end

end

