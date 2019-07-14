control "V-89591" do
  title "The system must require root password authentication upon booting into
single-user mode."
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

    Access control policies include: identity-based policies, role-based
policies, and attribute-based policies. Access enforcement mechanisms include:
access control lists, access control matrices, and cryptography. These policies
and mechanisms must be employed by the application to control access between
users (or processes acting on behalf of users) and objects (e.g., devices,
files, records, processes, programs, and domains) in the information system.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000080-GPOS-00048"
  tag "gid": "V-89591"
  tag "rid": "SV-100241r1_rule"
  tag "stig_id": "VRAU-SL-000420"
  tag "fix_id": "F-96333r1_fix"
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
  tag "check": "Verify that root password is required for single user mode
login with the following command:

# grep sulogin /etc/inittab

Expected result:
~~:S:respawn:/sbin/sulogin

If the expected result is not displayed, this is a finding."
  tag "fix": "Configure the system to require root password login with single
user mode use the following command:

# echo '~~:S:respawn:/sbin/sulogin' >> /etc/inittab"
end

