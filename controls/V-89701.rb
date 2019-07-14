control "V-89701" do
  title "The SLES for vRealize must use mechanisms meeting the requirements of
applicable federal laws, Executive orders, directives, policies, regulations,
standards, and guidance for authentication to a cryptographic module."
  desc  "Unapproved mechanisms that are used for authentication to the
cryptographic module are not verified and therefore cannot be relied upon to
provide confidentiality or integrity, and DoD data may be compromised.

    Operating systems utilizing encryption are required to use FIPS-compliant
mechanisms for authenticating to cryptographic modules.

    FIPS 140-2 is the current standard for validating that mechanisms used to
access cryptographic modules utilize authentication that meets DoD
requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a
general purpose computing system.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000120-GPOS-00061"
  tag "gid": "V-89701"
  tag "rid": "SV-100351r1_rule"
  tag "stig_id": "VRAU-SL-000730"
  tag "fix_id": "F-96443r1_fix"
  tag "cci": ["CCI-000803"]
  tag "nist": ["IA-7", "Rev_4"]
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
  tag "check": "Check the /etc/default/passwd file:

# grep CRYPT /etc/default/passwd

If the \"CRYPT\" setting in /etc/default/passwd is not present, or not set to
\"SHA256\" or \"SHA512\", this is a finding.

If the \"CRYPT_FILES\" setting in /etc/default/passwd is not present, or not
set to \"SHA256\" or \"SHA512\", this is a finding."
  tag "fix": "Edit the /etc/default/passwd file and add or change the \"CRYPT\"
variable setting so that it contains:

CRYPT=sha256
OR
CRYPT=sha512

Edit the /etc/default/passwd file and add or change the \"CRYPT_FILES\"
variable setting so that it contains:

CRYPT_FILES=sha256
OR
CRYPT_FILES=sha512"
end

