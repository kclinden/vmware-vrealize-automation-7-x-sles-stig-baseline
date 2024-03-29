control "V-89807" do
  title "The SLES for vRealize must implement cryptographic mechanisms to
protect the confidentiality of nonlocal maintenance and diagnostic
communications, when used for nonlocal maintenance sessions."
  desc  "Privileged access contains control and configuration information and
is particularly sensitive, so additional protections are necessary. This is
maintained by using cryptographic mechanisms such as encryption to protect
confidentiality.

    Nonlocal maintenance and diagnostic activities are those activities
conducted by individuals communicating through a network, either an external
network (e.g., the Internet) or an internal network. Local maintenance and
diagnostic activities are those activities carried out by individuals
physically present at the information system or information system component
and not communicating across a network connection.

    This requirement applies to hardware/software diagnostic test equipment or
tools. This requirement does not cover hardware/software components that may
support information system maintenance, yet are a part of the system (e.g., the
software implementing \"ping,\" \"ls,\" \"ipconfig,\" or the hardware and
software implementing the monitoring port of an Ethernet switch).

    The operating system can meet this requirement through leveraging a
cryptographic module.
  "
  impact 0.5
  tag "severity": nil
  tag "gtitle": "SRG-OS-000394-GPOS-00174"
  tag "gid": "V-89807"
  tag "rid": "SV-100457r1_rule"
  tag "stig_id": "VRAU-SL-001255"
  tag "fix_id": "F-96549r2_fix"
  tag "cci": ["CCI-003123"]
  tag "nist": ["MA-4 (6)", "Rev_4"]
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
  tag "check": "Check the SSH daemon configuration for allowed MACs:

# grep -i macs /etc/ssh/sshd_config | grep -v '^#'

If no lines are returned, or the returned MACs list contains any MAC other than
\"hmac-sha1\", this is a finding."
  tag "fix": "Edit the SSH daemon configuration and remove any MACs other than
\"hmac-sha1\". If necessary, add a \"MACs\" line.

# sed -i \"/^[^#]*MACs/ c\\MACs hmac-sha1\" /etc/ssh/sshd_config"

describe sshd_config do
  its('macs') {should cmp 'hmac-sha1'}
end

end

